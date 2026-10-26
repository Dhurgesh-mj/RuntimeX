/*
 * RuntimeX Runtime Core — allocator hooks and lifecycle tracking (Person 1).
 *
 * Design notes:
 *  - The lifecycle table is a fixed-size open-addressing hash table in the
 *    library's .bss. It never calls malloc, so instrumentation cannot
 *    recurse through the allocator.
 *  - Allocation identity is a per-run monotonically increasing id minted per
 *    allocation. A pointer address alone is NOT identity: after free(), the
 *    same address can back an allocation with a new id.
 *  - Pre-resolution calls (dynamic-linker init, dlsym recursion window) are
 *    served from a static bootstrap arena with size headers. It never frees.
 *  - Preserving realloc failure semantics: on failure the original block is
 *    untouched and the original metadata row survives.
 */
#include "internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

volatile int rtx_ready = 0;
uint64_t rtx_next_alloc_id = 0; /* 0 reserved: add_fetch yields 1 first */

/* ---------------- bootstrap arena ---------------- */

static _Alignas(16) unsigned char rtx_boot_arena[RUNTIMEX_BOOT_ARENA_SIZE];
static size_t rtx_boot_used = 0; /* pre-init single-thread window (ld.so) */

void *rtx_boot_alloc(size_t size)
{
    boot_hdr_t *hdr;
    size_t total = sizeof(boot_hdr_t) + size;
    if (size == 0 || total < size /* overflow */) {
        errno = ENOMEM;
        return NULL;
    }
    if (rtx_boot_used + total > RUNTIMEX_BOOT_ARENA_SIZE ||
        rtx_boot_used + total < rtx_boot_used) {
        errno = ENOMEM;
        return NULL;
    }
    hdr = (boot_hdr_t *)(rtx_boot_arena + rtx_boot_used);
    rtx_boot_used += total;
    hdr->size = size;
    hdr->pad = 0;
    return (void *)(hdr + 1);
}

int rtx_in_boot_arena(const void *p)
{
    return (const unsigned char *)p >= rtx_boot_arena &&
           (const unsigned char *)p <  rtx_boot_arena +
                                       RUNTIMEX_BOOT_ARENA_SIZE;
}

/* ---------------- lifecycle table ---------------- */

typedef struct {
    void    *ptr;   /* NULL = free slot or tombstone */
    uint64_t id;    /* 0 with ptr!=NULL = tombstone */
    size_t   size;
} slot_t;

/* RUNTIMEX_MAX_TRACKED is the static hard cap; the active capacity
 * (power of two, [16, RUNTIMEX_MAX_TRACKED]) can be lowered at init via
 * the RUNTIMEX_TRACKED environment variable to exercise exhaustion. */
static slot_t rtx_table[RUNTIMEX_MAX_TRACKED];
#define RTX_TABLE_MASK RUNTIMEX_MAX_TRACKED
static size_t rtx_table_live = 0;
static size_t rtx_cap = RUNTIMEX_MAX_TRACKED;
static int    rtx_table_full = 0;
static pthread_mutex_t rtx_table_lock = PTHREAD_MUTEX_INITIALIZER;

void rtx_table_init(void)
{
    const char *env;
    size_t cap = RUNTIMEX_MAX_TRACKED;

    memset(rtx_table, 0, sizeof(rtx_table));
    rtx_table_live = 0;
    rtx_table_full = 0;

    env = getenv("RUNTIMEX_TRACKED");
    if (env != NULL && *env != '\0') {
        char *endp;
        unsigned long long v = strtoull(env, &endp, 10);
        if (*endp == '\0' && v >= 16)
            cap = (size_t)v;
    }
    /* Round down to a power of two, clamp to the static array. */
    while ((cap & (cap - 1)) != 0)
        cap &= cap - 1;
    rtx_cap = cap < 16 ? 16 : (cap > RUNTIMEX_MAX_TRACKED ? RUNTIMEX_MAX_TRACKED : cap);
}

int rtx_table_capacity(void)
{
    return (int)rtx_cap;
}

static size_t rtx_hash_ptr(const void *p)
{
    uint64_t x = (uint64_t)(uintptr_t)p;
    x *= 0x9E3779B97F4A7C15ull;          /* splitmix-style avalanche */
    x ^= x >> 32;
    x *= 0xBF58476D1CE4E5B9ull;
    x ^= x >> 29;
    return (size_t)x;
}

static void rtx_insert_nolock(void *p, uint64_t id, size_t size)
{
    if (rtx_table_live >= rtx_cap) {
        /* Exhausted: this allocation is logged but not tracked. */
        rtx_table_full = 1;
        return;
    }
    size_t i = rtx_hash_ptr(p) & (RTX_TABLE_MASK - 1);
    size_t n;
    for (n = 0; n < RTX_TABLE_MASK; n++, i = (i + 1) & (RTX_TABLE_MASK - 1)) {
        slot_t *s = &rtx_table[i];
        if (s->ptr == NULL) {
            /* free slot or tombstone: scan ahead for a same-address row
             * left behind by an unremoved reused address. */
            size_t j, probe;
            for (probe = (i + 1) & (RTX_TABLE_MASK - 1), j = 0;
                 j < RTX_TABLE_MASK;
                 j++, probe = (probe + 1) & (RTX_TABLE_MASK - 1)) {
                slot_t *t = &rtx_table[probe];
                if (t->ptr == NULL && t->id == 0) break; /* real empty */
                if (t->ptr == p) {
                    t->id = id;
                    t->size = size;
                    return;
                }
            }
            s->ptr = p;
            s->id = id;
            s->size = size;
            rtx_table_live++;
            return;
        }
        if (s->ptr == p) { /* overwrite (same address re-minted) */
            s->id = id;
            s->size = size;
            return;
        }
    }
    rtx_table_full = 1; /* probed the whole table */
}

void rtx_table_insert(void *p, uint64_t id, size_t size)
{
    pthread_mutex_lock(&rtx_table_lock);
    rtx_insert_nolock(p, id, size);
    pthread_mutex_unlock(&rtx_table_lock);
}

void rtx_table_remove(void *p)
{
    size_t i = rtx_hash_ptr(p) & (RTX_TABLE_MASK - 1);
    size_t n;
    pthread_mutex_lock(&rtx_table_lock);
    for (n = 0; n < RTX_TABLE_MASK; n++, i = (i + 1) & (RTX_TABLE_MASK - 1)) {
        slot_t *s = &rtx_table[i];
        if (s->ptr == NULL && s->id == 0) break; /* empty: not present */
        if (s->ptr == p) {
            s->id = 0; /* tombstone */
            s->size = 0;
            rtx_table_live--;
            break;
        }
    }
    if (rtx_table_live < rtx_cap / 2)
        rtx_table_full = 0;
    pthread_mutex_unlock(&rtx_table_lock);
}

int rtx_table_lookup(const void *p, uint64_t *id_out, size_t *size_out)
{
    size_t i = rtx_hash_ptr(p) & (RTX_TABLE_MASK - 1);
    size_t n;
    int found = 0;
    pthread_mutex_lock(&rtx_table_lock);
    for (n = 0; n < RTX_TABLE_MASK; n++, i = (i + 1) & (RTX_TABLE_MASK - 1)) {
        const slot_t *s = &rtx_table[i];
        if (s->ptr == NULL && s->id == 0) break;
        if (s->ptr == p && s->id != 0) { /* skip tombstones */
            *id_out = s->id;
            *size_out = s->size;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&rtx_table_lock);
    return found;
}

int rtx_table_is_exhausted(void)
{
    return rtx_table_full;
}

/* ---------------- allocator wrappers ---------------- */

static __thread int t_in_hook
    __attribute__((tls_model("initial-exec")));

static uint64_t rtx_mint_id(void)
{
    return __atomic_add_fetch(&rtx_next_alloc_id, 1, __ATOMIC_RELAXED);
}

__attribute__((visibility("default")))
void *malloc(size_t size)
{
    rtx_malloc_fn real;
    void *p;
    int saved_errno;

    if (t_in_hook)
        goto fallback_call;

    real = rtx_real_malloc;
    if (real == NULL || !rtx_ready) {
        /* Initialization window: serve from the bootstrap arena. */
        return rtx_boot_alloc(size);
    }

    t_in_hook = 1;
    p = real(size);
    t_in_hook = 0;

    saved_errno = errno;

    if (p != NULL) {
        uint64_t id = rtx_mint_id();
        rtx_table_insert(p, id, size);
        rtx_log_allocation(id, size, RTX_STATUS_OK);
    } else {
        rtx_log_allocation(0, size, RTX_STATUS_FAILED);
    }

    errno = saved_errno;
    return p;

fallback_call:
    /* Should not normally happen (instrumentation must not allocate), but
     * if it does, forward to the real allocator when available. */
    real = rtx_real_malloc;
    if (real != NULL && rtx_ready)
        return real(size);
    return rtx_boot_alloc(size);
}

__attribute__((visibility("default")))
void free(void *ptr)
{
    rtx_free_fn real;
    uint64_t id = 0;
    size_t old_size = 0;
    int tracked;
    int saved_errno;

    if (ptr == NULL)
        return; /* C standard no-op; documented: no event emitted */

    if (rtx_in_boot_arena(ptr)) {
        /* Bootstrap memory was never obtained from the real allocator;
         * the real free() must not be given this pointer. Memory is not
         * reclaimed (see docs/instrumentation-limitations.md). */
        if (rtx_ready)
            rtx_log_deallocation(0, 0, RTX_STATUS_UNTRACKED);
        return;
    }

    if (t_in_hook)
        return;

    real = rtx_real_free;
    if (real == NULL || !rtx_ready)
        return; /* can only be a stale pointer; leak documented above */

    tracked = rtx_table_lookup(ptr, &id, &old_size);

    t_in_hook = 1;
    real(ptr);
    t_in_hook = 0;
    saved_errno = errno;

    rtx_table_remove(ptr);
    if (tracked)
        rtx_log_deallocation(id, old_size, RTX_STATUS_OK);
    else
        rtx_log_deallocation(0, 0, RTX_STATUS_UNTRACKED);

    errno = saved_errno;
}

__attribute__((visibility("default")))
void *realloc(void *ptr, size_t size)
{
    rtx_realloc_fn real;
    rtx_malloc_fn  mreal;
    void *nr;
    uint64_t old_id = 0;
    size_t old_size = 0;
    int tracked;
    int saved_errno;

    if (t_in_hook) {
        real = rtx_real_realloc;
        if (real != NULL && rtx_ready)
            return real(ptr, size);
        return rtx_boot_alloc(size);
    }

    if (rtx_in_boot_arena(ptr)) {
        /* Move bootstrap block into real memory if possible. The chunk did
         * not come from the real allocator, so the real realloc must not be
         * given this pointer; allocate fresh and copy instead. */
        const boot_hdr_t *h = (const boot_hdr_t *)ptr - 1;
        size_t copy = h->size < size ? h->size : size;
        real = rtx_real_realloc;
        mreal = rtx_real_malloc;
        if (!rtx_ready || mreal == NULL) {
            void *nb = rtx_boot_alloc(size);
            if (nb == NULL) return NULL;
            if (copy) memcpy(nb, ptr, copy);
            return nb;
        }
        nr = mreal(size);
        if (nr == NULL) return NULL;
        if (copy) memcpy(nr, ptr, copy);
        if (rtx_ready) {
            uint64_t id = rtx_mint_id();
            rtx_table_insert(nr, id, size);
            rtx_log_reallocation(id, 0, (long long)h->size, size, RTX_STATUS_OK);
        }
        return nr;
    }

    if (ptr == NULL) {
        /* realloc(NULL, size) == malloc(size) */
        return malloc(size);
    }

    real = rtx_real_realloc;
    if (real == NULL || !rtx_ready)
        return rtx_boot_alloc(size);

    tracked = rtx_table_lookup(ptr, &old_id, &old_size);

    if (size == 0) {
        /* glibc semantics: realloc(p, 0) frees p and returns NULL. */
        t_in_hook = 1;
        real(ptr, 0);
        t_in_hook = 0;
        saved_errno = errno;
        rtx_table_remove(ptr);
        if (tracked)
            rtx_log_reallocation(0, old_id, (long long)old_size, 0,
                                 RTX_STATUS_OK);
        else
            rtx_log_reallocation(0, 0, -1, 0, RTX_STATUS_UNTRACKED);
        errno = saved_errno;
        return NULL;
    }

    t_in_hook = 1;
    nr = real(ptr, size);
    t_in_hook = 0;
    saved_errno = errno;

    if (nr == NULL) {
        /* Original allocation preserved, including its metadata row and id. */
        if (tracked)
            rtx_log_reallocation(0, old_id, (long long)old_size, size,
                                 RTX_STATUS_FAILED);
        else
            rtx_log_reallocation(0, 0, -1, size, RTX_STATUS_FAILED);
        errno = ENOMEM;
        return NULL;
    }

    {
        uint64_t new_id = rtx_mint_id();
        if (nr == ptr) {
            /* Same address returned: update the row in place so the old
             * id is superseded rather than colliding. */
            rtx_table_insert(nr, new_id, size);
        } else {
            rtx_table_remove(ptr);
            rtx_table_insert(nr, new_id, size);
        }
        if (tracked)
            rtx_log_reallocation(new_id, old_id, (long long)old_size, size,
                                 RTX_STATUS_OK);
        else
            rtx_log_reallocation(new_id, 0, -1, size, RTX_STATUS_OK);
    }

    errno = saved_errno;
    return nr;
}
