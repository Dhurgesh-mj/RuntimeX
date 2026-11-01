/*
 * allocator.c — HeapSentry malloc/free/realloc/calloc hooks + bootstrap arena
 *
 * Red-zone layout per allocation:
 *
 *   [hs_block_hdr_t : 32 B]
 *     canary_left_0  (8 B)  \
 *     canary_left_1  (8 B)   } left canary — embedded in header
 *     alloc_id       (8 B)
 *     user_size      (8 B)
 *   [user data       : user_size B]  ← pointer returned to caller
 *   [right canary    : 16 B]         (2 × uint64_t HS_CANARY_VALUE)
 *
 * Bootstrap arena:
 *   Static 512 KB buffer services allocations that arrive before
 *   runtime initialization completes or during reentrant internal calls.
 */

#include "internal.h"

/* ── Thread-local recursion guard ────────────────────────────────────────── */
__attribute__((tls_model("initial-exec")))
__thread int hs_in_hook = 0;

/* ─────────────────────────────────────────────────────────────────────────
 * Bootstrap arena
 * ────────────────────────────────────────────────────────────────────────── */

static uint8_t         hs_boot_buf[HS_BOOT_ARENA_SIZE];
static volatile size_t hs_boot_offset = 0;
static pthread_mutex_t hs_boot_lock   = PTHREAD_MUTEX_INITIALIZER;

void *hs_boot_alloc(size_t size)
{
    if (size == 0) size = 1;

    size_t payload = (size + 15u) & ~(size_t)15u;
    size_t total   = sizeof(hs_boot_hdr_t) + payload;
    total = (total + 15u) & ~(size_t)15u;

    pthread_mutex_lock(&hs_boot_lock);
    size_t off = hs_boot_offset;
    if (off + total > HS_BOOT_ARENA_SIZE) {
        pthread_mutex_unlock(&hs_boot_lock);
        const char msg[] = "heapsentry: bootstrap arena exhausted\n";
        (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
        return NULL;
    }
    hs_boot_offset = off + total;
    pthread_mutex_unlock(&hs_boot_lock);

    hs_boot_hdr_t *hdr = (hs_boot_hdr_t *)(hs_boot_buf + off);
    hdr->size = size;
    return (void *)(hdr + 1);
}

int hs_in_boot_arena(const void *ptr)
{
    const uint8_t *p = (const uint8_t *)ptr;
    return (p >= hs_boot_buf && p < hs_boot_buf + HS_BOOT_ARENA_SIZE);
}

/* ─────────────────────────────────────────────────────────────────────────
 * System allocator dispatch
 * ────────────────────────────────────────────────────────────────────────── */

#ifdef __APPLE__
/* On macOS, dyld interposing allows direct calls to system malloc/free
 * within the interposing dylib without recursing into the interposer. */
extern void *malloc(size_t);
extern void  free(void *);
extern void *realloc(void *, size_t);
extern void *calloc(size_t, size_t);

static inline void *sys_malloc(size_t sz) { return malloc(sz); }
static inline void  sys_free(void *p)     { free(p); }
static inline void *sys_realloc(void *p, size_t sz) { return realloc(p, sz); }
#else
/* Linux (ELF): use resolved dlsym(RTLD_NEXT) function pointers */
static inline void *sys_malloc(size_t sz) {
    hs_malloc_fn f = (hs_malloc_fn)__atomic_load_n((void *volatile *)&hs_real_malloc, __ATOMIC_ACQUIRE);
    return f ? f(sz) : NULL;
}
static inline void sys_free(void *p) {
    hs_free_fn f = (hs_free_fn)__atomic_load_n((void *volatile *)&hs_real_free, __ATOMIC_ACQUIRE);
    if (f) f(p);
}
static inline void *sys_realloc(void *p, size_t sz) {
    hs_realloc_fn f = (hs_realloc_fn)__atomic_load_n((void *volatile *)&hs_real_realloc, __ATOMIC_ACQUIRE);
    return f ? f(p, sz) : NULL;
}
#endif

/* ─────────────────────────────────────────────────────────────────────────
 * Red-zone helpers
 * ────────────────────────────────────────────────────────────────────────── */

static inline void write_right_canary(hs_block_hdr_t *hdr)
{
    uint64_t canaries[2] = { HS_CANARY_VALUE, HS_CANARY_VALUE };
    uint8_t *rc = (uint8_t *)(hdr + 1) + hdr->user_size;
    memcpy(rc, canaries, sizeof(canaries));
}

static int check_canaries(hs_block_hdr_t *hdr, void *user_ptr)
{
    int bad = 0;

    if (hdr->canary_left_0 != HS_CANARY_VALUE) {
        hs_log_heap_overflow(hdr->alloc_id, user_ptr, hdr->user_size,
                             "left", hdr->canary_left_0);
        bad = 1;
    }
    if (hdr->canary_left_1 != HS_CANARY_VALUE) {
        hs_log_heap_overflow(hdr->alloc_id, user_ptr, hdr->user_size,
                             "left", hdr->canary_left_1);
        bad = 1;
    }

    uint64_t rc[2];
    uint8_t *rc_ptr = (uint8_t *)(hdr + 1) + hdr->user_size;
    memcpy(rc, rc_ptr, sizeof(rc));

    if (rc[0] != HS_CANARY_VALUE) {
        hs_log_heap_overflow(hdr->alloc_id, user_ptr, hdr->user_size,
                             "right", rc[0]);
        bad = 1;
    } else if (rc[1] != HS_CANARY_VALUE) {
        hs_log_heap_overflow(hdr->alloc_id, user_ptr, hdr->user_size,
                             "right", rc[1]);
        bad = 1;
    }

    return bad;
}

/* ─────────────────────────────────────────────────────────────────────────
 * Hook implementations
 * ────────────────────────────────────────────────────────────────────────── */

void *hs_malloc(size_t size)
{
    if (hs_in_hook || !__atomic_load_n(&hs_ready, __ATOMIC_ACQUIRE))
        return hs_boot_alloc(size);

    hs_in_hook = 1;

    size_t block_size = sizeof(hs_block_hdr_t) + size + 16u;
    void  *block      = sys_malloc(block_size);
    if (!block) {
        hs_in_hook = 0;
        return NULL;
    }

    hs_block_hdr_t *hdr = (hs_block_hdr_t *)block;
    hdr->canary_left_0  = HS_CANARY_VALUE;
    hdr->canary_left_1  = HS_CANARY_VALUE;
    hdr->alloc_id       = hs_mint_id();
    hdr->user_size      = size;
    write_right_canary(hdr);

    void *user_ptr = (void *)(hdr + 1);

    hs_table_insert(user_ptr, hdr->alloc_id, size);
    hs_log_allocation(hdr->alloc_id, user_ptr, size);

    hs_in_hook = 0;
    return user_ptr;
}

void hs_free(void *user_ptr)
{
    if (!user_ptr || hs_in_boot_arena(user_ptr)) return;

    if (hs_in_hook || !__atomic_load_n(&hs_ready, __ATOMIC_ACQUIRE)) {
        sys_free(user_ptr);
        return;
    }

    hs_in_hook = 1;

    /* Double-free detection: check quarantine first */
    if (hs_quarantine_contains(user_ptr)) {
        hs_log_double_free(user_ptr, 0);
        hs_in_hook = 0;
        return;
    }

    /* Lookup in lifecycle table */
    hs_entry_t entry = {0};
    int tracked = hs_table_lookup(user_ptr, &entry);

    if (!tracked) {
        /* Untracked pointer (e.g. allocated before injection or in ld.so) */
        sys_free(user_ptr);
        hs_in_hook = 0;
        return;
    }

    hs_block_hdr_t *hdr = ((hs_block_hdr_t *)user_ptr) - 1;

    /* Check canaries for heap buffer overflow */
    check_canaries(hdr, user_ptr);

    /* Remove from table */
    hs_table_remove(user_ptr, NULL);

    /* Emit deallocation event */
    hs_log_deallocation(entry.alloc_id, user_ptr, entry.user_size);

    /* Poison memory */
    memset(user_ptr, HS_POISON_BYTE, entry.user_size);

    /* Add to quarantine ring buffer (evicts oldest by sys_free(old_hdr)) */
    hs_quarantine_add(user_ptr);

    hs_in_hook = 0;
}

void *hs_realloc(void *user_ptr, size_t new_size)
{
    if (!user_ptr) return hs_malloc(new_size);
    if (new_size == 0) { hs_free(user_ptr); return NULL; }

    if (hs_in_hook || !__atomic_load_n(&hs_ready, __ATOMIC_ACQUIRE)) {
        return sys_realloc(user_ptr, new_size);
    }

    if (hs_in_boot_arena(user_ptr)) {
        void *p = hs_malloc(new_size);
        if (p) {
            hs_boot_hdr_t *bh = ((hs_boot_hdr_t *)user_ptr) - 1;
            size_t c = bh->size < new_size ? bh->size : new_size;
            memcpy(p, user_ptr, c);
        }
        return p;
    }

    hs_in_hook = 1;

    hs_entry_t old_entry = {0};
    int tracked = hs_table_lookup(user_ptr, &old_entry);
    if (!tracked) {
        void *r = sys_realloc(user_ptr, new_size);
        hs_in_hook = 0;
        return r;
    }

    hs_block_hdr_t *old_hdr = ((hs_block_hdr_t *)user_ptr) - 1;
    check_canaries(old_hdr, user_ptr);

    size_t new_block_size = sizeof(hs_block_hdr_t) + new_size + 16u;
    void  *new_block      = sys_malloc(new_block_size);
    if (!new_block) {
        hs_in_hook = 0;
        return NULL;
    }

    hs_block_hdr_t *new_hdr = (hs_block_hdr_t *)new_block;
    new_hdr->canary_left_0  = HS_CANARY_VALUE;
    new_hdr->canary_left_1  = HS_CANARY_VALUE;
    new_hdr->alloc_id       = hs_mint_id();
    new_hdr->user_size      = new_size;
    write_right_canary(new_hdr);

    void *new_user = (void *)(new_hdr + 1);
    size_t copy_sz = old_entry.user_size < new_size ? old_entry.user_size : new_size;
    memcpy(new_user, user_ptr, copy_sz);

    hs_table_remove(user_ptr, NULL);
    memset(user_ptr, HS_POISON_BYTE, old_entry.user_size);
    sys_free((void *)old_hdr);

    hs_table_insert(new_user, new_hdr->alloc_id, new_size);

    hs_log_reallocation(old_entry.alloc_id, user_ptr,
                        new_hdr->alloc_id, new_user,
                        old_entry.user_size, new_size);

    hs_in_hook = 0;
    return new_user;
}

void *hs_calloc(size_t nmemb, size_t size)
{
    size_t total;
    if (nmemb && size > (size_t)-1 / nmemb) return NULL;
    total = nmemb * size;

    void *p = hs_malloc(total);
    if (p) memset(p, 0, total);
    return p;
}

/* ─────────────────────────────────────────────────────────────────────────
 * Interposition bindings
 * ────────────────────────────────────────────────────────────────────────── */

#ifdef __APPLE__
#include <malloc/malloc.h>

size_t hs_malloc_size(const void *ptr)
{
    if (!ptr) return 0;
    if (hs_in_boot_arena(ptr)) {
        hs_boot_hdr_t *bh = ((hs_boot_hdr_t *)ptr) - 1;
        return bh->size;
    }
    hs_entry_t entry = {0};
    if (hs_table_lookup((void *)ptr, &entry)) {
        return entry.user_size;
    }
    extern size_t malloc_size(const void *);
    return malloc_size(ptr);
}

#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { \
        const void *replacement; \
        const void *replacee; \
    } _interpose_##_replacee \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(uintptr_t)&_replacement, \
        (const void *)(uintptr_t)&_replacee \
    };

DYLD_INTERPOSE(hs_malloc, malloc);
DYLD_INTERPOSE(hs_free, free);
DYLD_INTERPOSE(hs_realloc, realloc);
DYLD_INTERPOSE(hs_calloc, calloc);
DYLD_INTERPOSE(hs_malloc_size, malloc_size);

#else
/* Linux (ELF) direct symbol interposition */
__attribute__((visibility("default"))) void *malloc(size_t sz) { return hs_malloc(sz); }
__attribute__((visibility("default"))) void free(void *p) { hs_free(p); }
__attribute__((visibility("default"))) void *realloc(void *p, size_t sz) { return hs_realloc(p, sz); }
__attribute__((visibility("default"))) void *calloc(size_t n, size_t s) { return hs_calloc(n, s); }
#endif
