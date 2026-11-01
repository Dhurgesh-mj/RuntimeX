/*
 * detector.c — HeapSentry detection state
 *
 * Implements:
 *   - Open-addressing lifecycle table (HS_MAX_TRACKED slots)
 *   - Quarantine ring buffer (HS_QUARANTINE_MAX slots)
 *   - Leak reporter (called via atexit)
 */

#include "internal.h"

/* ─────────────────────────────────────────────────────────────────────────
 * Lifecycle table — open-addressing hash map keyed by user_ptr
 * ────────────────────────────────────────────────────────────────────────── */

#define TABLE_CAP  HS_MAX_TRACKED   /* must be power of two */

typedef struct {
    void    *user_ptr;   /* NULL ⟹ empty slot                               */
    uint64_t alloc_id;
    size_t   user_size;
} hs_slot_t;

static hs_slot_t        hs_table[TABLE_CAP];
static size_t           hs_table_count = 0;
static pthread_mutex_t  hs_table_lock  = PTHREAD_MUTEX_INITIALIZER;

/* Compile-time check: TABLE_CAP must be a power of two. */
typedef char _hs_cap_pow2_check[((TABLE_CAP & (TABLE_CAP - 1)) == 0) ? 1 : -1];

static inline size_t table_hash(void *ptr)
{
    uintptr_t v = (uintptr_t)ptr;
    /* Fibonacci hashing for pointer distribution. */
    v = (v ^ (v >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    v = (v ^ (v >> 27)) * UINT64_C(0x94d049bb133111eb);
    v = v ^ (v >> 31);
    return (size_t)(v & (TABLE_CAP - 1));
}

void hs_table_init(void)
{
    memset(hs_table, 0, sizeof(hs_table));
    hs_table_count = 0;
}

int hs_table_is_full(void)
{
    /* Keep load factor ≤ 75 %. */
    return hs_table_count >= (TABLE_CAP * 3u / 4u);
}

int hs_table_insert(void *user_ptr, uint64_t alloc_id, size_t user_size)
{
    if (!user_ptr) return 0;
    pthread_mutex_lock(&hs_table_lock);
    if (hs_table_count >= TABLE_CAP * 3u / 4u) {
        pthread_mutex_unlock(&hs_table_lock);
        hs_log_dropped();
        return 0;
    }
    size_t idx = table_hash(user_ptr);
    for (size_t i = 0; i < TABLE_CAP; ++i) {
        size_t slot = (idx + i) & (TABLE_CAP - 1);
        if (!hs_table[slot].user_ptr) {
            hs_table[slot].user_ptr  = user_ptr;
            hs_table[slot].alloc_id  = alloc_id;
            hs_table[slot].user_size = user_size;
            ++hs_table_count;
            pthread_mutex_unlock(&hs_table_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&hs_table_lock);
    return 0;
}

int hs_table_lookup(void *user_ptr, hs_entry_t *out)
{
    if (!user_ptr) return 0;
    pthread_mutex_lock(&hs_table_lock);
    size_t idx = table_hash(user_ptr);
    for (size_t i = 0; i < TABLE_CAP; ++i) {
        size_t slot = (idx + i) & (TABLE_CAP - 1);
        if (!hs_table[slot].user_ptr) break;
        if (hs_table[slot].user_ptr == user_ptr) {
            if (out) {
                out->user_ptr  = hs_table[slot].user_ptr;
                out->alloc_id  = hs_table[slot].alloc_id;
                out->user_size = hs_table[slot].user_size;
            }
            pthread_mutex_unlock(&hs_table_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&hs_table_lock);
    return 0;
}

/*
 * Robin-Hood backward-shift deletion to maintain probe sequences intact.
 */
int hs_table_remove(void *user_ptr, hs_entry_t *out)
{
    if (!user_ptr) return 0;
    pthread_mutex_lock(&hs_table_lock);
    size_t idx = table_hash(user_ptr);
    size_t found = (size_t)-1;

    for (size_t i = 0; i < TABLE_CAP; ++i) {
        size_t slot = (idx + i) & (TABLE_CAP - 1);
        if (!hs_table[slot].user_ptr) break;
        if (hs_table[slot].user_ptr == user_ptr) {
            found = slot;
            if (out) {
                out->user_ptr  = hs_table[slot].user_ptr;
                out->alloc_id  = hs_table[slot].alloc_id;
                out->user_size = hs_table[slot].user_size;
            }
            break;
        }
    }

    if (found == (size_t)-1) {
        pthread_mutex_unlock(&hs_table_lock);
        return 0;
    }

    /* Backward-shift deletion. */
    size_t cur = found;
    for (;;) {
        size_t next = (cur + 1) & (TABLE_CAP - 1);
        if (!hs_table[next].user_ptr) {
            memset(&hs_table[cur], 0, sizeof(hs_slot_t));
            break;
        }
        size_t nat = table_hash(hs_table[next].user_ptr);
        /* Check if next's natural home is cur or earlier. */
        /* Distance from natural home to next slot. */
        size_t d_next = (next - nat) & (TABLE_CAP - 1);
        size_t d_cur  = (next - cur) & (TABLE_CAP - 1);
        if (d_next >= d_cur) {
            hs_table[cur] = hs_table[next];
            cur = next;
        } else {
            memset(&hs_table[cur], 0, sizeof(hs_slot_t));
            break;
        }
    }
    --hs_table_count;
    pthread_mutex_unlock(&hs_table_lock);
    return 1;
}

/* Walk all live entries. Callback returning non-zero stops the walk.        */
void hs_table_walk(hs_table_walk_fn fn, void *ctx)
{
    pthread_mutex_lock(&hs_table_lock);
    for (size_t i = 0; i < TABLE_CAP; ++i) {
        if (hs_table[i].user_ptr) {
            hs_entry_t e = {
                .user_ptr  = hs_table[i].user_ptr,
                .alloc_id  = hs_table[i].alloc_id,
                .user_size = hs_table[i].user_size
            };
            /* Unlock around callback to avoid deadlock if callback logs.   */
            pthread_mutex_unlock(&hs_table_lock);
            int stop = fn(&e, ctx);
            pthread_mutex_lock(&hs_table_lock);
            if (stop) break;
        }
    }
    pthread_mutex_unlock(&hs_table_lock);
}

/* ─────────────────────────────────────────────────────────────────────────
 * Quarantine ring buffer
 *
 * We store USER pointers.  When evicting, we reconstruct the block pointer
 * via `(hs_block_hdr_t *)user_ptr - 1` and call real_free on it.
 * ────────────────────────────────────────────────────────────────────────── */

static void            *hs_quarantine[HS_QUARANTINE_MAX];
static size_t           hs_q_head  = 0;   /* index of next write position   */
static size_t           hs_q_count = 0;   /* number of entries currently held */
static pthread_mutex_t  hs_q_lock  = PTHREAD_MUTEX_INITIALIZER;

void hs_quarantine_add(void *user_ptr)
{
    if (!user_ptr) return;
    pthread_mutex_lock(&hs_q_lock);

    if (hs_q_count == HS_QUARANTINE_MAX) {
        /* Evict oldest: reconstruct block pointer, call real_free. */
        void *old_user = hs_quarantine[hs_q_head];
        if (old_user) {
            hs_block_hdr_t *old_hdr = ((hs_block_hdr_t *)old_user) - 1;
#ifdef __APPLE__
            extern void free(void *);
            free((void *)old_hdr);
#else
            if (hs_real_free) {
                ((hs_free_fn)hs_real_free)((void *)old_hdr);
            }
#endif
        }
        hs_quarantine[hs_q_head] = user_ptr;
        hs_q_head = (hs_q_head + 1) % HS_QUARANTINE_MAX;
        /* count stays at HS_QUARANTINE_MAX */
    } else {
        size_t write_pos = (hs_q_head + hs_q_count) % HS_QUARANTINE_MAX;
        hs_quarantine[write_pos] = user_ptr;
        ++hs_q_count;
    }
    pthread_mutex_unlock(&hs_q_lock);
}

int hs_quarantine_contains(void *user_ptr)
{
    if (!user_ptr) return 0;
    int found = 0;
    pthread_mutex_lock(&hs_q_lock);
    for (size_t i = 0; i < hs_q_count; ++i) {
        size_t idx = (hs_q_head + i) % HS_QUARANTINE_MAX;
        if (hs_quarantine[idx] == user_ptr) {
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&hs_q_lock);
    return found;
}

/* ─────────────────────────────────────────────────────────────────────────
 * Leak reporter  (registered as atexit handler in entry.c)
 * ────────────────────────────────────────────────────────────────────────── */

static int leak_walk_cb(const hs_entry_t *e, void *ctx)
{
    (void)ctx;
    hs_log_leak(e->alloc_id, e->user_ptr, e->user_size);
    return 0; /* keep walking */
}

void hs_report_leaks_at_exit(void)
{
    hs_table_walk(leak_walk_cb, NULL);
}
