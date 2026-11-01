/*
 * resolver.c — HeapSentry symbol resolver
 *
 * Resolves the real malloc/free/realloc/calloc via dlsym(RTLD_NEXT).
 * Must be called before any hook tries to forward to the real allocator.
 *
 * The calloc hook is special: dlsym itself may internally call calloc, which
 * would recurse.  We guard this via hs_resolving; the calloc hook routes
 * bootstrap-arena allocations when hs_resolving is set.
 */

#include "internal.h"

/* ── Real function pointers ──────────────────────────────────────────────── */
volatile hs_malloc_fn   hs_real_malloc   = NULL;
volatile hs_free_fn     hs_real_free     = NULL;
volatile hs_realloc_fn  hs_real_realloc  = NULL;
volatile hs_calloc_fn   hs_real_calloc   = NULL;

/* Defined here (resolver owns hs_resolving); hs_ready is owned by entry.c. */
volatile int hs_resolving = 0;
volatile int hs_ready     = 0;

/* Monotonic allocation counter — zero-initialised by the linker.            */
uint64_t hs_next_alloc_id = 0;

/* ─────────────────────────────────────────────────────────────────────────
 * hs_resolve_symbols
 *
 * Returns 0 on success, -1 if any symbol could not be resolved.
 * Safe to call multiple times; subsequent calls are no-ops once resolved.
 * ────────────────────────────────────────────────────────────────────────── */
int hs_resolve_symbols(void)
{
#ifdef __APPLE__
    /* On macOS, dyld interposition directly calls the real system allocator
     * symbols from within the interposing dylib. No dlsym needed. */
    return 0;
#else
    /* Already resolved — fast path. */
    if (hs_real_malloc && hs_real_free && hs_real_realloc && hs_real_calloc)
        return 0;

    /*
     * Mark resolution in-flight so that the calloc hook (which dlsym may
     * trigger internally) redirects to the bootstrap arena instead of
     * recursing back into dlsym.
     */
    __atomic_store_n(&hs_resolving, 1, __ATOMIC_SEQ_CST);

    void *m = dlsym(RTLD_NEXT, "malloc");
    void *f = dlsym(RTLD_NEXT, "free");
    void *r = dlsym(RTLD_NEXT, "realloc");
    void *c = dlsym(RTLD_NEXT, "calloc");

    __atomic_store_n(&hs_resolving, 0, __ATOMIC_SEQ_CST);

    if (!m || !f || !r || !c) {
        /* Write to stderr directly — no heap, no logger yet.               */
        const char msg[] = "heapsentry: dlsym resolution failed\n";
        (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
        return -1;
    }

    /*
     * Store with sequential consistency so other threads/hooks see a
     * consistent view once hs_ready is set by the caller (entry.c).
     */
    __atomic_store_n((void *volatile *)&hs_real_malloc,  m, __ATOMIC_SEQ_CST);
    __atomic_store_n((void *volatile *)&hs_real_free,    f, __ATOMIC_SEQ_CST);
    __atomic_store_n((void *volatile *)&hs_real_realloc, r, __ATOMIC_SEQ_CST);
    __atomic_store_n((void *volatile *)&hs_real_calloc,  c, __ATOMIC_SEQ_CST);

    return 0;
#endif
}
