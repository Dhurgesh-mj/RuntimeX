/*
 * entry.c — HeapSentry library constructor and destructor
 *
 * Constructor priority 101 runs early but after C runtime setup.
 * Registers a leak reporter with atexit().
 */

#include "internal.h"

/* ── Library constructor ─────────────────────────────────────────────────── */

__attribute__((constructor(101)))
static void hs_runtime_init(void)
{
    /* 1. Initialise the lifecycle table (zeroes out the hash table). */
    hs_table_init();

    /* 2. Resolve the real allocator symbols via dlsym(RTLD_NEXT, ...).
     *    Must happen before we set hs_ready, so hooks that wake up during
     *    resolution see hs_ready == 0 and stay in bootstrap mode.          */
    int resolved = (hs_resolve_symbols() == 0);

    /* 3. Mark the runtime ready.  All hooks check this atomically.         */
    __atomic_store_n(&hs_ready, resolved ? 1 : 0, __ATOMIC_SEQ_CST);

    /* 4. Open the log file (reads HEAPSENTRY_LOG, CRASHLAB_* env vars).    */
    int log_ok = 0;
    hs_log_init(&log_ok);

    /* 5. Emit the initialization event.                                    */
    hs_log_initialization((resolved && log_ok) ? "ok" : "failed");
}

/* ── Library destructor ──────────────────────────────────────────────────── */

__attribute__((destructor(101)))
static void hs_runtime_fini(void)
{
    /* 1. Report any remaining unfreed allocations as memory leaks.        */
    hs_report_leaks_at_exit();

    /* 2. Disable runtime so shutdown sequence does not recurse.           */
    __atomic_store_n(&hs_ready, 0, __ATOMIC_SEQ_CST);
}
