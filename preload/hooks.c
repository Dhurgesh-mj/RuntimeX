/*
 * RuntimeX Runtime Core — library entry point (Person 1).
 *
 * Constructor: resolve real allocator symbols, initialize the lifecycle
 * table, open the event log, and emit one `initialization` event.
 * Constructor priority 101 keeps it early among preloaded libraries.
 */
#include "internal.h"

#include <stdlib.h>

__attribute__((constructor(101)))
static void rtx_runtime_init(void)
{
    int resolved;
    int logger_ok = 0;

    rtx_table_init();
    resolved = (rtx_resolve_symbols() == 0);
    rtx_ready = resolved;

    rtx_event_logger_init(&logger_ok);

    if (resolved) {
        rtx_log_initialization(logger_ok ? RTX_STATUS_OK
                                         : RTX_STATUS_FAILED);
    } else {
        /* Symbol resolution failed: allocator ops fall back to the
         * bootstrap arena and cannot be tracked. */
        rtx_log_initialization(RTX_STATUS_FAILED);
    }
}

/* Provide the dropped-event count through a visible symbol for tests. */
__attribute__((visibility("default")))
unsigned long runtimex_dropped_events(void)
{
    return (unsigned long)rtx_log_dropped();
}

/* Symbol the Python tests look for to confirm expected exports. */
__attribute__((visibility("default")))
int runtimex_schema_version(void)
{
    return RUNTIMEX_SCHEMA_VERSION;
}
