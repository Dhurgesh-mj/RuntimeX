/*
 * HeapSentry Runtime Core — internal shared definitions (Person 1).
 *
 * Supported environment (see docs/limitations.md):
 *   Linux x86_64, glibc, dynamically linked ELF executables,
 *   LD_PRELOAD interposition of malloc/free/realloc only.
 */
#ifndef HEAPSENTRY_INTERNAL_H
#define HEAPSENTRY_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

/* Schema version emitted in every event record. Must match
 * shared/event_schema.json ("const": 1) and docs/event-schema.md. */
#define HEAPSENTRY_SCHEMA_VERSION 1

/* Environment variables honored by the runtime core. */
#define HEAPSENTRY_ENV_LOG      "HEAPSENTRY_LOG"      /* output path */
#define HEAPSENTRY_ENV_LOG_OLD  "RUNTIMEX_LOG"        /* legacy alias */
#define HEAPSENTRY_ENV_TRACKED  "HEAPSENTRY_TRACKED"  /* tracker capacity */
#define HEAPSENTRY_ENV_RUN_ID   "CRASHLAB_RUN_ID"     /* crashlab join key */
#define HEAPSENTRY_ENV_BATCH_ID "CRASHLAB_BATCH_ID"   /* crashlab join key */

/* Maximum number of simultaneously tracked live allocations. When this many
 * live allocations exist, further allocations are still logged (with a fresh
 * allocation_id) but their identity is no longer remembered; a later free()
 * of such a pointer is logged with status "untracked". */
#define HEAPSENTRY_MAX_TRACKED 65536

/* Static bootstrap arena used only when the real allocator has not been
 * resolved yet (early dynamic-linker / dlsym-recursion window). */
#define HEAPSENTRY_BOOT_ARENA_SIZE (256u * 1024u)

typedef struct boot_hdr {
    size_t size;      /* requested size */
    size_t pad;       /* keep header 16 bytes for alignment */
} boot_hdr_t;

/* ---------- symbol_resolver.c ---------- */
typedef void *(*rtx_malloc_fn)(size_t);
typedef void  (*rtx_free_fn)(void *);
typedef void *(*rtx_realloc_fn)(void *, size_t);

extern volatile rtx_malloc_fn  rtx_real_malloc;
extern volatile rtx_free_fn    rtx_real_free;
extern volatile rtx_realloc_fn rtx_real_realloc;

/* Resolve the real allocator symbols via dlsym(RTLD_NEXT, ...).
 * Returns 0 on success, -1 if any symbol could not be resolved. */
int rtx_resolve_symbols(void);

/* Nonzero while rtx_resolve_symbols() is inside dlsym (recursion window). */
extern volatile int rtx_resolving;

/* ---------- allocator hooks / lifecycle ---------- */
/* 1 once all real symbols are successfully resolved. */
extern volatile int rtx_ready;

/* Bootstrap arena (pre-resolution fallback). Never reuses freed memory. */
void *rtx_boot_alloc(size_t size);
int   rtx_in_boot_arena(const void *p);

/* Global per-run allocation id counter. Id 0 means "no allocation"
 * (JSON null in events); live ids start at 1. */
extern uint64_t rtx_next_alloc_id;

/* Next id delivered is 1; add_fetch returns the value AFTER increment,
 * so the counter's initial value must be 0. */

/* Lifecycle table (ptr -> {id, size}). All functions take/leave the table
 * lock internally (except where noted) and are safe from multiple threads. */
void rtx_table_init(void);
void rtx_table_insert(void *p, uint64_t id, size_t size);
void rtx_table_remove(void *p);
/* Returns 1 and fills id_out and size_out if tracked, 0 if untracked. */
int  rtx_table_lookup(const void *p, uint64_t *id_out, size_t *size_out);
/* Nonzero once the table is exhausted (see HEAPSENTRY_MAX_TRACKED). */
int  rtx_table_is_exhausted(void);
/* Active capacity (for testing exhaustion via HEAPSENTRY_ENV_TRACKED_). */
int  rtx_table_capacity(void);

/* ---------- event_logger.c ---------- */
/* Event statuses. */
#define RTX_STATUS_OK        "ok"
#define RTX_STATUS_FAILED    "failed"
#define RTX_STATUS_UNTRACKED "untracked"

/* Event types. */
#define RTX_EVENT_ALLOCATION   "allocation"
#define RTX_EVENT_DEALLOCATION "deallocation"
#define RTX_EVENT_REALLOCATION "reallocation"
#define RTX_EVENT_INIT         "initialization"
#define RTX_EVENT_LOGGER_ERROR "logger_error"

/* Open the event log from HEAPSENTRY_ENV_LOG (default: ./heapsentry_events.jsonl).
 * Returns 0 on success. On failure the logger enters the failed state and
 * every later event is counted as dropped. */
int rtx_event_logger_init(int *ok_out);

/* Emit an initialization event. status is RTX_STATUS_OK or RTX_STATUS_FAILED. */
void rtx_log_initialization(const char *status);

/* Emit an allocation event. id==0 -> allocation_id:null (failed allocation,
 * no id minted). size is the requested size. */
void rtx_log_allocation(uint64_t id, size_t size, const char *status);

/* Emit a deallocation event. id==0 -> untracked/unknown pointer identity. */
void rtx_log_deallocation(uint64_t id, size_t old_size, const char *status);

/* Emit a reallocation event. new_id==0 -> allocation_id:null.
 * old_id==0 -> old_allocation_id:null. old_size<0 is not possible (size_t),
 * pass -1 as old_size_signed when the old size is unknown. */
void rtx_log_reallocation(uint64_t new_id, uint64_t old_id,
                          long long old_size_signed, size_t size,
                          const char *status);

/* Emit a logger_error event without any recursive error handling. */
void rtx_log_logger_error(const char *message);

/* Number of events dropped because the logger is unavailable/failed. */
uint64_t rtx_log_dropped(void);

#endif /* HEAPSENTRY_INTERNAL_H */
