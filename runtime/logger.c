/*
 * logger.c — HeapSentry JSONL event logger
 *
 * Fixed 4096-byte stack buffer, single write(2) per event, mutex-protected.
 * Zero heap use inside logger functions (safe to call from allocation hooks).
 *
 * All events carry a standard prefix:
 *   schema_version, event_id, event, run_id, batch_id,
 *   timestamp_ns, process_id, thread_id, status
 */

#include "internal.h"
#include <inttypes.h>
#include <fcntl.h>

/* ── Logger state ────────────────────────────────────────────────────────── */
static int             hs_log_fd    = -1;
static pthread_mutex_t hs_log_lock  = PTHREAD_MUTEX_INITIALIZER;
static uint64_t        hs_event_seq = 0;

static char hs_run_id[256]   = "";
static char hs_batch_id[256] = "";

#define LOG_BUFSZ 4096

/* ── Internal helpers ────────────────────────────────────────────────────── */

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static uint64_t next_event_id(void)
{
    return (uint64_t)__atomic_add_fetch(&hs_event_seq, 1u, __ATOMIC_SEQ_CST);
}

/* Write a JSON-escaped version of src into dst[0..room-1].
 * Returns bytes written (does NOT NUL-terminate). */
static int json_escape(char *dst, int room, const char *src)
{
    int n = 0;
    if (!src) src = "";
    for (; *src && n + 6 < room; ++src) {
        unsigned char c = (unsigned char)*src;
        if      (c == '"')  { dst[n++] = '\\'; dst[n++] = '"'; }
        else if (c == '\\') { dst[n++] = '\\'; dst[n++] = '\\'; }
        else if (c == '\n') { dst[n++] = '\\'; dst[n++] = 'n'; }
        else if (c == '\r') { dst[n++] = '\\'; dst[n++] = 'r'; }
        else if (c == '\t') { dst[n++] = '\\'; dst[n++] = 't'; }
        else if (c < 0x20) {
            int r = snprintf(dst + n, (size_t)(room - n), "\\u%04x", (unsigned)c);
            if (r > 0) n += r;
        } else {
            dst[n++] = (char)c;
        }
    }
    return n;
}

/* Appends n bytes of text into buf starting at *pos, capped at LOG_BUFSZ-1. */
#define APPEND(buf, pos, ...) \
    do { \
        int _r = snprintf((buf) + *(pos), \
                          (size_t)((LOG_BUFSZ - 1) - *(pos)), \
                          __VA_ARGS__); \
        if (_r > 0) *(pos) += _r; \
    } while (0)

/* Writes the common JSON prefix into buf[0..LOG_BUFSZ-1].
 * Returns bytes written. */
static int emit_prefix(char *buf,
                       uint64_t ev_id, const char *event_name,
                       const char *status)
{
    uint64_t ts  = now_ns();
    uint64_t tid = HS_TID();
    int      pid = (int)getpid();
    int      n   = 0;

    /* schema_version */
    APPEND(buf, &n, "{\"schema_version\":%d", HS_SCHEMA_VERSION);

    /* event_id */
    APPEND(buf, &n, ",\"event_id\":%" PRIu64, ev_id);

    /* event name */
    APPEND(buf, &n, ",\"event\":\"");
    n += json_escape(buf + n, LOG_BUFSZ - 1 - n, event_name);
    APPEND(buf, &n, "\"");

    /* run_id */
    APPEND(buf, &n, ",\"run_id\":\"");
    n += json_escape(buf + n, LOG_BUFSZ - 1 - n, hs_run_id);
    APPEND(buf, &n, "\"");

    /* batch_id */
    APPEND(buf, &n, ",\"batch_id\":\"");
    n += json_escape(buf + n, LOG_BUFSZ - 1 - n, hs_batch_id);
    APPEND(buf, &n, "\"");

    /* timestamp, pid, tid */
    APPEND(buf, &n, ",\"timestamp_ns\":%" PRIu64, ts);
    APPEND(buf, &n, ",\"process_id\":%d", pid);
    APPEND(buf, &n, ",\"thread_id\":%" PRIu64, tid);

    /* status */
    APPEND(buf, &n, ",\"status\":\"");
    n += json_escape(buf + n, LOG_BUFSZ - 1 - n, status);
    APPEND(buf, &n, "\"");

    return n;
}

/* Finalise and flush the buffer as a single write(2) call. */
static void emit_event(char *buf, int n)
{
    if (hs_log_fd < 0) return;
    if (n > LOG_BUFSZ - 3) n = LOG_BUFSZ - 3;
    buf[n++] = '}';
    buf[n++] = '\n';
    buf[n]   = '\0';

    pthread_mutex_lock(&hs_log_lock);
    (void)write(hs_log_fd, buf, (size_t)n);
    pthread_mutex_unlock(&hs_log_lock);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

void hs_log_init(int *ok_out)
{
    if (ok_out) *ok_out = 0;

    const char *run   = getenv(HS_ENV_RUN_ID);
    const char *batch = getenv(HS_ENV_BATCH_ID);
    if (run)   snprintf(hs_run_id,   sizeof(hs_run_id),   "%s", run);
    if (batch) snprintf(hs_batch_id, sizeof(hs_batch_id), "%s", batch);

    const char *path = getenv(HS_ENV_LOG);
    if (!path || !*path) {
        hs_log_fd = STDERR_FILENO;
        if (ok_out) *ok_out = 1;
        return;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        const char msg[] = "heapsentry: failed to open log file\n";
        (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
        return;
    }
    hs_log_fd = fd;
    if (ok_out) *ok_out = 1;
}

void hs_log_initialization(const char *status)
{
    if (hs_log_fd < 0) return;
    char buf[LOG_BUFSZ];
    int n = emit_prefix(buf, next_event_id(), "initialization", status);
    emit_event(buf, n);
}

void hs_log_allocation(uint64_t alloc_id, void *user_ptr, size_t user_size)
{
    if (hs_log_fd < 0) return;
    char buf[LOG_BUFSZ];
    int n = emit_prefix(buf, next_event_id(), "allocation", "ok");
    APPEND(buf, &n, ",\"allocation_id\":%" PRIu64, alloc_id);
    APPEND(buf, &n, ",\"address\":\"0x%" PRIx64 "\"",
           (uint64_t)(uintptr_t)user_ptr);
    APPEND(buf, &n, ",\"size\":%" PRIu64, (uint64_t)user_size);
    emit_event(buf, n);
}

void hs_log_deallocation(uint64_t alloc_id, void *user_ptr, size_t user_size)
{
    if (hs_log_fd < 0) return;
    char buf[LOG_BUFSZ];
    int n = emit_prefix(buf, next_event_id(), "deallocation", "ok");
    APPEND(buf, &n, ",\"allocation_id\":%" PRIu64, alloc_id);
    APPEND(buf, &n, ",\"address\":\"0x%" PRIx64 "\"",
           (uint64_t)(uintptr_t)user_ptr);
    APPEND(buf, &n, ",\"size\":%" PRIu64, (uint64_t)user_size);
    emit_event(buf, n);
}

void hs_log_reallocation(uint64_t old_id, void *old_ptr,
                         uint64_t new_id, void *new_ptr,
                         size_t old_size, size_t new_size)
{
    if (hs_log_fd < 0) return;
    char buf[LOG_BUFSZ];
    int n = emit_prefix(buf, next_event_id(), "reallocation", "ok");
    APPEND(buf, &n, ",\"old_allocation_id\":%" PRIu64, old_id);
    APPEND(buf, &n, ",\"old_address\":\"0x%" PRIx64 "\"",
           (uint64_t)(uintptr_t)old_ptr);
    APPEND(buf, &n, ",\"old_size\":%" PRIu64, (uint64_t)old_size);
    APPEND(buf, &n, ",\"new_allocation_id\":%" PRIu64, new_id);
    APPEND(buf, &n, ",\"new_address\":\"0x%" PRIx64 "\"",
           (uint64_t)(uintptr_t)new_ptr);
    APPEND(buf, &n, ",\"new_size\":%" PRIu64, (uint64_t)new_size);
    emit_event(buf, n);
}

void hs_log_calloc(uint64_t alloc_id, void *user_ptr,
                   size_t nmemb, size_t elem_size, size_t total)
{
    if (hs_log_fd < 0) return;
    char buf[LOG_BUFSZ];
    int n = emit_prefix(buf, next_event_id(), "calloc", "ok");
    APPEND(buf, &n, ",\"allocation_id\":%" PRIu64, alloc_id);
    APPEND(buf, &n, ",\"address\":\"0x%" PRIx64 "\"",
           (uint64_t)(uintptr_t)user_ptr);
    APPEND(buf, &n, ",\"nmemb\":%" PRIu64,    (uint64_t)nmemb);
    APPEND(buf, &n, ",\"elem_size\":%" PRIu64, (uint64_t)elem_size);
    APPEND(buf, &n, ",\"size\":%" PRIu64,      (uint64_t)total);
    emit_event(buf, n);
}

void hs_log_heap_overflow(uint64_t alloc_id, void *user_ptr, size_t user_size,
                          const char *side, uint64_t corrupted_canary)
{
    if (hs_log_fd < 0) return;
    char buf[LOG_BUFSZ];
    int n = emit_prefix(buf, next_event_id(), "heap_buffer_overflow", "error");
    APPEND(buf, &n, ",\"allocation_id\":%" PRIu64, alloc_id);
    APPEND(buf, &n, ",\"address\":\"0x%" PRIx64 "\"",
           (uint64_t)(uintptr_t)user_ptr);
    APPEND(buf, &n, ",\"overflow_side\":\"%s\"", side ? side : "unknown");
    APPEND(buf, &n, ",\"user_size\":%" PRIu64, (uint64_t)user_size);
    APPEND(buf, &n, ",\"corrupted_canary\":\"0x%" PRIx64 "\"", corrupted_canary);
    emit_event(buf, n);
}

void hs_log_double_free(void *user_ptr, uint64_t original_alloc_id)
{
    if (hs_log_fd < 0) return;
    char buf[LOG_BUFSZ];
    int n = emit_prefix(buf, next_event_id(), "double_free", "error");
    APPEND(buf, &n, ",\"address\":\"0x%" PRIx64 "\"",
           (uint64_t)(uintptr_t)user_ptr);
    APPEND(buf, &n, ",\"original_alloc_id\":%" PRIu64, original_alloc_id);
    emit_event(buf, n);
}

void hs_log_uaf_write(uint64_t alloc_id, void *user_ptr, size_t user_size)
{
    if (hs_log_fd < 0) return;
    char buf[LOG_BUFSZ];
    int n = emit_prefix(buf, next_event_id(), "use_after_free_write", "error");
    APPEND(buf, &n, ",\"address\":\"0x%" PRIx64 "\"",
           (uint64_t)(uintptr_t)user_ptr);
    APPEND(buf, &n, ",\"allocation_id\":%" PRIu64, alloc_id);
    APPEND(buf, &n, ",\"user_size\":%" PRIu64, (uint64_t)user_size);
    emit_event(buf, n);
}

void hs_log_leak(uint64_t alloc_id, void *user_ptr, size_t user_size)
{
    if (hs_log_fd < 0) return;
    char buf[LOG_BUFSZ];
    int n = emit_prefix(buf, next_event_id(), "memory_leak", "error");
    APPEND(buf, &n, ",\"allocation_id\":%" PRIu64, alloc_id);
    APPEND(buf, &n, ",\"address\":\"0x%" PRIx64 "\"",
           (uint64_t)(uintptr_t)user_ptr);
    APPEND(buf, &n, ",\"size\":%" PRIu64, (uint64_t)user_size);
    emit_event(buf, n);
}

void hs_log_dropped(void)
{
    if (hs_log_fd < 0) return;
    char buf[LOG_BUFSZ];
    int n = emit_prefix(buf, next_event_id(), "dropped", "warn");
    emit_event(buf, n);
}
