/*
 * RuntimeX Runtime Core — JSONL event logger (Person 1).
 *
 * Low-level write(2)-based logger. No stdio, no heap allocation in the
 * hot path: an event line is rendered into a fixed buffer and issued with
 * a single fully-retried write() under a mutex, so event_id order matches
 * write order.
 *
 * Failure policy (see docs/event-schema.md):
 *  - If the log cannot be opened at init, every event is counted as dropped.
 *  - On the first write failure the logger enters a sticky failed state,
 *    closes the fd and drops all later events (counted).
 *  - One `logger_error` event is attempted on first failure; emitting it
 *    can itself fail and is then silently counted as dropped (no recursion).
 *  - Logging failures never alter allocator return values.
 */
#include "internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define RTX_LINE_MAX 2048

static int g_log_fd = -1;
static int g_log_failed = 0;
static int g_logger_error_logged = 0;
static uint64_t g_event_seq = 0;
static uint64_t g_dropped = 0;
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

/* ---------------- fixed-buffer JSON writer ---------------- */

typedef struct {
    char *p;    /* write cursor */
    char *end;  /* one past last usable byte of the buffer */
    int   overflow;
} wbuf_t;

static void wb_litn(wbuf_t *w, const char *s, size_t n)
{
    if (w->overflow || (size_t)(w->end - w->p) < n) {
        w->overflow = 1;
        return;
    }
    memcpy(w->p, s, n);
    w->p += n;
}

static void wb_lit(wbuf_t *w, const char *s)
{
    size_t n = strlen(s);
    if (w->overflow || (size_t)(w->end - w->p) < n) {
        w->overflow = 1;
        return;
    }
    memcpy(w->p, s, n);
    w->p += n;
}

static void wb_ch(wbuf_t *w, char c)
{
    if (w->overflow || (w->end - w->p) < 1) {
        w->overflow = 1;
        return;
    }
    *w->p++ = c;
}

static void wb_u64(wbuf_t *w, uint64_t v)
{
    char tmp[20];
    int i = (int)sizeof(tmp);
    if (v == 0) { wb_ch(w, '0'); return; }
    while (v && i > 0) { tmp[--i] = (char)('0' + (v % 10)); v /= 10; }
    wb_litn(w, tmp + i, (size_t)(sizeof(tmp) - (size_t)i));
}

/* JSON-escaped string (values are internal literals or statuses). */
static void wb_json_str(wbuf_t *w, const char *s)
{
    wb_ch(w, '"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            wb_ch(w, '\\');
            wb_ch(w, (char)c);
        } else if (c == '\n') {
            wb_lit(w, "\\n");
        } else if (c == '\r') {
            wb_lit(w, "\\r");
        } else if (c == '\t') {
            wb_lit(w, "\\t");
        } else if (c < 0x20) {
            char esc[7];
            static const char hex[] = "0123456789abcdef";
            esc[0] = '\\'; esc[1] = 'u'; esc[2] = '0'; esc[3] = '0';
            esc[4] = hex[c >> 4];
            esc[5] = hex[c & 0xF];
            esc[6] = '\0';
            wb_lit(w, esc);
        } else {
            wb_ch(w, (char)c);
        }
    }
    wb_ch(w, '"');
}

/* ---------------- core emission ---------------- */

static uint64_t now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t tid_self(void)
{
    return (uint64_t)syscall(SYS_gettid);
}

/* Common prefix fields. */
static void wb_common_prefix(wbuf_t *w, uint64_t event_id, const char *event)
{
    wb_lit(w, "{\"schema_version\":1,\"event_id\":");
    wb_u64(w, event_id);
    wb_lit(w, ",\"event\":");
    wb_json_str(w, event);
}

static void wb_id_field(wbuf_t *w, const char *name, uint64_t id)
{
    wb_lit(w, ",\"");
    wb_lit(w, name);
    wb_lit(w, "\":");
    if (id == 0) wb_lit(w, "null");
    else wb_u64(w, id);
}

static void wb_common_tail(wbuf_t *w, uint64_t ts, const char *status)
{
    wb_lit(w, ",\"timestamp_ns\":");
    wb_u64(w, ts);
    wb_lit(w, ",\"process_id\":");
    wb_u64(w, (uint64_t)getpid());
    wb_lit(w, ",\"thread_id\":");
    wb_u64(w, tid_self());
    wb_lit(w, ",\"status\":");
    wb_json_str(w, status);
    wb_lit(w, "}\n");
}

/* Render one event; returns line length, 0 on overflow/unavailable. */
static size_t render_event(char *buf, size_t cap, uint64_t event_id,
                           const char *event, const char *status,
                           int has_alloc, uint64_t id,
                           int has_old_alloc, uint64_t old_id,
                           int has_size, size_t size,
                           int has_old_size, long long old_size_signed,
                           int has_msg, const char *msg)
{
    wbuf_t w;
    w.p = buf;
    w.end = buf + cap;
    w.overflow = 0;

    wb_common_prefix(&w, event_id, event);
    if (has_alloc)     wb_id_field(&w, "allocation_id", id);
    if (has_old_alloc) wb_id_field(&w, "old_allocation_id", old_id);
    if (has_size) {
        wb_lit(&w, ",\"size\":");
        wb_u64(&w, (uint64_t)size);
    }
    if (has_old_size) {
        if (old_size_signed >= 0) {
            wb_lit(&w, ",\"old_size\":");
            wb_u64(&w, (uint64_t)old_size_signed);
        } else {
            wb_lit(&w, ",\"old_size\":null");
        }
    }
    if (has_msg) {
        wb_lit(&w, ",\"message\":");
        wb_json_str(&w, msg);
    }
    wb_common_tail(&w, now_ns(), status);
    return w.overflow ? 0 : (size_t)(w.p - buf);
}

/* Write a fully-rendered line, retrying EINTR/short writes.
 * Called with g_log_lock held. Returns 0 on success, -1 on failure. */
static int write_all(const char *buf, size_t len)
{
    size_t written = 0;
    while (written < len) {
        ssize_t r = write(g_log_fd, buf + written, len - written);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            return -1;
        written += (size_t)r;
    }
    return 0;
}

int rtx_event_logger_init(int *ok_out)
{
    const char *path;
    int fd;

    if (ok_out)
        *ok_out = 1;

    pthread_mutex_lock(&g_log_lock);
    if (g_log_fd >= 0 || g_log_failed) {
        if (ok_out)
            *ok_out = g_log_fd >= 0;
        pthread_mutex_unlock(&g_log_lock);
        return g_log_fd >= 0 ? 0 : -1;
    }
    path = getenv("RUNTIMEX_LOG");
    if (path == NULL || path[0] == '\0')
        path = "./runtimex_events.jsonl";
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
    if (fd < 0) {
        g_log_failed = 1;
        g_dropped++;
        if (ok_out)
            *ok_out = 0;
        pthread_mutex_unlock(&g_log_lock);
        return -1;
    }
    g_log_fd = fd;
    pthread_mutex_unlock(&g_log_lock);
    return 0;
}

/* One logger_error event, no recursive error handling, no sticky state
 * change on its own failure (the caller already set the sticky state). */
static void emit_logger_error_once(const char *message)
{
    char buf[RTX_LINE_MAX];
    size_t len;
    uint64_t eid;

    if (g_log_fd < 0 ||
        __atomic_load_n(&g_logger_error_logged, __ATOMIC_SEQ_CST))
        return;
    __atomic_store_n(&g_logger_error_logged, 1, __ATOMIC_SEQ_CST);

    pthread_mutex_lock(&g_log_lock);
    eid = g_event_seq;
    len = render_event(buf, sizeof(buf), eid, RTX_EVENT_LOGGER_ERROR,
                       RTX_STATUS_FAILED,
                       1, 0, 0, 0, 0, 0, 0, -1, 1, message);
    if (len == 0 || write_all(buf, len) != 0) {
        g_dropped++;
    } else {
        g_event_seq++;
    }
    pthread_mutex_unlock(&g_log_lock);
}

/* Generic emitter used by all public log functions. */
static void emit(const char *event, const char *status,
                 int has_alloc, uint64_t id,
                 int has_old_alloc, uint64_t old_id,
                 int has_size, size_t size,
                 int has_old_size, long long old_size_signed)
{
    char buf[RTX_LINE_MAX];
    size_t len;
    uint64_t eid;
    int saved_errno = errno;

    pthread_mutex_lock(&g_log_lock);
    if (g_log_fd < 0 || g_log_failed) {
        g_dropped++;
        pthread_mutex_unlock(&g_log_lock);
        errno = saved_errno;
        return;
    }
    eid = g_event_seq;
    len = render_event(buf, sizeof(buf), eid, event, status,
                       has_alloc, id, has_old_alloc, old_id,
                       has_size, size, has_old_size, old_size_signed,
                       0, NULL);
    if (len == 0) {
        g_dropped++;
        emit_logger_error_once("event line exceeded limits");
    } else if (write_all(buf, len) != 0) {
        int fd = g_log_fd;
        g_log_failed = 1;
        g_dropped++;
        g_log_fd = -1;
        close(fd);
        emit_logger_error_once("log write failure; closing event log");
    } else {
        g_event_seq++;
    }
    pthread_mutex_unlock(&g_log_lock);
    errno = saved_errno;
}

/* ---------------- public emitters ---------------- */

void rtx_log_initialization(const char *status)
{
    emit(RTX_EVENT_INIT, status, 1, 0, 0, 0, 0, 0, 0, -1);
}

void rtx_log_allocation(uint64_t id, size_t size, const char *status)
{
    emit(RTX_EVENT_ALLOCATION, status, 1, id, 0, 0, 1, size, 0, -1);
}

void rtx_log_deallocation(uint64_t id, size_t old_size, const char *status)
{
    /* old_size is meaningful only for tracked frees (status ok). */
    int has_old = (id != 0);
    emit(RTX_EVENT_DEALLOCATION, status, 1, id,
         0, 0, 0, 0, has_old ? 1 : 0, has_old ? (long long)old_size : -1);
}

void rtx_log_reallocation(uint64_t new_id, uint64_t old_id,
                          long long old_size_signed, size_t size,
                          const char *status)
{
    emit(RTX_EVENT_REALLOCATION, status, 1, new_id, 1, old_id,
         1, size, 1, old_size_signed);
}

void rtx_log_logger_error(const char *message)
{
    emit_logger_error_once(message);
}

uint64_t rtx_log_dropped(void)
{
    return __atomic_load_n(&g_dropped, __ATOMIC_SEQ_CST);
}
