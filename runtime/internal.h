/*
 * internal.h — HeapSentry runtime internal header
 * Platform-aware; compiles on macOS arm64 (clang) and Linux x86_64/arm64 (GCC).
 */
#pragma once
#ifndef HEAPSENTRY_INTERNAL_H
#define HEAPSENTRY_INTERNAL_H

/* ── Standard C headers ──────────────────────────────────────────────────── */
#include <stdint.h>
#include <stddef.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <dlfcn.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

/* ── Platform guards ─────────────────────────────────────────────────────── */
#ifdef __APPLE__
#  include <sys/types.h>
#  include <mach/mach_time.h>
#  define HS_TID()           ((uint64_t)(uintptr_t)pthread_self())
#  define HS_SHARED_LIB_FLAGS  /* macOS: -dynamiclib */
#else
#  include <sys/syscall.h>
#  include <sys/types.h>
#  define HS_TID()           ((uint64_t)syscall(SYS_gettid))
#endif

/* ── Schema & version ────────────────────────────────────────────────────── */
#define HS_SCHEMA_VERSION    2

/* ── Red-zone constants ──────────────────────────────────────────────────── */
#define HS_REDZONE_SIZE      16u
#define HS_CANARY_VALUE      UINT64_C(0xFEEDFACEDEADBEEF)
#define HS_POISON_BYTE       0xDD
#define HS_QUARANTINE_MAX    512u

/* ── Capacity ────────────────────────────────────────────────────────────── */
#define HS_MAX_TRACKED       65536u

/* ── Bootstrap arena ─────────────────────────────────────────────────────── */
#define HS_BOOT_ARENA_SIZE   (512u * 1024u)

/* ── Environment variable names ──────────────────────────────────────────── */
#define HS_ENV_LOG           "HEAPSENTRY_LOG"
#define HS_ENV_TRACKED       "HEAPSENTRY_TRACKED"
#define HS_ENV_RUN_ID        "CRASHLAB_RUN_ID"
#define HS_ENV_BATCH_ID      "CRASHLAB_BATCH_ID"

/* ─────────────────────────────────────────────────────────────────────────
 * Block header (32 bytes, 16-byte aligned)
 *
 * Memory layout of a HeapSentry allocation:
 *
 *   [ hs_block_hdr_t (32 B) ][ user data (user_size B) ][ right canary (16 B) ]
 *
 * The left canary lives inside the header struct (canary_left_0/1).
 * ────────────────────────────────────────────────────────────────────────── */
typedef struct __attribute__((aligned(16))) hs_block_hdr {
    uint64_t canary_left_0;   /* HS_CANARY_VALUE */
    uint64_t canary_left_1;   /* HS_CANARY_VALUE */
    uint64_t alloc_id;        /* allocation identity (monotonic counter) */
    size_t   user_size;       /* originally requested size */
    /* [user data follows: user_size bytes]                                  */
    /* [right canary: 2 × uint64_t = 16 bytes, both HS_CANARY_VALUE]        */
} hs_block_hdr_t;

/* Compile-time size assertion: header must be exactly 32 bytes.            */
typedef char _hs_hdr_size_check[sizeof(hs_block_hdr_t) == 32u ? 1 : -1];

/* ── Bootstrap block header (no red zones, for pre-resolution allocs) ───── */
typedef struct hs_boot_hdr {
    size_t size;   /* payload size, not including this header */
} hs_boot_hdr_t;

/* ─────────────────────────────────────────────────────────────────────────
 * Real allocator function-pointer types
 * ────────────────────────────────────────────────────────────────────────── */
typedef void *(*hs_malloc_fn)(size_t);
typedef void  (*hs_free_fn)(void *);
typedef void *(*hs_realloc_fn)(void *, size_t);
typedef void *(*hs_calloc_fn)(size_t, size_t);

/* Extern declarations — defined in resolver.c */
extern volatile hs_malloc_fn   hs_real_malloc;
extern volatile hs_free_fn     hs_real_free;
extern volatile hs_realloc_fn  hs_real_realloc;
extern volatile hs_calloc_fn   hs_real_calloc;

/* ── Runtime state ───────────────────────────────────────────────────────── */
extern volatile int  hs_ready;       /* 1 once init is complete             */
extern volatile int  hs_resolving;   /* 1 while dlsym is in-flight          */
extern uint64_t      hs_next_alloc_id; /* monotonic allocation counter       */

/* ── Thread-local recursion guard ────────────────────────────────────────── */
/* Defined in allocator.c; declared here for all translation units.          */
extern __attribute__((tls_model("initial-exec"))) __thread int hs_in_hook;

/* ── Inline: mint a new allocation id ───────────────────────────────────── */
static inline uint64_t hs_mint_id(void) {
    return (uint64_t)__atomic_add_fetch(&hs_next_alloc_id, 1u, __ATOMIC_SEQ_CST);
}

/* ─────────────────────────────────────────────────────────────────────────
 * Lifecycle table API  (implemented in detector.c)
 * ────────────────────────────────────────────────────────────────────────── */
typedef struct hs_entry {
    void    *user_ptr;
    uint64_t alloc_id;
    size_t   user_size;
} hs_entry_t;

void       hs_table_init(void);
int        hs_table_insert(void *user_ptr, uint64_t alloc_id, size_t user_size);
int        hs_table_remove(void *user_ptr, hs_entry_t *out);
int        hs_table_lookup(void *user_ptr, hs_entry_t *out);
int        hs_table_is_full(void);

/* Walk callback — return 0 to continue, non-zero to stop.                 */
typedef int (*hs_table_walk_fn)(const hs_entry_t *entry, void *ctx);
void       hs_table_walk(hs_table_walk_fn fn, void *ctx);

/* ── Quarantine API  (implemented in detector.c) ─────────────────────────── */
void  hs_quarantine_add(void *user_ptr);
int   hs_quarantine_contains(void *user_ptr);

/* ── Bootstrap arena API  (implemented in allocator.c) ──────────────────── */
void *hs_boot_alloc(size_t size);
int   hs_in_boot_arena(const void *ptr);

/* ── Resolver ────────────────────────────────────────────────────────────── */
int  hs_resolve_symbols(void);

/* ─────────────────────────────────────────────────────────────────────────
 * Logger API  (implemented in logger.c)
 * ────────────────────────────────────────────────────────────────────────── */
void hs_log_init(int *ok_out);
void hs_log_initialization(const char *status);
void hs_log_allocation(uint64_t alloc_id, void *user_ptr, size_t user_size);
void hs_log_deallocation(uint64_t alloc_id, void *user_ptr, size_t user_size);
void hs_log_reallocation(uint64_t old_id, void *old_ptr,
                         uint64_t new_id, void *new_ptr,
                         size_t old_size, size_t new_size);
void hs_log_calloc(uint64_t alloc_id, void *user_ptr,
                   size_t nmemb, size_t elem_size, size_t total);
void hs_log_heap_overflow(uint64_t alloc_id, void *user_ptr, size_t user_size,
                          const char *side, uint64_t corrupted_canary);
void hs_log_double_free(void *user_ptr, uint64_t original_alloc_id);
void hs_log_uaf_write(uint64_t alloc_id, void *user_ptr, size_t user_size);
void hs_log_leak(uint64_t alloc_id, void *user_ptr, size_t user_size);
void hs_log_dropped(void);

/* ── Leak reporter (called by atexit in entry.c) ─────────────────────────── */
void hs_report_leaks_at_exit(void);

#endif /* HEAPSENTRY_INTERNAL_H */
