# HeapSentry runtime architecture (Person 1 module)

This document describes the **implemented** architecture of
`libheapsentry.so`. Statements here reflect verified behavior in the
documented environment (Ubuntu 24.04, x86_64, glibc 2.39, gcc 13.3);
see `instrumentation-limitations.md` for what is *not* supported or proven.

## 1. Module layout

| File | Responsibility |
|---|---|
| `preload/internal.h` | Shared internal declarations, schema version, tracking limits |
| `preload/symbol_resolver.c` | `dlsym(RTLD_NEXT, …)` resolution of the real allocator |
| `preload/allocator_hooks.c` | `malloc`/`free`/`realloc` wrappers, bootstrap arena, lifecycle table |
| `preload/event_logger.c` | Fixed-buffer JSONL rendering and `write(2)` emission |
| `preload/hooks.c` | Library constructor; emits `initialization` events |

## 2. Symbol resolution

`rtx_resolve_symbols()` resolves `malloc`, `free`, `realloc` via
`dlsym(RTLD_NEXT, …)` at constructor time (priority 101, early). A missing
symbol or `dlerror()` output marks resolution failure and the library stays
in a degraded state.

Recursion considerations:

- glibc's `dlsym()` may allocate (calloc) internally. HeapSentry does **not**
  wrap `calloc`, so `dlsym`'s internal allocations cannot recurse into the
  wrappers. Any later `free()` of that memory arrives as an *untracked*
  pointer and is forwarded to the real `free()`, which is its true owner.
- While `rtx_resolving` is nonzero the wrappers treat the state as
  "not ready" and serve allocations from the bootstrap arena.

If resolution fails, allocation requests fall back to a **static bootstrap
arena** (~256 KiB, bump allocator with size headers, never reclaimed). The
arena answers real allocations; frees and reallocs of bootstrap chunks are
performed without calling the real allocator on those pointers. The failure
is recorded as an `initialization` event with `"status":"failed"`. The
library never fabricates success: when the arena is exhausted, `malloc`
returns `NULL` with `errno = ENOMEM`.

## 3. Wrapper design

All three wrappers follow the same shape:

1. Recursion check (`__thread int t_in_hook`, `initial-exec` TLS model —
   safe for an `LD_PRELOAD`ed library and avoids lazy-TLS allocation).
2. Call the real allocator by the resolved function pointer.
3. Restore `errno` captured immediately after the real call, so the
   instrumentation cannot clobber allocator error reporting.
4. Update the lifecycle table and emit one JSONL event, converting
   allocator status into event status (`ok` / `failed` / `untracked`).
   Results are never altered by logging failures.

Special cases are explicit:

- `free(NULL)` → standard no-op, **no event emitted** (documented).
- `free` of an untracked pointer → real `free` is called; event status is
  `untracked` with `allocation_id: null`.
- `free` of a bootstrap-arena pointer → no real `free` call (ownership rule:
  the pointer did not come from the real allocator); event status `untracked`.
- `realloc(NULL, n)` → routed to the `malloc` path, event `allocation`.
- `realloc(p, 0)` → follows glibc semantics: frees `p`, returns `NULL`;
  recorded as `reallocation` with `status:"ok"`, `size:0`, no new id.
- failed `realloc` → the original block and its metadata row are preserved;
  event `reallocation` with `status:"failed"`, `allocation_id: null`,
  `old_allocation_id` still valid.

## 4. Lifecycle tracking and allocation identity

- A **new allocation id** is minted (`add_fetch`) for every successful
  allocating operation: `malloc` success, successful `realloc` (even when
  the returned address is unchanged — the new id *supersedes* the old one).
  Ids start at 1; id 0 always means "no allocation" (`allocation_id: null`).
- A pointer address alone is never treated as permanent identity. A freed
  id may never be minted again *in the same run* (ids are strictly
  increasing), so a second allocation of the same address always gets a
  fresh id. The Python validator enforces this invariant.
- The table is a fixed open-addressing hash table of
  `RUNTIMEX_MAX_TRACKED` (65536) slots in `.bss`. Removal leaves
  tombstones; lookup skips tombstones. No heap allocation happens anywhere
  in the instrumentation, which is the structural guarantee against
  recursive entry through the allocator.
- Capacity can be lowered at init with `HEAPSENTRY_TRACKED` (power of two,
  ≥16) to exercise exhaustion. When live entries reach capacity, new
  allocations are logged normally but **not tracked**: their later frees
  are `untracked`. Tracker exhaustion never changes allocator results.

## 5. Logging

`event_logger.c` renders each event into a fixed 2 KiB buffer (no stdio,
no heap) and issues one fully-retried `write(2)` (short writes and `EINTR`
handled) while holding a pthread mutex. Consequences:

- Event ids (`event_id`) are assigned under the logger mutex, so **the id
  order equals the write order** in the file: strictly increasing, gapless
  from 0 — verified by tests on multithreaded runs.
- `timestamp_ns` is `CLOCK_MONOTONIC` (not wall time; intervals only).
- `thread_id` is the Linux `gettid()` value; `process_id` is `getpid()`.
- Strings are JSON-escaped by a small escaping writer; integers are emitted
  as unsigned decimals. `null` marks unavailable values.
- Output goes to `HEAPSENTRY_LOG` (`O_TRUNC|O_APPEND`; each process run maps
  with an unset `HEAPSENTRY_LOG` the default is **per process**
  (`heapsentry_events_<pid>.jsonl`).

Failure policy (also in `event-schema.md`):

- Open failure at init (`invalid path`, `EACCES`, …): sticky failed state;
  every event is counted as dropped (`heapsentry_dropped_events()`).
- First unsuccessful `write()` (e.g. `ENOSPC` to `/dev/full`): sticky
  failed state, fd closed, later events dropped.
- One `logger_error` event is attempted on first failure; its own failure
  is silently counted (no recursion).
- Dropped events are **not** present in the log (no partial lines), so an
  externally-observed log contains no incomplete records — but a log may
  be truncated relative to what actually happened. There is no in-file
  marker for dropped events; if the log never opens, there is no file at
  all. Consumers must treat a missing/short log as an incomplete run.

## 6. Concurrency

- Metadata table: single global pthread mutex; writers (malloc/realloc/free
  of tracked pointers) serialize briefly (hash + probe; O(1) amortized).
- Logger: single global pthread mutex; one `write()` per event.
- Lock ordering is always table → logger; no other locks exist, so no
  lock-order cycles are possible.
- Two events from different threads may be assigned ids in a slightly
  different order than the underlying thread executed the *allocation
  calls* (the two mutexes are taken per event); consumers must not infer
  a total order of allocator calls beyond the (emission-ordered) `event_id`
  sequence and `timestamp_ns` ranges.
- The bootstrap arena is only serviced before/while initialization, which
  is single-threaded by construction of ELF startup.

## 7. Initialization sequence

```
constructor(101): rtx_table_init()      # reads HEAPSENTRY_TRACKED, clears table
                 rtx_resolve_symbols()  # dlsym x3; sets rtx_ready
                 rtx_event_logger_init()# HEAPSENTRY_LOG; on failure → sticky
                 rtx_log_initialization(status)  # first event (id 0)
```

`initialization` status is `ok` only when **both** symbol resolution and
log opening succeeded; `failed` if either failed (the event may then be
dropped if the log itself could not be opened — documented gap).
