# Instrumentation limitations — HeapSentry Runtime Core

Read this before interpreting HeapSentry evidence. Everything here reflects
the implemented behavior of `libheapsentry.so`.

## Supported configuration (as tested)

- Linux x86_64, glibc 2.39 (Ubuntu 24.04), gcc 13.3.
- Dynamically linked ELF executables using glibc's malloc — i.e. no
  `LD_PRELOAD` effect on fully static binaries and no support for
  non-glibc allocators (`jemalloc`, `tcmalloc`; those would be resolved by
  `RTLD_NEXT` and can be linked after HeapSentry with different results —
  interposition ordering is not tested and not supported).
- Interposition limited to `malloc`, `free`, `realloc`. Other allocator
  entry points (`calloc`, `memalign`, `posix_memalign`, `aligned_alloc`,
  `strdup`, …) call the real allocator **directly and are not observed**;
  their pointers may later appear as `untracked` deallocations.
- Secure-execution (setuid) binaries ignore `LD_PRELOAD` entirely — a
  kernel/dynamic-loader restriction, not a HeapSentry choice.

## Observation is not detection

A `deallocation` after out-of-bounds writes, or the absence of events
between two events, is **not** proof of a vulnerability or of its absence:

- HeapSentry logs the lifecycle of allocations only. It does not observe
  memory accesses, cannot see overflows into adjacent chunks, use-after-free
  reads, or invalid frees of legitimately-obtained pointers.
- The vulnerable demo (`targets/vulnerable_demo.c`) writes past an 8-byte
  heap block. In our controlled runs glibc did not even crash, and the
  resulting log shows a normal allocation → deallocation pair; the
  corruption itself is invisible to this module. Crash analysis is Person
  2's module, under a debugger, not this library.
- A clean event stream does not mean the program is memory-safe.

## Known precision limits

- **Bootstrap window**: allocations made before the constructor finishes
  are served from a ~256 KiB static arena and emit no events. Frees of
  those pointers appear as `untracked` deallocation events.
- **Unwrapped allocator entry points** produce `untracked` frees (e.g.
  `strdup()`'s pointer later freed). Sizes/ids for such pointers are null.
- **Tracker exhaustion** (`RUNTIMEX_MAX_TRACKED` live allocations, or a
  lower `HEAPSENTRY_TRACKED`): newer allocations stay untracked. Behavior is
  documented and tested; it must not be misread as a memory error.
- **Thread ordering**: `event_id` reflects emission order, which may not
  match cross-thread *call* order (see architecture docs). Per-thread
  analysis should filter by `thread_id`.
- **CLOCK_MONOTONIC timestamps** are not comparable across runs and are
  not wall time.
- **Signals**: the logger is not documented as async-signal-safe. If the
  target's signal handler allocates during emission, we make no guarantee;
  the recursion guard forwards such calls to the real allocator rather
  than recursing.
- **`fork()`/multi-process targets**: the default destination (unset
  `HEAPSENTRY_LOG`) is per process (`heapsentry_events_<pid>.jsonl`), so
  instrumented children never interleave into one file. With an explicit
  `HEAPSENTRY_LOG`, one file for one instrumented target remains the
  contract; a forked child inheriting an explicit path can still interleave
  (documented limitation). Crashlab's GDB bridge drops the target's
  `LD_PRELOAD` so the debugger is never instrumented (verified regression:
  gdb under the preload once emitted thousands of untracked events into a
  shared log).
- Zero-size realloc semantics follow glibc (`free(p); return NULL`); other
  libcs may return a valid minimal pointer instead, which this module
  would treat as a normal successful realloc — behavior then deviates from
  this documentation.

## Overhead (measured)

`make bench` reports (Ubuntu 24.04, WSL2-ish dev box, 8 threads × 2000
iterations ≈ 36 685 allocating ops):

- uninstrumented threaded_demo: 0.00–0.01 s
- instrumented: 0.09–0.12 s (36 692 events each run; no drops)

The overhead is dominated by one `write()` syscall per event plus JSONL
rendering — an intentional trade for gapless, complete lines. No
performance claims beyond this environment should be repeated.

## Explicit non-goals

Universal detection of all memory-safety bugs; exploit generation; fuzzing;
any kind of remote operation. HeapSentry is an *observation* layer for
controlled local research programs.
