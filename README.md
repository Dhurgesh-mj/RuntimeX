# RuntimeX — Runtime Core (Person 1)

**Runtime-Assisted Exploitability Research Platform** — runtime
instrumentation module. `libruntimex.so` observes `malloc`, `free`, and
`realloc` in dynamically linked Linux programs (via `LD_PRELOAD`) and emits
a structured JSONL event log of allocation lifecycle operations for a
separate crash-analysis module (Person 2's module, not in this repository).

An authorized local memory-safety **research** component: it *observes*; it
does not detect vulnerabilities on its own, and it does not exploit anything.

## Scope (Person 1)

- Shared library `libruntimex.so` (C, `LD_PRELOAD`)
- `dlsym(RTLD_NEXT)` resolution of the real allocator
- Wrappers for `malloc`, `free`, `realloc` with correct delegation,
  recursion handling, and `errno` preservation
- Heap-lifecycle tracking with stable, per-run allocation identities
- JSONL event logger (fixed-buffer, `write(2)`, schema v1)
- Native C test programs, automated tests, Makefile, documentation

Not here (Person 2): Python runner, crash detection/classification, GDB
automation, sanitizer-output parsing, reports.

## Supported environment (as tested)

- Linux x86_64, glibc 2.39 (Ubuntu 24.04), gcc ≥ 13, GNU make, python3
- Dynamically linked ELF binaries using glibc's malloc
- `python3-jsonschema` (optional: enables up to full Draft 2020-12 check)

## Build

```sh
make all     # -> build/libruntimex.so + test programs
```

## Run

```sh
LD_PRELOAD=$(pwd)/build/libruntimex.so \
  RUNTIMEX_LOG=/tmp/opencode/events.jsonl ./build/safe_demo
```

- `RUNTIMEX_LOG` — output file path (default `./runtimex_events.jsonl`;
  opened with `O_TRUNC`, so **one file per process run**).
- `RUNTIMEX_TRACKED` — optional; lowers the live-tracking capacity
  (power of two ≥ 16) to exercise the documented exhaustion policy.

## Build / test commands

```sh
make all      # build the library and binaries
make test     # run instrumented tests + JSONL/schema validation
make check    # + baseline comparison, logging-failure, vulnerable run
make bench    # overhead measurement
make clean    # remove build/ and logs/
```

## JSONL interpretation

See `docs/event-schema.md`; the machine contract is
`shared/event_schema.json` (Draft 2020-12, `"schema_version": 1`).

- Event types: `initialization`, `allocation`, `deallocation`,
  `reallocation`, `logger_error`.
- Statuses: `ok` (allocator operation succeeded)*; `failed` (allocator
  operation failed, e.g. `malloc(SIZE_MAX)`); `untracked` (pointer identity
  not available: unwrapped entry point, tracker exhaustion, bootstrap
  chunk). `*` status of allocator ops, never of the logging itself.
- `allocation_id`: stable identity, minted per successful allocation;
  null = no allocation / unknown. A successful realloc mints a NEW id that
  supersedes the old even when the address is unchanged.
- Events are ordered by `event_id` (emission order, which equals the on-disk
  order); it is not guaranteed to be the cross-thread call order.
- If logging fails, affected events are missing (counted in the process,
  not marked in-line) — treat short/absent logs as incomplete evidence.

## Integration for Person 2

1. Build: `make all` in a clean checkout.
2. For each target execution, choose a fresh log path and run:
   `LD_PRELOAD=<abs path>/build/libruntimex.so RUNTIMEX_LOG=<run>.jsonl <target>`.
   One log file = one execution; the `initialization` event (event_id 0)
   marks the start; process exit ends it.
3. Parse with `tests/test_event_schema.py` (`python3 tests/test_event_schema.py run.jsonl`)
   for syntax + contract validation before your analysis. Real examples:
   `examples/sample-events.jsonl`.
4. Semantics, id rules, ordering, error handling: `docs/event-schema.md`;
   boundaries: `docs/instrumentation-limitations.md`; internals:
   `docs/runtime-architecture.md`. The Python runner/crash engine stays in
   your module — the schema and this contract are the only touchpoints.
5. Handle the documented partial-evidence cases: missing log file, dropped
   events (no marker in-line), `untracked` statuses, unwrapped allocator
   entry points, and `fork()` fd inheritance.

## Demonstration (verified reproduction)

```sh
make clean && make check && make bench
head -5 logs/safe_demo.jsonl
python3 tests/test_event_schema.py examples/sample-events.jsonl
```

## Known limitations

See `docs/instrumentation-limitations.md`. Highlights: unwrapped allocator
entry points, bootstrap-window allocations, exhaustion → `untracked`,
log-less runs on logging failure, no crash-detection claims, measured
overhead of one write per event (~36.7k events ≈ 0.1 s here).
