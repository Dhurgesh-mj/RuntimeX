# HeapSentry

HeapSentry is a defensive memory-safety research project in two parts:

1. **Runtime core** (`preload/`, `shared/`, `targets/`, `docs/architecture.md`,
   `docs/event-schema.md`, `docs/limitations.md`, `docs/testing.md`) —
   an `LD_PRELOAD`-based allocator/event instrumentation layer
   (`build/libheapsentry.so`) that records runtime events around allocation and
   free sites. See [`docs/architecture.md`](docs/architecture.md) and
   [`docs/event-schema.md`](docs/event-schema.md).
2. **Crashlab** (`src/crashlab/`, `pyproject.toml`, `corpus/`, `docs/schema.md`) —
   a Python 3.10+ CLI harness that runs local test binaries, detects and
   classifies crashes, collects GDB/AddressSanitizer evidence, and renders
   JSON/HTML reports for **manual** exploitability triage. See below.

> **Scope.** Both components only detect, reproduce, instrument, and document
> memory-safety defects in authorized local test programs. Neither builds or
> delivers exploits, and a crash is never auto-promoted to a vulnerability:
> read every report record manually before assigning severity.

### How the two components correlate

Crashlab stamps every run with `run_id`, a UTC `timestamp_start`/`timestamp_end`
window, and `batch_id`, and exposes `CRASHLAB_RUN_ID`/`CRASHLAB_BATCH_ID` to the
target environment. The runtime-event logger can join each crash record to its
allocator events by `run_id`, or by overlapping timestamp windows. The full
contract is in [`docs/schema.md`](docs/schema.md) (crash side) and
[`docs/event-schema.md`](docs/event-schema.md) (runtime side).

---

# Crashlab

Crashlab is a defensive memory-safety research harness. It executes **local,
authorized test binaries** under controlled conditions, classifies abnormal
termination, collects GDB/AddressSanitizer evidence, and emits a single
structured crash model that drives both JSON and HTML reports for **manual**
exploitability triage.

> **Scope.** Crashlab only detects, reproduces, and documents crashes. It does
> not build or deliver exploits. A crash is not a vulnerability: a bare
> `SIGSEGV` stays `crash` unless sanitizer or allocator evidence names a concrete
> memory-safety class. Review every record manually before assigning severity.

---

## What it does

- Runs one target against a single input or a whole input directory (worker pool).
- Feeds the exact input bytes through stdin, a file path, or argv.
- Applies a per-run wall-clock timeout and kills the whole process tree.
- Captures stdout, stderr, exit code, and terminal signal.
- Preserves every reproducing input by **copying** it into the run directory.
- Normalizes POSIX signals and Windows NTSTATUS values into one model.
- Optionally collects scripted GDB state and parses ASan reports.
- Deduplicates crashes by signal + normalized top-N stack frames.
- Writes a JSON report (top-level array) and a single-file HTML report from the
  same `CrashRecord` objects.
- Emits correlation keys (`run_id`, UTC timestamp window, `batch_id`) so a
  separately built runtime-event logger can join its data to each crash.

## Requirements

- Python **3.10+** (tested with 3.11 on Windows 11).
- Optional: GDB for symbolic backtraces.
- Optional: an ASan-instrumented target, or a captured ASan report.
- No runtime dependencies beyond the standard library (`tomli` only on 3.10).

## Install

```sh
python -m pip install -e .
crashlab --version
```

Without installing, run from the repository root with `python -m crashlab` after
setting `PYTHONPATH=src` (or `$env:PYTHONPATH = "src"` in PowerShell).

## Quick start (no compiler required)

`examples/synthetic_target.py` is a portable smoke target. It is **not** a real
memory-safety target; it exercises the runner, crash classification, ASan
confirmation path, and both report writers on any host.

```sh
# Normal termination
python -m crashlab run --binary python \
  --binary-arg examples/synthetic_target.py \
  --input corpus/01_normal.bin --out results --timeout 5

# Simulated crash (SIGSEGV on POSIX, NTSTATUS 0xC0000005 on Windows)
python -m crashlab run --binary python \
  --binary-arg examples/synthetic_target.py \
  --input corpus/02_heap_overflow.bin --out results --no-gdb

# Synthetic ASan report => confirmed heap-buffer-overflow
python -m crashlab run --binary python \
  --binary-arg examples/synthetic_target.py \
  --input corpus/08_asan_report.bin --out results --no-gdb \
  --report-json results/report.json --report-html results/report.html
```

## Quick start (real target, POSIX)

```sh
cd examples
make          # ./target
make asan     # ./target_asan

cd ..
crashlab run --binary ./examples/target \
  --input corpus/02_heap_overflow.bin --timeout 5 --workers 4

crashlab run --binary ./examples/target_asan \
  --input corpus/02_heap_overflow.bin --timeout 5 \
  --asan-options abort_on_error=1:detect_leaks=0:symbolize=1

crashlab analyze --results results --gdb-path /usr/bin/gdb
crashlab report --results results --json results/report.json --html results/report.html
```

## Commands

### `crashlab run`

Executes the target against one or more inputs, then analyzes crashes by default.

| Option | Meaning |
|---|---|
| `--binary PATH` | Target executable. Bare names such as `python` are resolved on `PATH`. |
| `--input FILE` | Input file; repeatable. |
| `--input-dir DIR` | Directory of input files; repeatable. |
| `--input-mode {stdin,file,arg}` | Delivery method (default `stdin`). |
| `--arg-template TEMPLATE` | For file/arg mode; `{input}` is replaced. |
| `--binary-arg ARG` | Extra target argument; repeatable. |
| `--preload PATH` | `LD_PRELOAD` library (POSIX only; recorded but not applied on Windows). |
| `--timeout SECONDS` | Per-run wall-clock limit (default `5`). |
| `--workers N` | Batch worker pool size (default `1`). |
| `--cwd DIR` | Child working directory (default: the invocation directory). |
| `--out DIR` | Results root (default `results`). |
| `--config FILE` | TOML configuration file. |
| `--asan-options VALUE` | Value for `ASAN_OPTIONS`. |
| `--gdb-path PATH` | GDB executable. |
| `--gdb` / `--no-gdb` | Enable or disable GDB analysis (default enabled). |
| `--gdb-timeout SECONDS` | GDB wall-clock budget. |
| `--signature-frames N` | Number of normalized frames in a signature (default `5`). |
| `--asan-dir DIR` | Directory of separately captured reports named `<run_id>.*`. |
| `--asan-log FILE` | One ASan report; only valid when exactly one crash is analyzed. |
| `--no-analyze` | Skip crash analysis after execution. |
| `--fail-on-crash` | Exit `3` if any crash or timeout was observed. |
| `--report-json PATH` / `--report-html PATH` | Render reports after analysis. |
| `-v` / `-q` | Debug / errors-only logging. |

### `crashlab analyze`

Re-runs analysis over saved run manifests. Useful after installing GDB or after
capturing ASan logs separately.

```sh
crashlab analyze --results results
crashlab analyze --run results/runs/<run_id> --no-gdb
crashlab analyze --results results --asan-dir ./asan-logs
```

### `crashlab report`

Renders JSON and/or HTML from saved `crash_record.json` files. With no output
flags it writes `results/report.json` and `results/report.html`.

```sh
crashlab report --results results
crashlab report --results results --json - --html report.html
crashlab report --results results --no-raw-evidence
```

Use `--json -` or `--html -` to write to stdout.

### `crashlab doctor`

Prints Python/platform details, whether `LD_PRELOAD` is supported, GDB
availability, detected ASan runtime, and corpus information. It never executes a
target.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Command completed. (Crashes are data, not command failures.) |
| `1` | Nothing to analyze/report: no run manifests or no crash records. |
| `2` | Usage, configuration, or runner error. |
| `3` | `--fail-on-crash` observed at least one crash or timeout. |
| `130` | Interrupted. |

## Classification policy

Execution status and evidence-backed classification are deliberately separate.

**Execution status** (`RunStatus`):

- `normal` — process exited without a crash signal (non-zero exits are still
  `normal` unless a fatal sanitizer report is present).
- `crash` — process terminated by a crash signal, a recognized Windows NTSTATUS,
  or a fatal ASan/UBSan report that chose to exit instead of aborting.
- `timeout` — killed after exceeding the per-run limit.
- `error` — launch failure or an unrecognized/non-crash termination.

**Crash classification** (`Classification`):

- `crash` — abnormal termination observed but **not** promoted. This includes
  bare SIGSEGV/SIGABRT, ASan `SEGV`, and GDB-only null-pointer evidence.
- `confirmed_vulnerability` — a concrete ASan class (heap/stack/global/container
  overflow, use-after-free/return/scope, double-free, invalid-free,
  stack-overflow) or an unambiguous glibc allocator diagnostic named the defect.

The promotion rule lives in `src/crashlab/analysis.py`. LeakSanitizer-only
reports are not crashes and never promote a record.

### Signals and Windows

On POSIX, `subprocess` returns `-SIGNUM`; crashlab maps that to a
`SignalInfo`. Windows has no equivalent convention, so crashlab maps well-known
NTSTATUS values to POSIX pseudo-signals while retaining `native_status`:

| NTSTATUS | Normalized |
|---|---|
| `0xC0000005` | `SIGSEGV` (access violation) |
| `0xC00000FD` | `SIGSEGV` (stack overflow) |
| `0xC000001D`, `0xC0000096` | `SIGILL` |
| `0xC0000094`, `0xC0000095` | `SIGFPE` |
| `0xC0000374`, `0xC0000409`, `0xC0000420` | `SIGABRT` |

Unknown high-bit statuses become `error`, not `crash`. This is intentionally
conservative.

## Deduplication and signatures

A signature answers "are these the same bug?". Preference order:

1. **`gdb`** — signal + normalized top-N GDB frames.
2. **`asan-stack`** — signal + ASan crash/alloc/free frames.
3. **`instruction-pointer`** — signal + fault IP when no frames exist.
4. **`signal-only`** — last resort.

Normalization removes ASLR addresses, absolute build paths, offset suffixes, and
duplicate frames, keeping function + source file + line. Instruction-pointer
signatures are ASLR-sensitive; the method is recorded so a reviewer can judge
grouping quality.

Reproducing inputs are copied (never moved) into
`results/crashes/<signature_hash>/inputs/`, with one JSON record per run and a
`repro_input.bin` for the representative run.

## Results layout

```text
results/
  runs/<run_id>/
    input.bin              # exact bytes used (copied from the seed)
    stdout.txt
    stderr.txt
    run.log
    run_manifest.json      # RunResult (object)
    crash_record.json      # CrashRecord (written after analysis)
    gdb_output.txt         # when GDB evidence was captured
    asan_report.txt        # when ASan evidence was captured
  crashes/<signature_hash>/
    inputs/<sha256-prefix>.bin
    records/<run_id>.json
    repro_input.bin
    group.json
  crashes/groups.json
  report.json              # `crashlab report` default
  report.html              # self-contained
```

`run_id` has the form `YYYYMMDDTHHMMSSffffff_<input-sha12>_<random4>`, so the
timestamp and input hash are visible without opening the manifest.

## Reports

- **JSON** (`results/report.json`): a top-level **array** of `CrashRecord`
  objects, so downstream tooling can iterate without an envelope. See
  [`docs/schema.md`](docs/schema.md) for every field.
- **HTML** (`results/report.html`): one self-contained file. CSS is inline,
  raw evidence is escaped and embedded, and there are no scripts, fonts, images,
  or network references. It contains a summary table and expandable
  `<details>` sections for each crash.

Both writers consume the same records; they cannot drift into different views of
the evidence.

## Correlation with runtime-event logs (runtime core)

Every run and crash record carries:

- `run_id` — unique per execution.
- `timestamp_start` / `timestamp_end` — UTC ISO-8601 with milliseconds.
- `batch_id` — shared by all runs in one CLI invocation.
- `runtime_trace_ref` — a typed join object with `run_id`, the timestamp window,
  `batch_id`, `producer`, `join_keys`, and `schema`.

The target environment receives:

| Variable | Meaning |
|---|---|
| `CRASHLAB_RUN_ID` | Join key for this execution. |
| `CRASHLAB_BATCH_ID` | Present when the run belongs to a batch. |
| `CRASHLAB_TIMESTAMP_START` | Run start timestamp. |
| `CRASHLAB_TIMEOUT_SECONDS` | Configured timeout. |
| `CRASHLAB_INPUT_SHA256` | Hash of the exact input bytes. |

Passing `--preload <abs path>/build/libheapsentry.so` (POSIX) makes crashlab run
the target **under the runtime event logger**. The logger stamps
`CRASHLAB_RUN_ID` and `CRASHLAB_BATCH_ID` onto every emitted event as the
`run_id`/`batch_id` fields (verified by `make check-correlation`), so crash
records join the allocator events they explain. Join on `run_id` when the
runtime logger can stamp it, or on overlapping `[timestamp_start,
timestamp_end]` windows when events are captured out of band. The full
contract is in [`docs/schema.md`](docs/schema.md).

## Configuration

Copy [`crashlab.toml.example`](crashlab.toml.example) to `crashlab.toml` in the
working directory, or pass `--config` explicitly. Precedence is:

```text
explicit CLI flag > TOML config > built-in default
```

Unknown TOML keys are ignored with a warning so newer configs remain readable by
older checkouts. Invalid values raise a clear configuration error (exit code 2).

## Evidence collection

- **GDB** runs in batch mode with a fixed script (`bt full`, registers,
  disassembly near `$pc`, fault address). No interactive session is required.
  `GdbBridge` is an interface; tests use `FakeGdbBridge` and saved output
  fixtures, so no live GDB is needed to validate parsing or analysis.
- **ASan** reports are parsed from stderr or from separately captured files
  (`--asan-dir`, `--asan-log`). The parser extracts error type, access
  type/size, fault address, thread, region, crash stack, allocation stack, and
  free stack.
- Missing tools never abort a run. Evidence is marked unavailable and the
  signature falls back to lower-fidelity methods.

## Platform support and limitations

- POSIX is the primary target; Windows is supported through the NTSTATUS shim.
- `LD_PRELOAD` is recorded on Windows but not applied.
- GDB/ASan execution cannot be validated on hosts without those tools; the test
  suite uses realistic fixtures and mocks instead.
- Instruction-pointer signatures can change with ASLR or binary layout.
- The Windows NTSTATUS table is conservative: unknown statuses are errors, not
  crashes.
- Crashlab does not symbolize binaries, minimize inputs, or score
  exploitability. Those are deliberate manual-review steps.

## Development

```sh
python -m pip install -e ".[dev]"
python -m pytest
```

The suite covers signal classification (POSIX + Windows), runner behavior,
signature normalization/deduplication, ASan and GDB parsing, analysis/promotion,
JSON/HTML report schemas, and full CLI run/analyze/report flows.

## Repository map

| Path | Purpose |
|---|---|
| `preload/` | Runtime-core `LD_PRELOAD` allocator/event hooks (C). |
| `shared/` | Runtime event schema shared by both components. |
| `targets/` | Intentionally vulnerable C demo programs for the runtime core. |
| `docs/runtime-*.md` | Runtime-core architecture, event schema, testing. |
| `src/crashlab/cli.py` | Argument parsing and command orchestration. |
| `src/crashlab/runner.py` | Controlled execution and run-directory persistence. |
| `src/crashlab/signals.py` | Signal/NTSTATUS normalization, environment, teardown. |
| `src/crashlab/analysis.py` | Evidence correlation, classification, grouping. |
| `src/crashlab/signatures.py` | Normalization and signature computation. |
| `src/crashlab/debugger/gdb.py` | Mockable GDB bridge and output parser. |
| `src/crashlab/debugger/asan.py` | AddressSanitizer report parser. |
| `src/crashlab/reports/` | JSON array and self-contained HTML writers. |
| `src/crashlab/models.py` | Shared dataclasses and serialization contract. |
| `docs/schema.md` | Crash record / correlation contract. |
| `examples/` | C crash demo (crashlab) and runtime-core sample events. |
| `corpus/` | Deterministic seed inputs for the crashlab sample targets. |
| `tests/` | Unit, fixture, schema, and CLI end-to-end tests (both components). |

## License

MIT. The sample targets contain deliberate memory-safety bugs and must only be
built and run in an isolated, authorized research environment.
