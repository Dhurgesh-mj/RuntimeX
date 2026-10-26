# On-disk schema and correlation contract

Schema version: **`1.0`**. Schema identifiers:

| Constant | Value | Used by |
|---|---|---|
| `RUN_MANIFEST_SCHEMA` | `crashlab.run_manifest/1.0` | `run_manifest.json` (object) |
| `CRASH_RECORD_SCHEMA` | `crashlab.crash_record/1.0` | `crash_record.json` and each JSON-report element |
| `REPORT_SCHEMA` | `crashlab.report/1.0` | HTML report metadata |

Crashlab is deliberately tolerant on input: unknown fields are ignored and
unknown enum values fall back to conservative defaults. Writers always emit the
full documented shape.

---

## 1. `run_manifest.json`

One JSON object per execution, written atomically to
`results/runs/<run_id>/run_manifest.json`. It is the serialized `RunResult`
dataclass.

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | `crashlab.run_manifest/1.0`. |
| `run_id` | string | `YYYYMMDDTHHMMSSffffff_<input-sha12>_<rand4>`. |
| `status` | enum string | `normal`, `crash`, `timeout`, `error`. |
| `timestamp_start` | string | UTC ISO-8601, milliseconds, `Z` suffix. |
| `timestamp_end` | string | UTC ISO-8601, milliseconds, `Z` suffix. |
| `binary` | string | Binary value from config. |
| `binary_resolved` | string | Absolute path actually launched. |
| `binary_sha256` | string \| null | Hash of the target at run time. |
| `argv` | string[] | Exact argv, including the binary and target args. |
| `input` | object | `InputRef`, see below. |
| `timeout_seconds` | number | Configured wall-clock limit. |
| `duration_ms` | integer | Observed wall-clock duration. |
| `exit_code` | integer \| null | Raw child return code. |
| `signal` | object \| null | `SignalInfo`, see below. |
| `preload` | string \| null | Requested/effective `LD_PRELOAD`. |
| `preload_applied` | boolean | False on Windows. |
| `asan_options` | string \| null | Effective `ASAN_OPTIONS`. |
| `cwd` | string \| null | Child working directory. |
| `command` | string | Copy-pasteable reproduction command with env overrides. |
| `run_dir` | string | Absolute run directory. |
| `stdout_file` / `stderr_file` / `manifest_file` / `log_file` | string | Relative artifact names. |
| `stdout_sha256` / `stderr_sha256` | string \| null | Captured stream hashes. |
| `env_overrides` | object | Only the variables crashlab set. |
| `batch_id` | string \| null | Shared by one CLI invocation. |
| `error` | string \| null | Launch/decoder diagnostics. |
| `host_platform` | string | Host description. |

### `InputRef`

| Field | Type | Notes |
|---|---|---|
| `sha256` | string | Hash of the exact bytes delivered. |
| `size` | integer | Byte length. |
| `mode` | enum string | `stdin`, `file`, or `arg`. |
| `original_path` | string \| null | Seed location, for provenance only. |
| `stored_name` | string | Relative copy name, normally `input.bin`. |

`input.bin` is a byte-for-byte copy. Crashlab never moves or deletes the seed.

### `SignalInfo`

| Field | Type | Notes |
|---|---|---|
| `name` | string | POSIX name, e.g. `SIGSEGV`. |
| `number` | integer \| null | POSIX number. On Windows, a pseudo-number. |
| `description` | string | Human description. |
| `core_dumped` | boolean | POSIX core flag when known. |
| `native_status` | integer \| null | Windows NTSTATUS, e.g. `3221225477` (`0xC0000005`). |
| `platform` | string | `windows` or host platform. |

---

## 2. `crash_record.json`

One JSON object per crashed run, written atomically to
`results/runs/<run_id>/crash_record.json`, and copied into
`results/crashes/<signature_hash>/records/<run_id>.json`. It is the serialized
`CrashRecord` dataclass.

The JSON **report** (`results/report.json`) is a top-level array of these
objects. There is no report envelope; the array is the payload.

### Required fields

These fields are always present (some may be `null`):

`run_id`, `timestamp`, `timestamp_start`, `timestamp_end`, `input`,
`crash_signature`, `signature_hash`, `signature_method`, `classification`,
`vulnerability_class`, `gdb`, `asan`, `runtime_trace_ref`,
`suspected_root_cause`, `confidence`, `reproduction_command`,
`mitigation_notes`.

### Full field list

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | `crashlab.crash_record/1.0`. |
| `run_id` | string | Joins to the run manifest and runtime events. |
| `timestamp` | string | Alias of the run's `timestamp_start`. |
| `timestamp_start` | string | UTC ISO-8601 start of the observed run window. |
| `timestamp_end` | string | UTC ISO-8601 end of the observed run window. |
| `input` | object | `InputRef` from the run. |
| `crash_signature` | string | Human-readable normalized signature. |
| `signature_hash` | string | 16-hex-character SHA-256 prefix; grouping key. |
| `signature_method` | string | `gdb`, `asan-stack`, `instruction-pointer`, or `signal-only`. |
| `classification` | enum string | `crash` or `confirmed_vulnerability`. |
| `vulnerability_class` | enum string | Normalized class, see taxonomy below. |
| `gdb` | object | `GdbFindings`, never null; use `available=false`. |
| `asan` | object \| null | `AsanFinding` when an ASan report explained the crash. |
| `runtime_trace_ref` | object \| null | Typed join object, see §4. |
| `signal` | object \| null | `SignalInfo`; null for fatal sanitizer exit without a signal. |
| `exit_code` | integer \| null | Raw child return code. |
| `duration_ms` | integer \| null | Run duration. |
| `confidence` | enum string | `low`, `medium`, `high`. |
| `reproduction_command` | string | Exact invocation including environment overrides. |
| `suspected_root_cause` | string | Evidence-based narrative; may say "not confirmed". |
| `mitigation_notes` | string | Defensive remediation guidance. |
| `triage_summary` | string | Multi-line manual-review summary. |
| `evidence_sources` | string[] | Subset of `signal`, `exit-status`, `asan`, `glibc`, `gdb`. |
| `batch_id` | string \| null | Shared batch identifier. |
| `run_dir` | string \| null | Run directory containing the preserved input. |

### `Classification` semantics

| Value | Meaning |
|---|---|
| `crash` | Abnormal termination observed; **not** promoted. Includes bare signals, ASan `SEGV`, and GDB-only null dereferences. |
| `confirmed_vulnerability` | Concrete sanitizer class or unambiguous glibc allocator diagnosis named the defect. |

Never infer `confirmed_vulnerability` from a signal alone.

### `VulnerabilityClass` taxonomy

`heap-buffer-overflow`, `stack-buffer-overflow`, `global-buffer-overflow`,
`buffer-overflow`, `container-overflow`, `use-after-free`, `use-after-return`,
`use-after-scope`, `double-free`, `invalid-free`, `heap-corruption`,
`stack-overflow`, `null-pointer-dereference`, `arithmetic-error`,
`illegal-instruction`, `unknown`.

Classes that confirm a vulnerability: all overflow classes, all
use-after-* classes, `double-free`, `invalid-free`, `stack-overflow`, and
glibc-reported `heap-corruption`. `null-pointer-dereference`,
`arithmetic-error`, `illegal-instruction`, and `unknown` do **not** confirm on
their own.

### `GdbFindings`

| Field | Type | Notes |
|---|---|---|
| `available` | boolean | Whether a usable GDB bridge ran. |
| `crashed` | boolean | GDB observed a terminating signal. |
| `signal_name` | string \| null | e.g. `SIGSEGV`. |
| `signal_number` | integer \| null | POSIX number. |
| `fault_address` | string \| null | Hex string from `$_siginfo...si_addr`. |
| `fault_instruction` | string \| null | Faulting disassembly line. |
| `pc` | string \| null | Program counter at the fault. |
| `backtrace` | `StackFrame[]` | Innermost first. |
| `registers` | object | Lower-case register name → hex string. |
| `disassembly` | string[] | Lines near `$pc`. |
| `raw_output_path` | string \| null | Saved `gdb_output.txt`. |
| `error` | string \| null | Timeout/unavailable/parse diagnostics. |
| `gdb_path` | string \| null | Configured executable. |
| `exit_code` | integer \| null | GDB process exit code. |

Raw GDB text is persisted to `gdb_output.txt`; the in-memory `raw_output` field
is not serialized after persistence.

### `AsanFinding`

| Field | Type | Notes |
|---|---|---|
| `available` | boolean | Report was parsed. |
| `sanitizer` | string | Usually `AddressSanitizer`. |
| `error_type` | string | e.g. `heap-buffer-overflow`, `SEGV`. |
| `vulnerability_class` | enum string | Normalized taxonomy value. |
| `access_type` | string \| null | `read` or `write`. |
| `access_size` | integer \| null | Bytes accessed, when reported. |
| `fault_address` | string \| null | Hex address from the report. |
| `thread_id` | integer \| null | ASan thread (`T0` → `0`). |
| `pc` | string \| null | Faulting program counter. |
| `region` | string \| null | Region description text. |
| `region_size` | integer \| null | Region size in bytes. |
| `crash_stack` | `StackFrame[]` | Access/crash stack. |
| `alloc_stack` | `StackFrame[]` | Allocation stack. |
| `free_stack` | `StackFrame[]` | Free stack. |
| `summary` | string \| null | Raw `SUMMARY:` line. |
| `raw_output_path` | string \| null | Saved `asan_report.txt`. |

### `StackFrame`

| Field | Type | Notes |
|---|---|---|
| `index` | integer | Frame number from the source report. |
| `function` | string | `??` when unknown. |
| `address` | string \| null | Absolute address (excluded from signatures). |
| `file` | string \| null | Source path as reported. |
| `line` / `column` | integer \| null | Source location. |
| `offset` | integer \| null | Optional symbol offset. |
| `module` | string \| null | Shared library / module. |
| `args` | string \| null | Arguments text, when parsed. |
| `raw` | string \| null | Original line. |

---

## 3. Signatures, groups, and preserved inputs

Signature normalization:

1. Normalize function names (drop argument lists and `+0x..`/`+N` offsets).
2. Prefer `file:line`; otherwise `function @ <module>`.
3. Remove absolute path prefixes from source files and modules.
4. Remove ASLR-sensitive addresses.
5. Deduplicate frames while preserving order.
6. Keep the top N (default 5) frames.

`signature_method` records the evidence used. `instruction-pointer` and
`signal-only` are lower-fidelity fallbacks.

`results/crashes/<signature_hash>/group.json` is an object:

```json
{
  "generated_at": "2026-01-01T00:00:02.000Z",
  "signature_hash": "0123456789abcdef",
  "crash_signature": "SIGSEGV | heap_overflow @ target_demo.c:39 > main @ target_demo.c:112",
  "classification": "confirmed_vulnerability",
  "vulnerability_class": "heap-buffer-overflow",
  "confidence": "high",
  "record_count": 2,
  "unique_inputs": 2,
  "input_hashes": ["...", "..."],
  "representative_run_id": "...",
  "records": ["...", "..."]
}
```

`results/crashes/groups.json` is an index object:

```json
{
  "generated_at": "2026-01-01T00:00:02.000Z",
  "schema_version": "crashlab.crash_record/1.0",
  "groups": [
    {
      "signature_hash": "...",
      "crash_signature": "...",
      "classification": "crash",
      "vulnerability_class": "unknown",
      "confidence": "low",
      "record_count": 1,
      "unique_inputs": 1,
      "run_ids": ["..."]
    }
  ]
}
```

Preserved inputs are copies: `inputs/<sha256-prefix>.bin` plus
`repro_input.bin` for the representative record.

---

## 4. Correlation contract (Person 1)

### Keys emitted by crashlab

| Key | Location | Meaning |
|---|---|---|
| `run_id` | run manifest, crash record, `runtime_trace_ref` | Primary join key. |
| `timestamp_start` / `timestamp_end` | run manifest, crash record, `runtime_trace_ref` | UTC half-open wall-clock window. |
| `batch_id` | both, when batched | Groups runs from one CLI invocation. |
| `runtime_trace_ref` | crash record | Typed placeholder for the runtime log. |

`RuntimeTraceRef` fields:

| Field | Type | Notes |
|---|---|---|
| `run_id` | string | Same value as the crash record. |
| `timestamp_start` | string | UTC ISO-8601. |
| `timestamp_end` | string | UTC ISO-8601. |
| `batch_id` | string \| null | Same value as the run. |
| `log_path` | string \| null | Reserved for a future attached log. |
| `producer` | string | Defaults to `person1-runtime-events`. |
| `join_keys` | string[] | Defaults to `["run_id", "timestamp_window"]`. |
| `schema` | string | Defaults to `runtime-event-log/v1`. |

### Environment variables visible to the target

| Variable | Notes |
|---|---|
| `CRASHLAB_RUN_ID` | Always set. |
| `CRASHLAB_BATCH_ID` | Set for batched runs. |
| `CRASHLAB_TIMESTAMP_START` | Matches `timestamp_start`. |
| `CRASHLAB_TIMEOUT_SECONDS` | Configured timeout. |
| `CRASHLAB_INPUT_SHA256` | Matches `input.sha256`. |

Only these crashlab-set values appear in `env_overrides`; inherited environment
variables are not recorded.

### Join algorithm

1. Prefer an exact `run_id` join.
2. If the runtime logger could not read the environment, select events whose
   timestamps overlap `[timestamp_start, timestamp_end]` and, when available,
   match `input.sha256` or `batch_id`.
3. Treat a timestamp-only match as lower confidence; record ids are authoritative.

A runtime event envelope compatible with this contract:

```json
{
  "run_id": "20260101T000000000000_deadbeefcafe_abcd",
  "batch_id": "batch_20260101T000000_abcdef",
  "timestamp": "2026-01-01T00:00:00.500Z",
  "event": "heap-write",
  "details": {}
}
```

---

## 5. Report formats

### JSON

`results/report.json` is exactly:

```json
[
  { "schema_version": "crashlab.crash_record/1.0", "run_id": "...", "...": "..." },
  { "schema_version": "crashlab.crash_record/1.0", "run_id": "...", "...": "..." }
]
```

- UTF-8, two-space indentation by default, trailing newline.
- No envelope, so tools can stream the array directly.
- Records are written in the order supplied by the CLI (normally timestamp order).

### HTML

`results/report.html` is a single self-contained document:

- Inline `<style>`; no external fonts, images, scripts, or network URLs.
- A summary table with one row per signature.
- One expandable `<details>` card per record, opened on the first record.
- Escaped raw ASan/GDB evidence (embedded up to 200,000 characters per file).
- Overview counters (`crash records`, `unique signatures`, `confirmed`,
  `unconfirmed`, `unique inputs`, `high confidence`).
- The same `CrashRecord` data used by the JSON writer.

---

## 6. Compatibility rules

- Adding optional fields is backward compatible.
- Readers ignore unknown object keys.
- Unknown enum values map to `classification=crash`,
  `vulnerability_class=unknown`, `confidence=low`, or `status=error`.
- A missing `signal` is valid: fatal sanitizer exits may have no signal.
- Legacy records without `timestamp_start`/`timestamp_end` are normalized to
  `timestamp` when loaded.
- `gdb.available=false` is normal when GDB is absent; it is not an error record.
- Do not infer exploitability from `classification` alone. Read `gdb`, `asan`,
  `evidence_sources`, and `triage_summary`.
