# RuntimeX JSONL event schema — version 1

Machine contract: `shared/event_schema.json` (JSON Schema Draft 2020-12).
This page is the human-readable definition. **Schema version: 1.**
This is the integration contract with Person 2. Any change bumps the
version and updates `event_logger.c` and the tests.

## Record layout

Every line of an event log is one JSON object. All records carry:

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | integer (constant 1) | Contract version |
| `event_id` | integer ≥ 0 | Emission-order sequence number, unique per process run, starts at 0, strictly increasing (gapless while no events are dropped) |
| `event` | string | One of: `allocation`, `deallocation`, `reallocation`, `initialization`, `logger_error` |
| `allocation_id` | integer ≥ 1 or null | Identity of the allocation the event is about |
| `old_allocation_id` | integer ≥ 1 or null | Only for `reallocation` |
| `size` | integer ≥ 0 | Requested size (allocation, reallocation; also 0 in the zero-size-realloc case) |
| `old_size` | integer ≥ 0 or null | Tracked size before free/realloc; null when untracked |
| `message` | string | Only for `logger_error` |
| `timestamp_ns` | integer | `CLOCK_MONOTONIC` reading (ns). Not wall-clock time |
| `process_id` | integer ≥ 1 | `getpid()` |
| `thread_id` | integer ≥ 1 | `gettid()` of the executing thread |
| `status` | string | `ok`, `failed`, or `untracked` |

Fields not meaningful for an event type are omitted by the runtime and
must be treated as unknown by consumers.

## Event types and status semantics

### `initialization` (event_id 0)
- `status:"ok"` — symbols resolved **and** log opened.
- `status:"failed"` — resolution or open failed; instrumentation is
  degraded (bootstrap arena fallback / events dropped).
- `allocation_id` is always null.

### `allocation`
- `status:"ok"`, `allocation_id` set, `size` = requested size. Emitted after
  each successful `malloc(n)` (incl. `realloc(NULL,n)`).
- `status:"failed"`, `allocation_id: null`, `size` = requested. Emitted for
  failed `malloc`. Interpreter: *the allocation failed*; no id exists.

### `deallocation`
- `status:"ok"`, `allocation_id` = freed identity, `old_size` = tracked
  size. Emitted for each successful `free(p)` of a tracked pointer.
- `status:"untracked"`, `allocation_id: null`. Emitted when freeing a
  pointer whose identity is unknown: untracked pointer, tracker
  exhaustion, or a bootstrap-arena chunk. The real `free()` was called
  (except bootstrap chunks); RuntimeX just cannot attribute identity.

### `reallocation`
- `status:"ok"`, `allocation_id` = **new id**, `old_allocation_id` = old id,
  `old_size` = old tracked size (null if untracked), `size` = new requested
  size. The new id **supersedes** the old one even when the returned
  address is unchanged. The old id is never minted again in this run.
- `status:"ok"`, `allocation_id: null`, `size: 0` — glibc zero-size
  realloc: the old block was freed and `NULL` returned.
- `status:"failed"`, `allocation_id: null`, `old_allocation_id` = old id,
  `old_size` = old size — the **original allocation is preserved** and
  continues to be identified by `old_allocation_id`.
- `status:"failed"` or `"untracked"` with `allocation_id: null` and
  `old_allocation_id: null` — failed/untracked realloc where identity is
  unavailable.

### `logger_error`
- `status:"failed"`, `allocation_id: null`, `message` describes the logging
  failure (open failure at init or first write failure). At most one such
  event is attempted per run.

## Allocation identity rules

1. Ids are minted **per run**, strictly increasing, starting at 1.
2. Exactly one id per successful allocating operation; never reused.
3. Address reuse after `free()` is expected and yields a **new** id.
4. `id 0` is the "unknown" representation (JSON `null`).
5. A deallocation id always referred to an earlier successful
   allocation/reallocation in the same log — the bundled validator checks
   this (`tests/test_event_schema.py`).

## Ordering and uniqueness guarantees (verified)

- `event_id` is unique and strictly increasing per file.
- Ordering reflects the **emission order under the logger lock**, which is
  close to but not guaranteed identical to cross-thread call order.
- `free(p)`'s deallocation event is emitted after `free` ran, i.e. after
  the real allocator already released the memory; the still-valid
  metadata was captured before.
- Events are never partially written: any line that was not completely
  written is not present (the write path either completes a line or the
  logger enters the failed state; later events are unlogged, counted).

## Error conditions and dropped events

- If the logger cannot open the file, events are dropped and unrecordable
  (process exit status is unaffected). `runtimex_dropped_events()` exposes
  the counter for tests.
- A `logger_error` event may itself fail to be written; then the log shows
  nothing and consumers must treat missing logs/unfinished runs as
  incomplete evidence.
- `status:"failed"` in allocator events never reflects logging trouble and
  vice versa; the two failure domains are disjoint.

## Example records (real output)

```jsonl
{"schema_version":1,"event_id":0,"event":"initialization","allocation_id":null,"timestamp_ns":100265973000,"process_id":1000001,"thread_id":1000001,"status":"ok"}
{"schema_version":1,"event_id":1,"event":"allocation","allocation_id":1,"size":64,"timestamp_ns":100265987234,"process_id":1000001,"thread_id":1000001,"status":"ok"}
{"schema_version":1,"event_id":2,"event":"reallocation","allocation_id":2,"old_allocation_id":1,"size":256,"old_size":64,"timestamp_ns":100267759720,"process_id":1000001,"thread_id":1000001,"status":"ok"}
{"schema_version":1,"event_id":3,"event":"deallocation","allocation_id":2,"old_size":256,"timestamp_ns":100267768393,"process_id":1000001,"thread_id":1000001,"status":"ok"}
```
(A full, unmodified sample produced by a real run is checked in at
`examples/sample-events.jsonl`.)
