"""Shared data model for runs, evidence, and crash records.

The central rule of this project is that JSON and HTML reports are generated
from the *same* objects defined here. If a field is not on
:class:`CrashRecord`, it does not belong in either report format.

Correlation contract (consumed later by Person 1's runtime-event logging):

* every :class:`RunResult` and :class:`CrashRecord` carries ``run_id``;
* every record exposes a half-open wall-clock window
  ``timestamp_start`` / ``timestamp_end`` in UTC ISO-8601;
* :class:`CrashRecord` embeds a :class:`RuntimeTraceRef` placeholder with the
  same keys, so a join can happen later without rewriting crash data.

See ``docs/schema.md`` for the full on-disk contract.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping

SCHEMA_VERSION = "1.0"
RUN_MANIFEST_SCHEMA = f"crashlab.run_manifest/{SCHEMA_VERSION}"
CRASH_RECORD_SCHEMA = f"crashlab.crash_record/{SCHEMA_VERSION}"
REPORT_SCHEMA = f"crashlab.report/{SCHEMA_VERSION}"

#: Fields every serialized CrashRecord is guaranteed to contain.
REQUIRED_CRASH_RECORD_FIELDS = (
    "schema_version",
    "run_id",
    "timestamp",
    "timestamp_start",
    "timestamp_end",
    "input",
    "crash_signature",
    "classification",
    "vulnerability_class",
    "gdb",
    "asan",
    "runtime_trace_ref",
    "suspected_root_cause",
    "confidence",
    "reproduction_command",
    "mitigation_notes",
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class RunStatus(str, Enum):
    """Termination outcome observed by the runner."""

    NORMAL = "normal"
    CRASH = "crash"
    TIMEOUT = "timeout"
    ERROR = "error"  # infrastructure/launch failure, not a target crash


class Classification(str, Enum):
    """Evidence-backed classification of an observed crash.

    ``CRASH`` means "abnormal termination observed, not promoted". A crash is
    only promoted to ``CONFIRMED_VULNERABILITY`` when ASan or corroborating
    allocator/debugger evidence names a concrete memory-safety class.
    """

    CRASH = "crash"
    CONFIRMED_VULNERABILITY = "confirmed_vulnerability"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class InputMode(str, Enum):
    """How the test input is delivered to the target."""

    STDIN = "stdin"
    FILE = "file"
    ARG = "arg"


class VulnerabilityClass(str, Enum):
    """Normalized vulnerability taxonomy shared by ASan and reports."""

    HEAP_BUFFER_OVERFLOW = "heap-buffer-overflow"
    STACK_BUFFER_OVERFLOW = "stack-buffer-overflow"
    GLOBAL_BUFFER_OVERFLOW = "global-buffer-overflow"
    BUFFER_OVERFLOW = "buffer-overflow"
    CONTAINER_OVERFLOW = "container-overflow"
    USE_AFTER_FREE = "use-after-free"
    USE_AFTER_RETURN = "use-after-return"
    USE_AFTER_SCOPE = "use-after-scope"
    DOUBLE_FREE = "double-free"
    INVALID_FREE = "invalid-free"
    HEAP_CORRUPTION = "heap-corruption"
    STACK_OVERFLOW = "stack-overflow"
    NULL_POINTER_DEREFERENCE = "null-pointer-dereference"
    ARITHMETIC_ERROR = "arithmetic-error"
    ILLEGAL_INSTRUCTION = "illegal-instruction"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp with millisecond precision."""

    return datetime_to_iso(utc_now())


def datetime_to_iso(value: datetime) -> str:
    """Render a datetime as ``YYYY-MM-DDTHH:MM:SS.mmmZ`` in UTC."""

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def iso_to_datetime(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, accepting a trailing ``Z``."""

    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def sha256_bytes(data: bytes) -> str:
    """Hex SHA-256 of ``data``."""

    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | os.PathLike[str], chunk_size: int = 1024 * 1024) -> str:
    """Hex SHA-256 of a file, read incrementally."""

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def to_jsonable(value: Any) -> Any:
    """Recursively convert models/enums/paths to JSON-native values."""

    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {key: to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return datetime_to_iso(value)
    return value


def _known_fields(cls: type) -> set[str]:
    return {item.name for item in fields(cls)}


def _enum_or(default: Any, enum_type: type[Enum], value: Any) -> Any:
    if value is None:
        return default
    try:
        return enum_type(value)
    except ValueError:
        return default


class JsonModel:
    """Mixin adding deterministic JSON serialization to dataclasses."""

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe dict (enums become strings, paths become str)."""

        return to_jsonable(self)

    def to_json(self, *, indent: int | None = 2) -> str:
        """Return a UTF-8 JSON string."""

        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Evidence / supporting models
# ---------------------------------------------------------------------------


@dataclass
class SignalInfo(JsonModel):
    """Normalized description of a terminating signal.

    On POSIX ``number`` is the real signal number. On Windows, where there is
    no signal concept for crashed processes, ``number`` is the POSIX pseudo
    number used for classification and ``native_status`` holds the NTSTATUS
    value (e.g. ``0xC0000005`` for an access violation).
    """

    name: str
    number: int | None = None
    description: str = ""
    core_dumped: bool = False
    native_status: int | None = None
    platform: str = ""

    @property
    def label(self) -> str:
        """Human label such as ``SIGSEGV (11)``."""

        if self.number is None:
            return self.name
        return f"{self.name} ({self.number})"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> SignalInfo | None:
        if not data:
            return None
        allowed = _known_fields(cls)
        return cls(**{key: value for key, value in data.items() if key in allowed})


@dataclass
class InputRef(JsonModel):
    """Reference to the exact bytes used for a run.

    ``stored_name`` is relative to the run directory and always points at the
    byte-for-byte copy written by the runner. ``original_path`` records where
    the seed came from. Inputs are copied, never moved.
    """

    sha256: str
    size: int
    mode: InputMode = InputMode.STDIN
    original_path: str | None = None
    stored_name: str = "input.bin"

    def stored_path(self, run_dir: str | os.PathLike[str]) -> Path:
        """Resolve the preserved input copy inside ``run_dir``."""

        return Path(run_dir) / self.stored_name

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> InputRef:
        return cls(
            sha256=str(data.get("sha256", "")),
            size=int(data.get("size", 0)),
            mode=_enum_or(InputMode.STDIN, InputMode, data.get("mode")),
            original_path=data.get("original_path"),
            stored_name=str(data.get("stored_name", "input.bin")),
        )


@dataclass
class StackFrame(JsonModel):
    """One normalized stack frame from GDB or a sanitizer report."""

    index: int
    function: str = "??"
    address: str | None = None
    file: str | None = None
    line: int | None = None
    column: int | None = None
    offset: int | None = None
    module: str | None = None
    args: str | None = None
    raw: str | None = None

    @property
    def location(self) -> str:
        """Return ``file:line`` when known, otherwise the module name."""

        if self.file and self.line:
            return f"{self.file}:{self.line}"
        if self.file:
            return self.file
        return self.module or ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StackFrame:
        allowed = _known_fields(cls)
        return cls(**{key: value for key, value in data.items() if key in allowed})


@dataclass
class GdbFindings(JsonModel):
    """Structured output of a scripted GDB batch session."""

    available: bool = False
    crashed: bool = False
    signal_name: str | None = None
    signal_number: int | None = None
    fault_address: str | None = None
    fault_instruction: str | None = None
    pc: str | None = None
    backtrace: list[StackFrame] = field(default_factory=list)
    registers: dict[str, str] = field(default_factory=dict)
    disassembly: list[str] = field(default_factory=list)
    raw_output_path: str | None = None
    error: str | None = None
    gdb_path: str | None = None
    exit_code: int | None = None
    #: Populated by the bridge, cleared by the analyzer after it is persisted.
    raw_output: str | None = field(default=None, repr=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> GdbFindings:
        if not data:
            return cls()
        values = {key: value for key, value in data.items() if key in _known_fields(cls)}
        values["backtrace"] = [
            StackFrame.from_dict(item) for item in data.get("backtrace", [])
        ]
        values["registers"] = {
            str(key): str(value) for key, value in data.get("registers", {}).items()
        }
        return cls(**values)


@dataclass
class AsanFinding(JsonModel):
    """Structured subset of an AddressSanitizer report."""

    available: bool = True
    sanitizer: str = "AddressSanitizer"
    error_type: str = "unknown"
    vulnerability_class: VulnerabilityClass = VulnerabilityClass.UNKNOWN
    access_type: str | None = None
    access_size: int | None = None
    fault_address: str | None = None
    thread_id: int | None = None
    pc: str | None = None
    region: str | None = None
    region_size: int | None = None
    crash_stack: list[StackFrame] = field(default_factory=list)
    alloc_stack: list[StackFrame] = field(default_factory=list)
    free_stack: list[StackFrame] = field(default_factory=list)
    summary: str | None = None
    raw_output_path: str | None = None

    @property
    def is_specific(self) -> bool:
        """True when the sanitizer named a concrete memory-safety class."""

        return self.vulnerability_class not in {
            VulnerabilityClass.UNKNOWN,
            VulnerabilityClass.NULL_POINTER_DEREFERENCE,
            VulnerabilityClass.ARITHMETIC_ERROR,
            VulnerabilityClass.ILLEGAL_INSTRUCTION,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> AsanFinding | None:
        if not data:
            return None
        values = {key: value for key, value in data.items() if key in _known_fields(cls)}
        values["vulnerability_class"] = _enum_or(
            VulnerabilityClass.UNKNOWN,
            VulnerabilityClass,
            data.get("vulnerability_class"),
        )
        for key in ("crash_stack", "alloc_stack", "free_stack"):
            values[key] = [StackFrame.from_dict(item) for item in data.get(key, [])]
        return cls(**values)


@dataclass
class RuntimeTraceRef(JsonModel):
    """Placeholder join key for Person 1's runtime-event logs.

    Person 1 should emit event records keyed by ``run_id`` (or, if events are
    collected out-of-band, by a window overlapping
    ``timestamp_start``/``timestamp_end``). Crashlab sets the environment
    variables ``CRASHLAB_RUN_ID`` and ``CRASHLAB_BATCH_ID`` for the target so
    instrumented runtimes can stamp the same identifiers.
    """

    run_id: str
    timestamp_start: str
    timestamp_end: str
    batch_id: str | None = None
    log_path: str | None = None
    producer: str = "person1-runtime-events"
    join_keys: list[str] = field(default_factory=lambda: ["run_id", "timestamp_window"])
    schema: str = "runtime-event-log/v1"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> RuntimeTraceRef | None:
        if not data:
            return None
        allowed = _known_fields(cls)
        return cls(**{key: value for key, value in data.items() if key in allowed})


# ---------------------------------------------------------------------------
# Run and crash records
# ---------------------------------------------------------------------------


@dataclass
class RunResult(JsonModel):
    """Everything observed and recorded for one execution of a target."""

    run_id: str
    status: RunStatus
    timestamp_start: str
    timestamp_end: str
    binary: str
    input: InputRef
    timeout_seconds: float
    duration_ms: int
    argv: list[str] = field(default_factory=list)
    exit_code: int | None = None
    signal: SignalInfo | None = None
    binary_resolved: str = ""
    binary_sha256: str | None = None
    preload: str | None = None
    preload_applied: bool = False
    asan_options: str | None = None
    cwd: str | None = None
    command: str = ""
    run_dir: str = ""
    stdout_file: str = "stdout.txt"
    stderr_file: str = "stderr.txt"
    manifest_file: str = "run_manifest.json"
    log_file: str = "run.log"
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    env_overrides: dict[str, str] = field(default_factory=dict)
    batch_id: str | None = None
    error: str | None = None
    host_platform: str = ""
    schema_version: str = RUN_MANIFEST_SCHEMA

    @property
    def timestamp(self) -> str:
        """Alias used by correlation tooling."""

        return self.timestamp_start

    def input_path(self) -> Path:
        """Path to the preserved input copy."""

        return self.input.stored_path(self.run_dir)

    def stdout_path(self) -> Path:
        return Path(self.run_dir) / self.stdout_file

    def stderr_path(self) -> Path:
        return Path(self.run_dir) / self.stderr_file

    def argv_without_binary(self) -> list[str]:
        return list(self.argv[1:]) if self.argv else []

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RunResult:
        """Load a run manifest. Unknown/missing optional fields are tolerated."""

        values = {key: value for key, value in data.items() if key in _known_fields(cls)}
        values["status"] = _enum_or(RunStatus.ERROR, RunStatus, data.get("status"))
        values["input"] = InputRef.from_dict(data.get("input", {}))
        values["signal"] = SignalInfo.from_dict(data.get("signal"))
        values["argv"] = [str(item) for item in data.get("argv", [])]
        values["env_overrides"] = {
            str(key): str(value) for key, value in data.get("env_overrides", {}).items()
        }
        values.setdefault("schema_version", RUN_MANIFEST_SCHEMA)
        return cls(**values)


@dataclass
class CrashRecord(JsonModel):
    """One crash plus all evidence needed for manual exploitability triage.

    This is the sole input to JSON and HTML rendering. ``classification`` is
    conservative: bare signals remain ``CRASH`` unless ASan (or a clearly
    diagnostic allocator report) names a memory-safety class.
    """

    run_id: str
    timestamp: str
    input: InputRef
    crash_signature: str
    signature_hash: str
    signature_method: str
    classification: Classification
    vulnerability_class: VulnerabilityClass
    gdb: GdbFindings
    confidence: Confidence
    reproduction_command: str
    suspected_root_cause: str
    mitigation_notes: str
    asan: AsanFinding | None = None
    runtime_trace_ref: RuntimeTraceRef | None = None
    signal: SignalInfo | None = None
    exit_code: int | None = None
    duration_ms: int | None = None
    triage_summary: str = ""
    evidence_sources: list[str] = field(default_factory=list)
    batch_id: str | None = None
    run_dir: str | None = None
    #: Wall-clock window for correlation. ``timestamp`` aliases the start.
    timestamp_start: str | None = None
    timestamp_end: str | None = None
    schema_version: str = CRASH_RECORD_SCHEMA

    @property
    def is_confirmed(self) -> bool:
        return self.classification is Classification.CONFIRMED_VULNERABILITY

    def __post_init__(self) -> None:
        """Keep the correlation window populated for legacy records."""

        if self.timestamp_start is None:
            self.timestamp_start = self.timestamp
        if self.timestamp_end is None:
            self.timestamp_end = self.timestamp

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CrashRecord:
        values = {key: value for key, value in data.items() if key in _known_fields(cls)}
        values["input"] = InputRef.from_dict(data.get("input", {}))
        values["classification"] = _enum_or(
            Classification.CRASH, Classification, data.get("classification")
        )
        values["vulnerability_class"] = _enum_or(
            VulnerabilityClass.UNKNOWN,
            VulnerabilityClass,
            data.get("vulnerability_class"),
        )
        values["confidence"] = _enum_or(Confidence.LOW, Confidence, data.get("confidence"))
        values["gdb"] = GdbFindings.from_dict(data.get("gdb"))
        values["asan"] = AsanFinding.from_dict(data.get("asan"))
        values["signal"] = SignalInfo.from_dict(data.get("signal"))
        values["runtime_trace_ref"] = RuntimeTraceRef.from_dict(
            data.get("runtime_trace_ref")
        )
        values["evidence_sources"] = [
            str(item) for item in data.get("evidence_sources", [])
        ]
        values.setdefault("schema_version", CRASH_RECORD_SCHEMA)
        return cls(**values)


@dataclass
class CrashGroup(JsonModel):
    """Crashes sharing a normalized signature."""

    signature_hash: str
    crash_signature: str
    records: list[CrashRecord] = field(default_factory=list)

    @property
    def classification(self) -> Classification:
        return self.records[0].classification if self.records else Classification.CRASH

    @property
    def vulnerability_class(self) -> VulnerabilityClass:
        return (
            self.records[0].vulnerability_class
            if self.records
            else VulnerabilityClass.UNKNOWN
        )

    @property
    def confidence(self) -> Confidence:
        return self.records[0].confidence if self.records else Confidence.LOW

    @property
    def input_hashes(self) -> list[str]:
        seen: set[str] = set()
        for record in self.records:
            seen.add(record.input.sha256)
        return sorted(seen)

    @property
    def representative(self) -> CrashRecord:
        """Prefer a confirmed/high-confidence record, else the first one."""

        for record in self.records:
            if record.is_confirmed:
                return record
        return self.records[0]

    def summary_dict(self) -> dict[str, Any]:
        return {
            "signature_hash": self.signature_hash,
            "crash_signature": self.crash_signature,
            "classification": self.classification.value,
            "vulnerability_class": self.vulnerability_class.value,
            "confidence": self.confidence.value,
            "record_count": len(self.records),
            "unique_inputs": len(self.input_hashes),
            "run_ids": [record.run_id for record in self.records],
        }


@dataclass
class ReportConfig(JsonModel):
    """Rendering options shared by the JSON and HTML writers."""

    title: str = "Crashlab crash report"
    subtitle: str = "Automated crash triage for manual exploitability review"
    generated_at: str = field(default_factory=utc_now_iso)
    include_raw_evidence: bool = True
    schema_version: str = REPORT_SCHEMA


def group_by_signature(records: Iterable[CrashRecord]) -> list[CrashGroup]:
    """Group records by ``signature_hash`` and sort by severity/count.

    Confirmed groups come first, then higher confidence, then larger groups,
    then signature hash for deterministic output.
    """

    groups: dict[str, CrashGroup] = {}
    for record in records:
        group = groups.get(record.signature_hash)
        if group is None:
            group = CrashGroup(
                signature_hash=record.signature_hash,
                crash_signature=record.crash_signature,
            )
            groups[record.signature_hash] = group
        group.records.append(record)

    confirmed_rank = {
        Classification.CONFIRMED_VULNERABILITY: 0,
        Classification.CRASH: 1,
    }
    confidence_rank = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}

    return sorted(
        groups.values(),
        key=lambda group: (
            confirmed_rank[group.classification],
            confidence_rank[group.confidence],
            -len(group.records),
            group.signature_hash,
        ),
    )
