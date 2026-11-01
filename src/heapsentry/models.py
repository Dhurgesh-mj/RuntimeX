"""Data model dataclasses for HeapSentry."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"   # heap_buffer_overflow, double_free
    HIGH     = "high"       # use_after_free_write
    MEDIUM   = "medium"     # memory_leak (confirmed)
    INFO     = "info"       # informational


class BugClass(str, Enum):
    HEAP_BUFFER_OVERFLOW = "heap_buffer_overflow"
    DOUBLE_FREE          = "double_free"
    USE_AFTER_FREE_WRITE = "use_after_free_write"
    MEMORY_LEAK          = "memory_leak"
    CRASH                = "crash"       # crash without specific bug class
    CLEAN                = "clean"       # no bugs found


@dataclass
class AllocationEvent:
    event_id: int
    event: str
    allocation_id: int | None
    old_allocation_id: int | None
    address: str | None
    size: int | None
    status: str
    timestamp_ns: int
    thread_id: int
    process_id: int
    overflow_side: str | None = None
    original_alloc_id: int | None = None
    user_size: int | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class Finding:
    bug_class: BugClass
    severity: Severity
    address: str | None
    allocation_id: int | None
    size: int | None
    description: str
    event_id: int | None = None
    overflow_side: str | None = None
    evidence: dict = field(default_factory=dict)


@dataclass
class CrashInfo:
    exit_code: int
    signal_name: str | None
    signal_number: int | None
    backtrace: str | None
    asan_output: str | None
    stderr_text: str
    stdout_text: str


@dataclass
class ScanResult:
    run_id: str
    binary: str
    input_path: str | None
    timestamp_start: str
    timestamp_end: str
    crashed: bool
    timed_out: bool
    exit_code: int
    crash_info: CrashInfo | None
    events: list[AllocationEvent]
    findings: list[Finding]
    event_log_path: str | None
    out_dir: str
