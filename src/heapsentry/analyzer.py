"""Analyze parsed events and crash info to produce Finding objects."""

from collections import defaultdict

from heapsentry.models import (
    AllocationEvent,
    BugClass,
    CrashInfo,
    Finding,
    Severity,
)
from heapsentry.events import filter_by_type, group_by_allocation


def analyze(events: list[AllocationEvent], crash: CrashInfo | None) -> list[Finding]:
    """
    Extract findings from events and optional crash info.

    Priority order:
    1. heap_buffer_overflow → CRITICAL
    2. double_free          → CRITICAL
    3. use_after_free_write → HIGH
    4. memory_leak          → MEDIUM
    5. Crashed with no specific vuln → CRASH finding → HIGH
    6. Completely clean     → CLEAN finding → INFO
    """
    findings: list[Finding] = []

    # ---- 1. Heap buffer overflows ----------------------------------------
    for ev in filter_by_type(events, "heap_buffer_overflow"):
        side = ev.overflow_side or "unknown"
        sz = ev.user_size or ev.size
        desc = (
            f"Heap buffer overflow detected on the {side} side of allocation "
            f"#{ev.allocation_id} (user size {sz} bytes) at {ev.address}."
        )
        findings.append(Finding(
            bug_class=BugClass.HEAP_BUFFER_OVERFLOW,
            severity=Severity.CRITICAL,
            address=ev.address,
            allocation_id=ev.allocation_id,
            size=sz,
            description=desc,
            event_id=ev.event_id,
            overflow_side=side,
            evidence=_event_evidence(ev),
        ))

    # ---- 2. Double frees --------------------------------------------------
    for ev in filter_by_type(events, "double_free"):
        desc = (
            f"Double-free of address {ev.address} (original alloc #{ev.original_alloc_id}, "
            f"event #{ev.event_id})."
        )
        findings.append(Finding(
            bug_class=BugClass.DOUBLE_FREE,
            severity=Severity.CRITICAL,
            address=ev.address,
            allocation_id=ev.allocation_id,
            size=ev.size,
            description=desc,
            event_id=ev.event_id,
            evidence=_event_evidence(ev),
        ))

    # ---- 3. Use-after-free writes -----------------------------------------
    for ev in filter_by_type(events, "use_after_free_write"):
        desc = (
            f"Write to freed memory at {ev.address} "
            f"(allocation #{ev.allocation_id}, event #{ev.event_id})."
        )
        findings.append(Finding(
            bug_class=BugClass.USE_AFTER_FREE_WRITE,
            severity=Severity.HIGH,
            address=ev.address,
            allocation_id=ev.allocation_id,
            size=ev.size,
            description=desc,
            event_id=ev.event_id,
            evidence=_event_evidence(ev),
        ))

    # ---- 4. Memory leaks --------------------------------------------------
    for ev in filter_by_type(events, "memory_leak"):
        desc = (
            f"Memory leak: allocation #{ev.allocation_id} of {ev.size} bytes "
            f"at {ev.address} was never freed."
        )
        findings.append(Finding(
            bug_class=BugClass.MEMORY_LEAK,
            severity=Severity.MEDIUM,
            address=ev.address,
            allocation_id=ev.allocation_id,
            size=ev.size,
            description=desc,
            event_id=ev.event_id,
            evidence=_event_evidence(ev),
        ))

    # ---- 5. Crash with no specific vuln -----------------------------------
    has_specific = any(
        f.bug_class in (
            BugClass.HEAP_BUFFER_OVERFLOW,
            BugClass.DOUBLE_FREE,
            BugClass.USE_AFTER_FREE_WRITE,
        )
        for f in findings
    )
    if crash is not None and crash.exit_code != 0 and not has_specific:
        sig_part = (
            f" (signal {crash.signal_name or crash.signal_number})"
            if crash.signal_number is not None
            else ""
        )
        desc = (
            f"Process crashed with exit code {crash.exit_code}{sig_part} "
            "but no specific memory-safety event was recorded."
        )
        findings.append(Finding(
            bug_class=BugClass.CRASH,
            severity=Severity.HIGH,
            address=None,
            allocation_id=None,
            size=None,
            description=desc,
            evidence={
                "exit_code": crash.exit_code,
                "signal": crash.signal_name or crash.signal_number,
            },
        ))

    # ---- 6. Clean ---------------------------------------------------------
    if not findings:
        findings.append(Finding(
            bug_class=BugClass.CLEAN,
            severity=Severity.INFO,
            address=None,
            allocation_id=None,
            size=None,
            description="No memory-safety issues detected.",
        ))

    return findings


def build_allocation_timeline(events: list[AllocationEvent]) -> list[dict]:
    """
    For each allocation_id, build a timeline row:
    {alloc_id, size, address, thread_id, fate}

    Fate values: "freed" | "leaked" | "overflowed" | "double_freed"
    """
    groups = group_by_allocation(events)
    rows: list[dict] = []

    for alloc_id, evs in sorted(groups.items()):
        # Find the originating allocation event
        alloc_ev = next(
            (e for e in evs if e.event in ("allocation", "reallocation")),
            evs[0],
        )
        size = alloc_ev.size
        address = alloc_ev.address
        thread_id = alloc_ev.thread_id

        # Determine fate from subsequent events
        event_types = {e.event for e in evs}
        if "heap_buffer_overflow" in event_types:
            fate = "overflowed"
        elif "double_free" in event_types:
            fate = "double_freed"
        elif "deallocation" in event_types:
            fate = "freed"
        else:
            fate = "leaked"

        rows.append({
            "alloc_id": alloc_id,
            "size": size,
            "address": address,
            "thread_id": thread_id,
            "fate": fate,
        })

    return rows


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event_evidence(ev: AllocationEvent) -> dict:
    """Serialize a subset of event fields as evidence."""
    d: dict = {
        "event_id": ev.event_id,
        "event": ev.event,
        "thread_id": ev.thread_id,
        "process_id": ev.process_id,
        "timestamp_ns": ev.timestamp_ns,
        "status": ev.status,
    }
    if ev.address is not None:
        d["address"] = ev.address
    if ev.size is not None:
        d["size"] = ev.size
    if ev.overflow_side is not None:
        d["overflow_side"] = ev.overflow_side
    if ev.original_alloc_id is not None:
        d["original_alloc_id"] = ev.original_alloc_id
    if ev.user_size is not None:
        d["user_size"] = ev.user_size
    if ev.extra:
        d["extra"] = ev.extra
    return d
