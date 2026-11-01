"""Parse and group JSONL event logs emitted by libheapsentry_detect."""

import json
from collections import defaultdict
from pathlib import Path

from heapsentry.models import AllocationEvent


def parse_events(log_path: Path) -> list[AllocationEvent]:
    """Read and parse a JSONL event log, skipping malformed lines."""
    events: list[AllocationEvent] = []
    try:
        text = Path(log_path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return events

    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue  # skip malformed lines silently

        # Pull out known fields; everything else lands in extra.
        known = {
            "event_id", "event", "allocation_id", "old_allocation_id",
            "address", "size", "status", "timestamp_ns", "thread_id",
            "process_id", "overflow_side", "original_alloc_id", "user_size",
            # schema/run metadata — ignored at event level
            "schema_version", "run_id", "batch_id", "corrupted_canary",
        }
        extra = {k: v for k, v in obj.items() if k not in known}

        try:
            ev = AllocationEvent(
                event_id=int(obj.get("event_id", 0)),
                event=str(obj.get("event", "")),
                allocation_id=_opt_int(obj.get("allocation_id")),
                old_allocation_id=_opt_int(obj.get("old_allocation_id")),
                address=obj.get("address"),
                size=_opt_int(obj.get("size")),
                status=str(obj.get("status", "ok")),
                timestamp_ns=int(obj.get("timestamp_ns", 0)),
                thread_id=int(obj.get("thread_id", 0)),
                process_id=int(obj.get("process_id", 0)),
                overflow_side=obj.get("overflow_side"),
                original_alloc_id=_opt_int(obj.get("original_alloc_id")),
                user_size=_opt_int(obj.get("user_size")),
                extra=extra,
            )
        except (TypeError, ValueError):
            continue  # skip events with structurally bad data

        events.append(ev)

    return events


def filter_by_type(events: list[AllocationEvent], *event_types: str) -> list[AllocationEvent]:
    """Return only events whose .event field matches one of event_types."""
    types = set(event_types)
    return [e for e in events if e.event in types]


def group_by_allocation(events: list[AllocationEvent]) -> dict[int, list[AllocationEvent]]:
    """Group events by allocation_id (None-keyed events are excluded)."""
    groups: dict[int, list[AllocationEvent]] = defaultdict(list)
    for ev in events:
        if ev.allocation_id is not None:
            groups[ev.allocation_id].append(ev)
    return dict(groups)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _opt_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
