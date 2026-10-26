"""JSON report generation from the shared CrashRecord model."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable, Sequence

from crashlab.models import (
    REQUIRED_CRASH_RECORD_FIELDS,
    CrashRecord,
    ReportConfig,
)


def records_payload(records: Iterable[CrashRecord]) -> list[dict[str, Any]]:
    """Serialize records into the top-level JSON array used on disk."""

    return [record.to_dict() for record in records]


def render_json(
    records: Iterable[CrashRecord],
    *,
    indent: int | None = 2,
) -> str:
    """Render the complete report payload as UTF-8 JSON text."""

    payload = records_payload(records)
    return json.dumps(payload, indent=indent, ensure_ascii=False, allow_nan=False)


def write_json_report(
    path: str | os.PathLike[str],
    records: Sequence[CrashRecord],
    *,
    config: ReportConfig | None = None,
    indent: int | None = 2,
) -> Path:
    """Write a JSON array of CrashRecords atomically.

    The ``config`` argument is accepted for symmetry with the HTML writer; the
    report payload itself is deliberately a plain array so downstream tooling
    can consume it without an envelope. Report-level metadata (title, generated
    timestamp) is available in the HTML report and in ``groups.json``.
    """

    del config  # reserved for future envelope/schema options
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(render_json(records, indent=indent) + "\n", encoding="utf-8", newline="\n")
    os.replace(temporary, target)
    return target


def validate_payload(payload: Any) -> list[str]:
    """Validate the serialized report shape; return human-readable errors.

    This is intentionally dependency-free (no jsonschema) and checks the
    fields both report writers rely on.
    """

    errors: list[str] = []
    if not isinstance(payload, list):
        return ["report payload must be a JSON array of crash records"]
    for index, record in enumerate(payload):
        prefix = f"record[{index}]"
        if not isinstance(record, dict):
            errors.append(f"{prefix} must be an object")
            continue
        for field_name in REQUIRED_CRASH_RECORD_FIELDS:
            if field_name not in record:
                errors.append(f"{prefix}.{field_name} is missing")
        for field_name in (
            "run_id",
            "timestamp",
            "timestamp_start",
            "timestamp_end",
            "crash_signature",
            "reproduction_command",
        ):
            if field_name in record and not isinstance(record[field_name], str):
                errors.append(f"{prefix}.{field_name} must be a string")
        for field_name in ("classification", "confidence", "vulnerability_class"):
            if field_name in record and not isinstance(record[field_name], str):
                errors.append(f"{prefix}.{field_name} must be a string")
        if "input" in record and not isinstance(record["input"], dict):
            errors.append(f"{prefix}.input must be an object")
        if "gdb" in record and not isinstance(record["gdb"], dict):
            errors.append(f"{prefix}.gdb must be an object")
        if "runtime_trace_ref" in record and record["runtime_trace_ref"] is not None and not isinstance(
            record["runtime_trace_ref"], dict
        ):
            errors.append(f"{prefix}.runtime_trace_ref must be an object or null")
    return errors
