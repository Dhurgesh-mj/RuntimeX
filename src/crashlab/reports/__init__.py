"""Report writers. Both consume the same :class:`CrashRecord` sequence."""

from __future__ import annotations

from crashlab.reports.html_report import render_html, write_html_report
from crashlab.reports.json_report import (
    records_payload,
    render_json,
    validate_payload,
    write_json_report,
)

__all__ = [
    "records_payload",
    "render_html",
    "render_json",
    "validate_payload",
    "write_html_report",
    "write_json_report",
]
