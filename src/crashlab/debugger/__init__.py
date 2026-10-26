"""Debugger and sanitizer evidence adapters.

Everything that shells out (or used to) lives behind these interfaces:

* :class:`crashlab.debugger.gdb.GdbBridge` — scripted GDB sessions;
* :class:`crashlab.debugger.gdb.GdbOutputParser` — pure parser over saved text;
* :class:`crashlab.debugger.asan.AsanParser` — pure parser over saved ASan text.
"""

from __future__ import annotations

from crashlab.debugger.asan import (
    AsanParser,
    AsanStackFrameParser,
    classify_asan_error,
    parse_asan_output,
    parse_asan_reports,
)
from crashlab.debugger.gdb import (
    GdbBridge,
    GdbError,
    GdbOutputParser,
    GdbRequest,
    GdbTimeoutError,
    GdbUnavailableError,
    LiveGdbBridge,
)

__all__ = [
    "AsanParser",
    "AsanStackFrameParser",
    "GdbBridge",
    "GdbError",
    "GdbOutputParser",
    "GdbRequest",
    "GdbTimeoutError",
    "GdbUnavailableError",
    "LiveGdbBridge",
    "classify_asan_error",
    "parse_asan_output",
    "parse_asan_reports",
]
