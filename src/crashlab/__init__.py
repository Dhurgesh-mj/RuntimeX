"""Crashlab: reproducible crash detection and exploitability triage.

Crashlab is a defensive memory-safety research harness. It executes local
test binaries under controlled conditions, classifies abnormal termination,
collects debugger/sanitizer evidence, and emits a single structured model
(:class:`crashlab.models.CrashRecord`) used by both JSON and HTML reports.

The public entry point is the ``crashlab`` console script (see
:mod:`crashlab.cli`). The package is intentionally dependency-light: the
runtime model uses dataclasses and the standard library only.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
