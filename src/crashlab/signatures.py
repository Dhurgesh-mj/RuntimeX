"""Crash signature computation and deduplication.

A signature answers "are these two crashes the same bug?". The preferred key
is signal + normalized top-N debugger frames. Normalization removes the things
that change between runs (ASLR addresses, absolute build paths) while keeping
the things triage cares about (function, source file, line).

Fallback order:

1. GDB backtrace frames (``gdb``)
2. ASan crash/alloc/free stack frames (``asan-stack``)
3. Signal + instruction pointer (``instruction-pointer``)
4. Signal only (``signal-only``)

Instruction-pointer signatures are ASLR-sensitive. Crashlab records the method
so a reader can judge how much to trust grouping; the README documents this
limitation.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable, Sequence

from crashlab.models import CrashGroup, CrashRecord, SignalInfo, StackFrame, group_by_signature

DEFAULT_TOP_N = 5

_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
_ADDR_SUFFIX_RE = re.compile(r"\+0x[0-9a-fA-F]+$")


@dataclass(frozen=True)
class Signature:
    """A human-readable signature plus its stable digest."""

    text: str
    digest: str
    method: str
    frames: tuple[str, ...] = ()


def _sha256_short(text: str, length: int = 16) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:length]


def _basename(path: str) -> str:
    # Stack traces can contain POSIX or Windows separators regardless of host.
    return re.split(r"[\\/]", path.strip())[-1]


def normalize_function(name: str | None) -> str:
    """Normalize a function name for grouping.

    Addresses and offset suffixes are removed, argument lists are dropped, and
    unknown frames collapse to ``[unknown]``. Namespace/template content is kept
    because it distinguishes real call sites.
    """

    if not name:
        return "[unknown]"
    text = name.strip()
    if text in {"??", "?", "[unknown]", "<unknown>"}:
        return "[unknown]"
    # Strip a trailing " (args)" if a caller passed a raw frame line.
    text = re.sub(r"\s*\(.*\)\s*$", "", text)
    # GDB sometimes prints "func+41" / "func+0x29" in symbolic names.
    text = re.sub(r"\+0x[0-9a-fA-F]+$", "", text)
    text = re.sub(r"\+\d+$", "", text)
    # Strip absolute address annotations such as "0x... in foo".
    text = re.sub(r"^0x[0-9a-fA-F]+\s+in\s+", "", text)
    text = text.strip()
    return text or "[unknown]"


def normalize_frame(frame: StackFrame) -> str:
    """Return the stable portion of one frame.

    Source location is preferred. If only a module is known, function + module
    is used. Addresses are intentionally omitted so ASLR does not fan out
    identical crashes into many groups.
    """

    function = normalize_function(frame.function)
    location = ""
    if frame.file:
        location = _basename(frame.file)
        if frame.line:
            location = f"{location}:{frame.line}"
    elif frame.module:
        module = _basename(frame.module)
        # Versioned libraries churn on updates; keep the leading name only.
        module = module.split(".so")[0]
        location = f"<{module}>"

    if function == "[unknown]" and not location:
        return "[unknown]"
    return f"{function} @ {location}" if location else function


def _frame_label(frame: StackFrame) -> str:
    """Human label used in the signature display text."""

    normalized = normalize_frame(frame)
    if frame.offset is not None:
        return f"{normalized}+0x{frame.offset:x}"
    return normalized


def _dedupe_preserving_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def compute_signature(
    signal: SignalInfo | None,
    frames: Sequence[StackFrame] | None = None,
    *,
    fault_ip: str | None = None,
    top_n: int = DEFAULT_TOP_N,
    method: str | None = None,
) -> Signature:
    """Compute a signature from frames, an instruction pointer, or a signal.

    ``frames`` is expected in innermost-first order. Only the top ``top_n``
    normalized frames participate, which keeps grouping resilient to deeper
    libc/startup frames while still distinguishing real call paths.
    """

    signal_name = signal.name if signal else "UNKNOWN"
    normalized = [_frame_label(frame) for frame in (frames or [])]
    normalized = _dedupe_preserving_order(normalized)
    normalized = [item for item in normalized if item != "[unknown]"]
    selected = normalized[: max(1, top_n)]

    if selected:
        resolved_method = method or "gdb"
        text = f"{signal_name} | " + " > ".join(selected)
        return Signature(
            text=text,
            digest=_sha256_short(text),
            method=resolved_method,
            frames=tuple(selected),
        )

    if fault_ip:
        # Normalize the numeric value but preserve the pointer value: when no
        # symbolication is available this is the only discriminator we have.
        address = fault_ip.strip().lower()
        try:
            address = hex(int(address, 16))
        except (TypeError, ValueError):
            pass
        text = f"{signal_name} | ip={address}"
        return Signature(
            text=text,
            digest=_sha256_short(text),
            method="instruction-pointer",
            frames=(),
        )

    text = f"{signal_name} | no-frames"
    return Signature(
        text=text,
        digest=_sha256_short(text),
        method="signal-only",
        frames=(),
    )


def signature_for_record(record: CrashRecord) -> Signature:
    """Recover the :class:`Signature` object from a record."""

    return Signature(
        text=record.crash_signature,
        digest=record.signature_hash,
        method=record.signature_method,
    )


def group_crashes(records: Iterable[CrashRecord]) -> list[CrashGroup]:
    """Group crash records by signature (thin wrapper for discoverability)."""

    return group_by_signature(records)


def describe_group(group: CrashGroup) -> str:
    """One-line manual summary of a crash group."""

    representative = group.representative
    return (
        f"{group.signature_hash}  {representative.vulnerability_class.value:<24} "
        f"{group.classification.value:<24} {group.confidence.value:<6} "
        f"x{len(group.records)} ({len(group.input_hashes)} input(s))"
    )
