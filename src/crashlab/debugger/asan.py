"""AddressSanitizer report parsing.

The parser is a pure function over saved stderr text so it can be tested
against realistic fixtures without building an ASan target. It extracts the
fields triage actually needs and keeps the raw report on disk via
``raw_output_path`` (set by the analyzer after persisting it).
"""

from __future__ import annotations

import re
from typing import Iterable

from crashlab.models import (
    AsanFinding,
    StackFrame,
    VulnerabilityClass,
)

_ERROR_HEADER_RE = re.compile(
    r"==\d+==ERROR:\s*(?P<sanitizer>[A-Za-z]+Sanitizer):\s*(?P<rest>[^\n]*)"
)
_LEGACY_ERROR_RE = re.compile(
    r"ERROR:\s*(?P<sanitizer>AddressSanitizer):\s*(?P<rest>[^\n]*)"
)
_SUMMARY_RE = re.compile(r"SUMMARY:\s*(?P<sanitizer>[A-Za-z]+Sanitizer):\s*(?P<rest>[^\n]*)")
_ACCESS_RE = re.compile(r"\b(READ|WRITE) of size (\d+)\b")
_SIGNAL_ACCESS_RE = re.compile(r"caused by a (READ|WRITE) memory access", re.IGNORECASE)
_THREAD_RE = re.compile(r"\bthread T(\d+)\b")
_PC_RE = re.compile(r"(?:\bat pc\s+|\(pc\s+|\bpc\s+)(0x[0-9a-fA-F]+)")
_ADDRESS_RE = re.compile(
    r"(?:on\s+(?:unknown\s+)?address\s+|on\s+|at\s+|address\s+)(0x[0-9a-fA-F]+)"
)
_REGION_RE = re.compile(r"((?:Address\s+)?0x[0-9a-fA-F]+\s+is\s+located\s+[^\n]+)", re.IGNORECASE)
_REGION_SIZE_RE = re.compile(r"(\d+)-byte region")
_LOCATION_RE = re.compile(r"\s(.+?):(\d+)(?::(\d+))?\s*$")
_MODULE_RE = re.compile(r"\((\S+?)\+0x[0-9a-fA-F]+\)")
_ASAN_FRAME_RE = re.compile(r"^\s*#(\d+)\s+(0x[0-9a-fA-F]+)\s+(?:in\s+)?(.*)$")
_SECTION_RE = re.compile(
    r"^\s*(?:(?P<alloc>previously allocated|allocated)\s+by\s+thread\s+T\d+\s+here:|"
    r"(?P<free>freed)\s+by\s+thread\s+T\d+\s+here:|"
    r"(?P<located>(?:address\s+)?0x[0-9a-fA-F]+\s+is\s+located)|"
    r"(?P<summary>SUMMARY:))",
    re.IGNORECASE,
)

_CLASS_MAP: dict[str, VulnerabilityClass] = {
    "heap-buffer-overflow": VulnerabilityClass.HEAP_BUFFER_OVERFLOW,
    "stack-buffer-overflow": VulnerabilityClass.STACK_BUFFER_OVERFLOW,
    "dynamic-stack-buffer-overflow": VulnerabilityClass.STACK_BUFFER_OVERFLOW,
    "global-buffer-overflow": VulnerabilityClass.GLOBAL_BUFFER_OVERFLOW,
    "container-overflow": VulnerabilityClass.CONTAINER_OVERFLOW,
    "heap-use-after-free": VulnerabilityClass.USE_AFTER_FREE,
    "use-after-poison": VulnerabilityClass.USE_AFTER_FREE,
    "stack-use-after-return": VulnerabilityClass.USE_AFTER_RETURN,
    "stack-use-after-scope": VulnerabilityClass.USE_AFTER_SCOPE,
    "double-free": VulnerabilityClass.DOUBLE_FREE,
    "attempting double-free": VulnerabilityClass.DOUBLE_FREE,
    "invalid-free": VulnerabilityClass.INVALID_FREE,
    "attempting free on address which was not malloc()-ed": VulnerabilityClass.INVALID_FREE,
    "alloc-dealloc-mismatch": VulnerabilityClass.INVALID_FREE,
    "stack-overflow": VulnerabilityClass.STACK_OVERFLOW,
    "SEGV": VulnerabilityClass.UNKNOWN,
    "FPE": VulnerabilityClass.ARITHMETIC_ERROR,
    "ILL": VulnerabilityClass.ILLEGAL_INSTRUCTION,
    "leak": VulnerabilityClass.UNKNOWN,
    "detected memory leaks": VulnerabilityClass.UNKNOWN,
}


def classify_asan_error(error_type: str) -> VulnerabilityClass:
    """Map an ASan error string to the shared vulnerability taxonomy."""

    base = error_type.strip()
    base = re.sub(r"\s*\(.*\)\s*$", "", base)
    lowered = base.lower()
    if lowered in _CLASS_MAP:
        return _CLASS_MAP[lowered]
    for key, value in _CLASS_MAP.items():
        if lowered.startswith(key.lower()):
            return value
    return VulnerabilityClass.UNKNOWN


class AsanParser:
    """Extract structured findings from AddressSanitizer stderr text."""

    def __init__(self) -> None:
        self._frame_parser = AsanStackFrameParser()

    def parse(
        self, text: str, *, raw_output_path: str | None = None
    ) -> AsanFinding | None:
        """Parse the first report in ``text`` (or ``None`` when absent)."""

        reports = self.parse_all(text, raw_output_path=raw_output_path)
        return reports[0] if reports else None

    def parse_all(
        self, text: str, *, raw_output_path: str | None = None
    ) -> list[AsanFinding]:
        """Parse every sanitizer error block in ``text``, in file order."""

        if not text:
            return []

        blocks = self._split_blocks(text)
        findings: list[AsanFinding] = []
        for sanitizer, block in blocks:
            parsed = self._parse_block(sanitizer, block)
            if parsed is None:
                continue
            parsed.raw_output_path = raw_output_path
            findings.append(parsed)
        return findings

    # -- internals --------------------------------------------------------

    @staticmethod
    def _split_blocks(text: str) -> list[tuple[str, str]]:
        matches = list(_ERROR_HEADER_RE.finditer(text))
        if not matches:
            matches = list(_LEGACY_ERROR_RE.finditer(text))
        if not matches:
            return []

        blocks: list[tuple[str, str]] = []
        for index, match in enumerate(matches):
            start = match.start() if match.start() > 0 else 0
            end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            block = text[start:end]
            blocks.append((match.group("sanitizer"), block))
        return blocks

    def _parse_block(self, sanitizer: str, block: str) -> AsanFinding | None:
        header = _ERROR_HEADER_RE.search(block) or _LEGACY_ERROR_RE.search(block)
        if not header:
            return None
        rest = header.group("rest").strip()

        address_match = _ADDRESS_RE.search(rest)
        fault_address = address_match.group(1) if address_match else None

        # The error type ends at " on address ...", " on 0x...", etc.
        type_text = re.split(
            r"\s+on\s+(?:unknown\s+)?address\s+|\s+on\s+0x|\s+in\s+thread\s+|\s+\(pc\s+|\s+at\s+pc\s+",
            rest,
            maxsplit=1,
        )[0]
        error_type = type_text.strip().rstrip(":,")
        if not error_type:
            error_type = "unknown"

        access_match = _ACCESS_RE.search(block)
        if access_match:
            access_type = access_match.group(1).lower()
            access_size = int(access_match.group(2))
        else:
            signal_access = _SIGNAL_ACCESS_RE.search(block)
            access_type = signal_access.group(1).lower() if signal_access else None
            access_size = None

        thread_match = _THREAD_RE.search(block)
        thread_id = int(thread_match.group(1)) if thread_match else None

        pc_match = _PC_RE.search(block)
        pc = pc_match.group(1) if pc_match else None

        region_match = _REGION_RE.search(block)
        region = region_match.group(1).strip() if region_match else None
        size_match = _REGION_SIZE_RE.search(block)
        region_size = int(size_match.group(1)) if size_match else None

        summary_match = _SUMMARY_RE.search(block)
        summary = summary_match.group(0).strip() if summary_match else None

        crash_stack, alloc_stack, free_stack = self._collect_stacks(block)
        vulnerability_class = classify_asan_error(error_type)
        if error_type.lower() == "segv" and fault_address:
            try:
                if int(fault_address, 16) == 0:
                    vulnerability_class = VulnerabilityClass.NULL_POINTER_DEREFERENCE
            except ValueError:
                pass

        return AsanFinding(
            available=True,
            sanitizer=sanitizer,
            error_type=error_type,
            vulnerability_class=vulnerability_class,
            access_type=access_type,
            access_size=access_size,
            fault_address=fault_address,
            thread_id=thread_id,
            pc=pc,
            region=region,
            region_size=region_size,
            crash_stack=crash_stack,
            alloc_stack=alloc_stack,
            free_stack=free_stack,
            summary=summary,
        )

    def _collect_stacks(
        self, block: str
    ) -> tuple[list[StackFrame], list[StackFrame], list[StackFrame]]:
        crash_stack: list[StackFrame] = []
        alloc_stack: list[StackFrame] = []
        free_stack: list[StackFrame] = []
        state = "crash"

        for line in block.splitlines():
            section = _SECTION_RE.match(line)
            if section:
                if section.group("alloc"):
                    state = "alloc"
                elif section.group("free"):
                    state = "free"
                elif section.group("located") or section.group("summary"):
                    state = "none"
                continue

            if not line.lstrip().startswith("#"):
                continue
            frame = self._frame_parser.parse_line(line)
            if frame is None:
                continue
            if state == "crash":
                crash_stack.append(frame)
            elif state == "alloc":
                alloc_stack.append(frame)
            elif state == "free":
                free_stack.append(frame)
        return crash_stack, alloc_stack, free_stack


class AsanStackFrameParser:
    """Parse the ``    #0 0x... in fn /src/file.c:12:3`` format."""

    def parse_line(self, line: str) -> StackFrame | None:
        match = _ASAN_FRAME_RE.match(line)
        if not match:
            return None
        index = int(match.group(1))
        address = match.group(2)
        remainder = match.group(3).strip()
        if not remainder:
            return None

        module: str | None = None
        module_match = _MODULE_RE.search(remainder)
        if module_match:
            module = module_match.group(1)
            remainder = remainder[: module_match.start()].strip()

        file: str | None = None
        line_number: int | None = None
        column: int | None = None
        location = _LOCATION_RE.search(remainder)
        if location:
            file = location.group(1).strip()
            line_number = int(location.group(2))
            column = int(location.group(3)) if location.group(3) else None
            remainder = remainder[: location.start()].strip()

        if remainder.startswith("in "):
            remainder = remainder[3:].strip()

        function = remainder or "??"
        args: str | None = None
        split = remainder.rfind(" (")
        if split != -1 and remainder.endswith(")"):
            function = remainder[:split].strip()
            args = remainder[split + 2 : -1].strip()

        return StackFrame(
            index=index,
            function=function or "??",
            address=address,
            file=file,
            line=line_number,
            column=column,
            module=module,
            args=args or None,
            raw=line.rstrip(),
        )


def parse_asan_output(
    text: str, *, raw_output_path: str | None = None
) -> AsanFinding | None:
    """Convenience wrapper for :class:`AsanParser`."""

    return AsanParser().parse(text, raw_output_path=raw_output_path)


def parse_asan_reports(
    texts: Iterable[str], *, raw_output_path: str | None = None
) -> list[AsanFinding]:
    """Parse multiple saved reports (one per string)."""

    findings: list[AsanFinding] = []
    for text in texts:
        findings.extend(AsanParser().parse_all(text, raw_output_path=raw_output_path))
    return findings
