"""GDB integration: a mockable bridge plus a pure output parser.

No test needs a live GDB. :class:`GdbOutputParser` is a pure function over
saved batch output; :class:`LiveGdbBridge` is a thin subprocess wrapper with an
injectable runner/which so unit tests can verify command construction without
executing anything.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from crashlab.models import GdbFindings, StackFrame
from crashlab.signals import signal_number_for_name

_FRAME_RE = re.compile(r"^\s*#(\d+)\s+(?:(0x[0-9a-fA-F]+)\s+)?(.*)$")
_REGISTER_RE = re.compile(
    r"^\s*([a-zA-Z][a-zA-Z0-9]{1,9})\s+(0x[0-9a-fA-F]+)\s*"
    r"(?:0x[0-9a-fA-F]+|\d+)?\s*(?:\[[^\]]*\])?\s*(?:<[^>]*>)?\s*$"
)
_LOCATION_RE = re.compile(r"\s+at\s+(.+?):(\d+)(?::(\d+))?\s*$")
_MODULE_RE = re.compile(r"\s+from\s+(\S+)\s*$")
_SIGNAL_RE = re.compile(r"Program (?:received|terminated with) signal\s+(SIG[A-Z0-9]+)")
_DISASM_RE = re.compile(r"^\s*(=>)?\s*(0x[0-9a-fA-F]+)\s+<([^>]+)>:\s*(.*)$")
_MARKER_VALUE_RE = re.compile(r"\$\d+\s*=\s*(0x[0-9a-fA-F]+)")


def _inferior_path(path: str) -> str:
    """Quote a path for GDB's ``run < ...`` redirection.

    GDB accepts shlex-style quoting on POSIX. On Windows, single quotes are not
    interpreted by the inferior's shell, so only add double quotes when the path
    actually contains whitespace.
    """

    if os.name == "nt":
        return f'"{path}"' if any(char.isspace() for char in path) else path
    return shlex.quote(path)


class GdbError(RuntimeError):
    """Raised when a GDB session could not be completed."""


class GdbUnavailableError(GdbError):
    """Raised when the configured GDB executable is not present."""


class GdbTimeoutError(GdbError):
    """Raised when GDB exceeded its wall-clock budget."""


@dataclass
class GdbRequest:
    """Inputs for one scripted GDB session."""

    binary: str
    argv: list[str] = field(default_factory=list)
    stdin_file: str | None = None
    cwd: str | None = None
    timeout: float = 30.0
    env: dict[str, str] = field(default_factory=dict)


class GdbBridge(ABC):
    """Interface used by the analyzer; easy to fake in tests."""

    @property
    @abstractmethod
    def available(self) -> bool:
        """Whether a usable GDB is configured."""

    @abstractmethod
    def collect(self, request: GdbRequest) -> GdbFindings:
        """Run GDB against ``request`` and return parsed findings."""


class GdbOutputParser:
    """Parse ``gdb --batch`` text into :class:`GdbFindings`."""

    def parse(
        self,
        text: str,
        *,
        gdb_path: str | None = None,
        exit_code: int | None = None,
    ) -> GdbFindings:
        signal_name = self._signal_name(text)
        signal_number = _signal_number(signal_name)
        frames = self._parse_frames(text)
        registers = self._parse_registers(text)
        disassembly, fault_instruction = self._parse_disassembly(text)
        pc = self._marker_value(text, "__CRASHLAB_PC__") or registers.get("rip") or registers.get(
            "eip"
        )
        fault_address = self._marker_value(text, "__CRASHLAB_SI_ADDR__")

        return GdbFindings(
            available=True,
            crashed=signal_name is not None,
            signal_name=signal_name,
            signal_number=signal_number,
            fault_address=fault_address,
            fault_instruction=fault_instruction,
            pc=pc,
            backtrace=frames,
            registers=registers,
            disassembly=disassembly,
            gdb_path=gdb_path,
            exit_code=exit_code,
            raw_output=text,
        )

    # -- individual extractors -------------------------------------------

    @staticmethod
    def _signal_name(text: str) -> str | None:
        match = _SIGNAL_RE.search(text)
        return match.group(1) if match else None

    @staticmethod
    def _marker_value(text: str, marker: str) -> str | None:
        index = text.find(marker)
        if index < 0:
            return None
        tail = text[index + len(marker) :]
        # Only inspect the next few lines so a later marker cannot leak in.
        window = "\n".join(tail.splitlines()[:4])
        match = _MARKER_VALUE_RE.search(window)
        return match.group(1) if match else None

    @staticmethod
    def _parse_frames(text: str) -> list[StackFrame]:
        frames: list[StackFrame] = []
        for line in text.splitlines():
            match = _FRAME_RE.match(line)
            if not match:
                continue
            index = int(match.group(1))
            address = match.group(2)
            remainder = match.group(3).strip()
            if not remainder:
                continue

            file: str | None = None
            line_number: int | None = None
            column: int | None = None
            location = _LOCATION_RE.search(remainder)
            if location:
                file = location.group(1).strip()
                line_number = int(location.group(2))
                column = int(location.group(3)) if location.group(3) else None
                remainder = remainder[: location.start()].strip()

            module: str | None = None
            module_match = _MODULE_RE.search(remainder)
            if module_match:
                module = module_match.group(1)
                remainder = remainder[: module_match.start()].strip()

            if remainder.startswith("in "):
                remainder = remainder[3:].strip()

            function = remainder
            args: str | None = None
            split = remainder.rfind(" (")
            if split != -1 and remainder.endswith(")"):
                function = remainder[:split].strip()
                args = remainder[split + 2 : -1].strip()
            if not function:
                function = "??"

            frames.append(
                StackFrame(
                    index=index,
                    function=function,
                    address=address,
                    file=file,
                    line=line_number,
                    column=column,
                    module=module,
                    args=args or None,
                    raw=line.rstrip(),
                )
            )
        return frames

    @staticmethod
    def _parse_registers(text: str) -> dict[str, str]:
        registers: dict[str, str] = {}
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            match = _REGISTER_RE.match(line)
            if match:
                registers[match.group(1).lower()] = match.group(2)
        return registers

    @staticmethod
    def _parse_disassembly(text: str) -> tuple[list[str], str | None]:
        lines: list[str] = []
        fault_instruction: str | None = None
        for line in text.splitlines():
            match = _DISASM_RE.match(line)
            if not match:
                continue
            cleaned = line.strip()
            lines.append(cleaned)
            if match.group(1) and fault_instruction is None:
                fault_instruction = cleaned.lstrip("=> ").strip()
        if fault_instruction is None and lines:
            fault_instruction = lines[0].lstrip("=> ").strip()
        return lines, fault_instruction


def _signal_number(name: str | None) -> int | None:
    """Resolve a signal name using the stable POSIX table."""

    return signal_number_for_name(name)


class LiveGdbBridge(GdbBridge):
    """Run ``gdb --batch`` with a fixed command script.

    ``runner`` and ``which`` are injectable for tests. ``runner`` must accept a
    command list and ``subprocess.run``-style keyword arguments.
    """

    def __init__(
        self,
        gdb_path: str = "gdb",
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
        which: Callable[[str], str | None] | None = None,
    ) -> None:
        self.gdb_path = gdb_path
        self._runner = runner or subprocess.run
        self._which = which or shutil.which

    @property
    def available(self) -> bool:
        return self._resolve_gdb() is not None

    def _resolve_gdb(self) -> str | None:
        candidate = Path(self.gdb_path)
        if candidate.parent != Path("") or candidate.is_absolute():
            if candidate.is_file():
                return str(candidate)
            # An explicit path that does not exist may still be resolvable on a
            # foreign-style path in tests; consult ``which`` before giving up.
            return self._which(self.gdb_path)
        return self._which(self.gdb_path)

    def build_command(self, request: GdbRequest) -> list[str]:
        """Build the exact argv passed to GDB (public for tests/diagnostics)."""

        gdb = self._resolve_gdb() or self.gdb_path
        commands = [
            "set pagination off",
            "set confirm off",
            "set width 0",
            "set height 0",
            "set print frame-arguments none",
            "set print elements 200",
            "set disassembly-flavor intel",
        ]
        run_command = "run"
        if request.stdin_file:
            run_command += f" < {_inferior_path(request.stdin_file)}"
        commands.append(run_command)
        commands.extend(
            [
                "bt full",
                "info registers",
                "echo \\n__CRASHLAB_DISASM__\\n",
                "x/5i $pc",
                "echo \\n__CRASHLAB_PC__\\n",
                "p/x $pc",
                "echo \\n__CRASHLAB_SI_ADDR__\\n",
                "p/x $_siginfo._sifields._sigfault.si_addr",
            ]
        )

        command = [gdb, "--batch", "--quiet", "--nx"]
        for item in commands:
            command.extend(["-ex", item])
        command.append("--args")
        command.append(request.binary)
        command.extend(request.argv)
        return command

    def collect(self, request: GdbRequest) -> GdbFindings:
        if not self.available:
            raise GdbUnavailableError(
                f"GDB executable not found: {self.gdb_path!r}. "
                "Install gdb or pass --gdb-path; analysis will otherwise fall "
                "back to signal/instruction-pointer signatures."
            )

        command = self.build_command(request)
        env = request.env or dict(os.environ)
        try:
            completed = self._runner(
                command,
                capture_output=True,
                text=True,
                timeout=request.timeout,
                cwd=request.cwd,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise GdbTimeoutError(
                f"GDB exceeded timeout of {request.timeout:g}s"
            ) from exc
        except FileNotFoundError as exc:  # pragma: no cover - availability check
            raise GdbUnavailableError(f"GDB executable not found: {self.gdb_path}") from exc
        except OSError as exc:
            raise GdbError(f"failed to execute GDB: {exc}") from exc

        combined = completed.stdout or ""
        if completed.stderr:
            combined += "\n[stderr]\n" + completed.stderr
        findings = GdbOutputParser().parse(
            combined, gdb_path=self.gdb_path, exit_code=completed.returncode
        )
        if not findings.crashed and completed.returncode != 0 and not findings.error:
            tail = (completed.stderr or completed.stdout or "").strip().splitlines()
            findings.error = tail[-1] if tail else f"GDB exited with {completed.returncode}"
        return findings
