"""Platform-aware signal decoding and process termination.

POSIX returns a negative ``subprocess`` return code when the child dies from a
signal (``-SIGSEGV``). Windows has no such convention; a crashing process exits
with an NTSTATUS value in the high-bit range (e.g. ``0xC0000005``). We normalize
both worlds to :class:`~crashlab.models.SignalInfo`, keeping the native NTSTATUS
in ``native_status`` so evidence is never lost.

The Windows mapping is deliberately conservative: only well-known crash
statuses are classified as crashes. Unknown ``0xC000....`` statuses are reported
as ``ERROR`` rather than silently inventing a signal.
"""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from crashlab.models import RunStatus, SignalInfo

IS_WINDOWS = os.name == "nt"

#: Stable POSIX signal numbers, independent of the host's signal table.
#: Windows exposes a different numbering (e.g. ``SIGABRT == 22``), so decoding
#: a *POSIX* return code must not use :mod:`signal` from the local platform.
POSIX_SIGNAL_NAMES: dict[int, str] = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    7: "SIGBUS",
    8: "SIGFPE",
    9: "SIGKILL",
    10: "SIGUSR1",
    11: "SIGSEGV",
    12: "SIGUSR2",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
    16: "SIGSTKFLT",
    17: "SIGCHLD",
    18: "SIGCONT",
    19: "SIGSTOP",
    20: "SIGTSTP",
    21: "SIGTTIN",
    22: "SIGTTOU",
    23: "SIGURG",
    24: "SIGXCPU",
    25: "SIGXFSZ",
    26: "SIGVTALRM",
    27: "SIGPROF",
    28: "SIGWINCH",
    29: "SIGIO",
    30: "SIGPWR",
    31: "SIGSYS",
}

POSIX_SIGNAL_NUMBERS: dict[str, int] = {
    name: number for number, name in POSIX_SIGNAL_NAMES.items()
}

_POSIX_DESCRIPTIONS: dict[int, str] = {
    1: "Hangup",
    2: "Interrupt",
    3: "Quit with core dump",
    4: "Illegal instruction",
    5: "Trace/breakpoint trap",
    6: "Aborted",
    7: "Bus error",
    8: "Floating-point exception",
    9: "Killed (uncatchable)",
    10: "User-defined signal 1",
    11: "Segmentation fault (invalid memory access)",
    12: "User-defined signal 2",
    13: "Broken pipe",
    14: "Alarm clock",
    15: "Terminated",
    16: "Stack fault",
    17: "Child status changed",
    18: "Continue",
    19: "Stopped",
    20: "Terminal stop",
    24: "CPU time limit exceeded",
    25: "File size limit exceeded",
    26: "Virtual timer expired",
    27: "Profiling timer expired",
    29: "I/O possible",
    31: "Bad system call",
}

#: Signals we treat as a crash when they terminate the process.
CRASH_SIGNALS: frozenset[str] = frozenset(
    {
        "SIGSEGV",
        "SIGBUS",
        "SIGABRT",
        "SIGILL",
        "SIGFPE",
        "SIGTRAP",
        "SIGSYS",
        "SIGXCPU",
        "SIGXFSZ",
    }
)


@dataclass(frozen=True)
class WindowsStatus:
    """Normalized interpretation of an NTSTATUS exit code."""

    posix_number: int
    posix_name: str
    description: str
    is_crash: bool = True


#: Common NTSTATUS crash values mapped to POSIX pseudo-signals.
WINDOWS_STATUS_MAP: dict[int, WindowsStatus] = {
    0xC0000005: WindowsStatus(11, "SIGSEGV", "Access violation (Windows NTSTATUS 0xC0000005)"),
    0xC0000006: WindowsStatus(11, "SIGSEGV", "In-page error (Windows NTSTATUS 0xC0000006)"),
    0xC0000008: WindowsStatus(11, "SIGSEGV", "Invalid handle (Windows NTSTATUS 0xC0000008)"),
    0xC000001D: WindowsStatus(4, "SIGILL", "Illegal instruction (Windows NTSTATUS 0xC000001D)"),
    0xC0000025: WindowsStatus(11, "SIGSEGV", "Non-continuable exception (Windows NTSTATUS 0xC0000025)"),
    0xC000008C: WindowsStatus(11, "SIGSEGV", "Array bounds exceeded (Windows NTSTATUS 0xC000008C)"),
    0xC0000094: WindowsStatus(8, "SIGFPE", "Integer divide by zero (Windows NTSTATUS 0xC0000094)"),
    0xC0000095: WindowsStatus(8, "SIGFPE", "Integer overflow (Windows NTSTATUS 0xC0000095)"),
    0xC0000096: WindowsStatus(4, "SIGILL", "Privileged instruction (Windows NTSTATUS 0xC0000096)"),
    0xC00000FD: WindowsStatus(11, "SIGSEGV", "Stack overflow (Windows NTSTATUS 0xC00000FD)"),
    0xC0000374: WindowsStatus(6, "SIGABRT", "Heap corruption (Windows NTSTATUS 0xC0000374)"),
    0xC0000409: WindowsStatus(6, "SIGABRT", "Stack buffer overrun / fast-fail (Windows NTSTATUS 0xC0000409)"),
    0xC000041D: WindowsStatus(6, "SIGABRT", "Unhandled exception during callback (Windows NTSTATUS 0xC000041D)"),
    0xC0000420: WindowsStatus(6, "SIGABRT", "Assertion failure (Windows NTSTATUS 0xC0000420)"),
}

#: NTSTATUS values that mean "the process failed to run", not "the target crashed".
WINDOWS_ERROR_STATUS_MAP: dict[int, str] = {
    0xC0000135: "DLL not found (Windows NTSTATUS 0xC0000135)",
    0xC0000142: "DLL initialization failed (Windows NTSTATUS 0xC0000142)",
    0xC000013A: "Interrupted with Ctrl-C (Windows NTSTATUS 0xC000013A)",
    0xC0000409 & 0xFFFFFFFF: "",  # documents precedence: crash map wins
}

_WINDOWS_ERRORS = {key: value for key, value in WINDOWS_ERROR_STATUS_MAP.items() if value}


def posix_signal_name(signum: int) -> str:
    """Return the POSIX signal name for ``signum``.

    Uses a fixed table (not the host's :mod:`signal` module) so simulated POSIX
    runs classify correctly on Windows.
    """

    return POSIX_SIGNAL_NAMES.get(signum, f"SIG{signum}")


def signal_number_for_name(name: str | None) -> int | None:
    """Return the POSIX number for a signal name such as ``SIGSEGV``."""

    if not name:
        return None
    return POSIX_SIGNAL_NUMBERS.get(name.upper())


def posix_signal(signum: int, *, platform_name: str | None = None) -> SignalInfo:
    """Build a :class:`SignalInfo` for a POSIX signal number."""

    platform_name = platform_name or ("windows" if IS_WINDOWS else sys.platform)
    return SignalInfo(
        name=posix_signal_name(signum),
        number=signum,
        description=_POSIX_DESCRIPTIONS.get(signum, ""),
        platform=platform_name,
    )


def decode_returncode(
    returncode: int | None,
    *,
    timed_out: bool = False,
    platform_name: str | None = None,
) -> tuple[RunStatus, SignalInfo | None, str | None]:
    """Classify a child return code.

    Returns ``(status, signal_info, error_message)``.

    * timeout wins over everything else;
    * POSIX negative codes are signal terminations;
    * Windows NTSTATUS crash values are normalized (native value retained);
    * a normal non-zero exit is still ``NORMAL`` — an exit code is not a crash.
    """

    platform_name = platform_name or ("windows" if IS_WINDOWS else sys.platform)

    if timed_out:
        return RunStatus.TIMEOUT, None, None

    if returncode is None:
        return RunStatus.ERROR, None, "process did not report a return code"

    if platform_name.startswith("win"):
        unsigned = returncode & 0xFFFFFFFF
        if unsigned in WINDOWS_STATUS_MAP:
            mapped = WINDOWS_STATUS_MAP[unsigned]
            return (
                RunStatus.CRASH,
                SignalInfo(
                    name=mapped.posix_name,
                    number=mapped.posix_number,
                    description=mapped.description,
                    native_status=unsigned,
                    platform="windows",
                ),
                None,
            )
        if unsigned in _WINDOWS_ERRORS:
            return RunStatus.ERROR, None, _WINDOWS_ERRORS[unsigned]
        if unsigned >= 0x80000000:
            return (
                RunStatus.ERROR,
                None,
                f"unrecognized Windows NTSTATUS 0x{unsigned:08X}; not auto-classified",
            )
        return RunStatus.NORMAL, None, None

    if returncode < 0:
        signum = -returncode
        info = posix_signal(signum, platform_name=platform_name)
        if info.name in CRASH_SIGNALS:
            return RunStatus.CRASH, info, None
        # Terminations such as SIGTERM/SIGKILL are abnormal but not memory
        # crashes. Keep them visible as ERROR instead of promoting them.
        return RunStatus.ERROR, info, f"terminated by non-crash signal {info.name}"

    return RunStatus.NORMAL, None, None


def is_crash_signal(name: str | None) -> bool:
    """True when ``name`` is in the crash-signal set."""

    return bool(name) and name in CRASH_SIGNALS


def supports_preload() -> bool:
    """LD_PRELOAD is a POSIX dynamic-linker feature."""

    return not IS_WINDOWS


def resolve_executable(command: str) -> str | None:
    """Resolve an executable via PATH (or as a direct path)."""

    candidate = Path(command)
    if candidate.parent != Path("") or candidate.is_absolute():
        if candidate.is_file():
            return str(candidate.resolve())
        return None
    return shutil.which(command)


def build_environment(
    *,
    run_id: str,
    batch_id: str | None,
    timestamp_start: str,
    timeout_seconds: float,
    input_sha256: str,
    preload: str | None,
    asan_options: str | None,
) -> tuple[dict[str, str], dict[str, str], str | None, bool]:
    """Construct the child environment and record only our overrides.

    Returns ``(env, overrides, effective_preload, preload_applied)``.

    Crashlab sets correlation environment variables (``CRASHLAB_*``) that
    Person 1's instrumentation can use to stamp runtime events with the same
    ``run_id``. Existing ``LD_PRELOAD`` entries are preserved and the requested
    library is prepended.
    """

    env = dict(os.environ)
    overrides: dict[str, str] = {
        "CRASHLAB_RUN_ID": run_id,
        "CRASHLAB_TIMESTAMP_START": timestamp_start,
        "CRASHLAB_TIMEOUT_SECONDS": f"{timeout_seconds:g}",
        "CRASHLAB_INPUT_SHA256": input_sha256,
    }
    if batch_id:
        overrides["CRASHLAB_BATCH_ID"] = batch_id

    effective_preload: str | None = None
    applied = False
    if preload:
        effective_preload = preload
        if supports_preload():
            existing = env.get("LD_PRELOAD", "").strip()
            env["LD_PRELOAD"] = f"{preload}:{existing}" if existing else preload
            overrides["LD_PRELOAD"] = env["LD_PRELOAD"]
            applied = True

    if asan_options:
        env["ASAN_OPTIONS"] = asan_options
        overrides["ASAN_OPTIONS"] = asan_options

    env.update(overrides)
    return env, overrides, effective_preload, applied


def format_reproduction_command(
    argv: Sequence[str],
    *,
    env_overrides: Mapping[str, str] | None = None,
    stdin_path: str | os.PathLike[str] | None = None,
    platform_name: str | None = None,
) -> str:
    """Render a copy-pasteable command (platform-appropriate quoting)."""

    platform_name = platform_name or ("windows" if IS_WINDOWS else sys.platform)
    env_overrides = dict(env_overrides or {})

    if platform_name.startswith("win"):
        command = subprocess.list2cmdline([str(item) for item in argv])
        prefix = " && ".join(
            f'set "{key}={value}"' for key, value in sorted(env_overrides.items())
        )
        if prefix:
            command = f"{prefix} && {command}"
        if stdin_path:
            command += f' < "{stdin_path}"'
        return command

    command = shlex.join([str(item) for item in argv])
    if env_overrides:
        assignments = " ".join(
            f"{key}={shlex.quote(value)}" for key, value in sorted(env_overrides.items())
        )
        command = f"env {assignments} {command}"
    if stdin_path:
        command += f" < {shlex.quote(str(stdin_path))}"
    return command


def new_process_group_kwargs() -> dict[str, object]:
    """Popen kwargs that put the child in its own group for clean teardown."""

    if IS_WINDOWS:
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def terminate_process_tree(process: subprocess.Popen[bytes], *, grace: float = 1.0) -> None:
    """Kill a child and its descendants, best effort.

    POSIX uses ``killpg`` on the session created by the runner. Windows uses
    ``taskkill /T /F`` because ``Popen.kill`` alone leaves grandchildren alive.
    """

    if process.poll() is not None:
        return

    if IS_WINDOWS:  # pragma: no cover - exercised on Windows only
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                capture_output=True,
                timeout=max(grace, 1.0),
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            process.kill()
        except OSError:
            pass
        return

    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except OSError:
            pass


def describe_platform() -> str:
    """Short human description used by ``crashlab doctor`` and manifests."""

    return f"{sys.platform} (python {sys.version.split()[0]})"
