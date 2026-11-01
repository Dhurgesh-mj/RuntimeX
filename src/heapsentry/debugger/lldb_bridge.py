"""LLDB integration for post-crash backtrace capture."""

import shutil
import subprocess
import tempfile
from pathlib import Path

# LLDB batch commands executed after the program is launched.
# 'run' starts the target; the remaining commands are executed after it stops
# (either by a signal/crash or normal exit).
_LLDB_COMMANDS = [
    "run",
    "bt all",
    "frame info",
    "register read",
    "quit",
]


class LLDBBridge:
    """Thin wrapper around the system LLDB for batch crash analysis."""

    def __init__(self, lldb_path: str = "lldb") -> None:
        self.lldb_path = lldb_path

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def available(self) -> bool:
        """Return True if lldb is on PATH (or at the configured path)."""
        return shutil.which(self.lldb_path) is not None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def capture(
        self,
        binary: str,
        args: list[str],
        *,
        stdin_bytes: bytes | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> str | None:
        """
        Run *binary* under LLDB in batch/one-shot mode and return raw output.

        Uses ``lldb --batch -o <cmd> ... -- <binary> [args]`` so LLDB exits
        automatically after executing all -o commands.  If ``stdin_bytes`` is
        provided it is written to a temporary file which is redirected to the
        target's stdin via ``<(cat file)`` — because subprocess with LLDB in
        batch mode does not easily forward stdin, we pass the temp-file path
        as a file-redirect argument instead.

        Returns ``None`` when:
        - LLDB is not available on this system
        - The invocation times out
        - Any other OS-level error prevents LLDB from running
        """
        if not self.available:
            return None

        # Build the -o command list
        cmd: list[str] = [self.lldb_path, "--batch"]
        for lldb_cmd in _LLDB_COMMANDS:
            cmd += ["-o", lldb_cmd]
        cmd += ["--", binary, *args]

        # If stdin data was supplied, write it to a temp file and redirect.
        stdin_file = None
        try:
            if stdin_bytes is not None:
                stdin_file = tempfile.NamedTemporaryFile(
                    delete=False, prefix="heapsentry_stdin_"
                )
                stdin_file.write(stdin_bytes)
                stdin_file.flush()
                stdin_file.close()
                stdin_redirect = open(stdin_file.name, "rb")
            else:
                stdin_redirect = subprocess.DEVNULL

            result = subprocess.run(
                cmd,
                stdin=stdin_redirect,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # merge stderr into stdout for full output
                env=env,
                timeout=timeout,
            )
            return result.stdout.decode("utf-8", errors="replace")

        except subprocess.TimeoutExpired:
            return None
        except OSError:
            return None
        finally:
            if stdin_file is not None:
                try:
                    Path(stdin_file.name).unlink(missing_ok=True)
                except OSError:
                    pass
            if stdin_bytes is not None and stdin_redirect is not subprocess.DEVNULL:
                try:
                    stdin_redirect.close()
                except OSError:
                    pass
