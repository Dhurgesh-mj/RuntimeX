"""Core scanner: orchestrates binary execution with library injection and analysis."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from heapsentry.analyzer import analyze
from heapsentry.debugger.lldb_bridge import LLDBBridge
from heapsentry.events import parse_events
from heapsentry.models import AllocationEvent, CrashInfo, Finding, ScanResult
from heapsentry.signals import decode_returncode


# ---------------------------------------------------------------------------
# Environment builder
# ---------------------------------------------------------------------------

def _build_env(
    run_id: str,
    library_path: str,
    event_log_path: str,
) -> dict[str, str]:
    """Return an environment dict with library injection and HeapSentry vars set."""
    env = dict(os.environ)
    env["CRASHLAB_RUN_ID"] = run_id
    env["HEAPSENTRY_LOG"] = event_log_path

    # Platform-aware library injection
    if sys.platform == "darwin":
        existing = env.get("DYLD_INSERT_LIBRARIES", "").strip()
        env["DYLD_INSERT_LIBRARIES"] = (
            f"{library_path}:{existing}" if existing else library_path
        )
        # Required for interposition on macOS — without this, the dynamic
        # linker may not honour DYLD_INSERT_LIBRARIES for two-level namespace
        # binaries (which is the default for modern macOS toolchains).
        env["DYLD_FORCE_FLAT_NAMESPACE"] = "1"
    else:
        existing = env.get("LD_PRELOAD", "").strip()
        env["LD_PRELOAD"] = f"{library_path}:{existing}" if existing else library_path

    return env


# ---------------------------------------------------------------------------
# ASan output extraction
# ---------------------------------------------------------------------------

_ASAN_MARKER = "ERROR: AddressSanitizer:"
_ASAN_END_MARKERS = ("SUMMARY: AddressSanitizer:", "==ABORTING==")


def _extract_asan_output(stderr_text: str) -> str | None:
    """Extract the ASan report block from stderr if present."""
    lines = stderr_text.splitlines()
    start_idx: int | None = None
    for i, line in enumerate(lines):
        if _ASAN_MARKER in line:
            start_idx = i
            break
    if start_idx is None:
        return None

    # Collect until an end marker or 200 lines (whichever comes first)
    block: list[str] = []
    for line in lines[start_idx:start_idx + 200]:
        block.append(line)
        if any(m in line for m in _ASAN_END_MARKERS):
            break
    return "\n".join(block)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class Scanner:
    """Orchestrates a single binary run with the HeapSentry detection library injected."""

    def __init__(
        self,
        binary: str,
        *,
        library_path: str,
        out_dir: str = "heapsentry_out",
        timeout: float = 10.0,
        extra_args: list[str] | None = None,
        lldb_path: str = "lldb",
        quiet: bool = False,
    ) -> None:
        self.binary = binary
        self.library_path = library_path
        self.out_dir = Path(out_dir)
        self.timeout = timeout
        self.extra_args = extra_args or []
        self.lldb = LLDBBridge(lldb_path=lldb_path)
        self.quiet = quiet

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        input_path: str | None = None,
        *,
        stdin_bytes: bytes | None = None,
    ) -> ScanResult:
        """
        Run the binary once with the detection library injected.

        Steps:
        1.  Create out_dir/run_id subdirectory
        2.  Copy input_path to run_dir/input.bin (if provided)
        3.  Build injection environment
        4.  Spawn subprocess (shell=False), capture stdout/stderr, enforce timeout
        5.  Determine crash: returncode < 0 (killed by signal on POSIX)
        6.  If crash: run LLDB for a backtrace
        7.  Parse events from events.jsonl
        8.  Extract ASan output from stderr
        9.  Analyze events + crash → findings
        10. Write findings.json, stdout.txt, stderr.txt, backtrace.txt
        11. Return ScanResult
        """
        run_id = uuid.uuid4().hex[:12]
        run_dir = self.out_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        ts_start = _utcnow()

        # ---- Copy input --------------------------------------------------
        effective_input: str | None = None
        if input_path is not None:
            dest = run_dir / "input.bin"
            shutil.copy2(input_path, dest)
            effective_input = str(dest)

        # ---- Prepare stdin bytes -----------------------------------------
        if stdin_bytes is None and effective_input is not None:
            with open(effective_input, "rb") as fh:
                stdin_bytes = fh.read()

        # ---- Build command -----------------------------------------------
        cmd: list[str] = [self.binary, *self.extra_args]

        # ---- Event log path ----------------------------------------------
        event_log = run_dir / "events.jsonl"
        env = _build_env(run_id, self.library_path, str(event_log))

        # ---- Run ---------------------------------------------------------
        timed_out = False
        try:
            proc = subprocess.run(
                cmd,
                input=stdin_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                timeout=self.timeout,
            )
            returncode = proc.returncode
            stdout_text = proc.stdout.decode("utf-8", errors="replace")
            stderr_text = proc.stderr.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            returncode = -1
            stdout_text = (exc.stdout or b"").decode("utf-8", errors="replace")
            stderr_text = (exc.stderr or b"").decode("utf-8", errors="replace")

        ts_end = _utcnow()

        # ---- Crash detection ---------------------------------------------
        sig_num, sig_name = decode_returncode(returncode)
        crashed = returncode < 0 or timed_out

        # ---- LLDB backtrace (only on crash, not timeout) ----------------
        backtrace: str | None = None
        if crashed and not timed_out and self.lldb.available:
            if not self.quiet:
                print(f"  [lldb] capturing backtrace for run {run_id} …")
            backtrace = self.lldb.capture(
                self.binary,
                self.extra_args,
                stdin_bytes=stdin_bytes,
                env=env,
                timeout=min(self.timeout * 3, 60.0),
            )

        # ---- ASan extraction ---------------------------------------------
        asan_output = _extract_asan_output(stderr_text)

        # ---- Build CrashInfo --------------------------------------------
        crash_info: CrashInfo | None = None
        if crashed:
            crash_info = CrashInfo(
                exit_code=returncode,
                signal_name=sig_name,
                signal_number=sig_num,
                backtrace=backtrace,
                asan_output=asan_output,
                stderr_text=stderr_text,
                stdout_text=stdout_text,
            )

        # ---- Parse events -----------------------------------------------
        events = parse_events(event_log)

        # ---- Analyze -----------------------------------------------------
        findings = analyze(events, crash_info)

        # ---- Persist artifacts ------------------------------------------
        (run_dir / "stdout.txt").write_text(stdout_text, encoding="utf-8")
        (run_dir / "stderr.txt").write_text(stderr_text, encoding="utf-8")
        if backtrace:
            (run_dir / "backtrace.txt").write_text(backtrace, encoding="utf-8")

        findings_data = [_finding_to_dict(f) for f in findings]
        (run_dir / "findings.json").write_text(
            json.dumps(findings_data, indent=2), encoding="utf-8"
        )

        return ScanResult(
            run_id=run_id,
            binary=self.binary,
            input_path=effective_input,
            timestamp_start=ts_start,
            timestamp_end=ts_end,
            crashed=crashed,
            timed_out=timed_out,
            exit_code=returncode,
            crash_info=crash_info,
            events=events,
            findings=findings,
            event_log_path=str(event_log) if event_log.exists() else None,
            out_dir=str(run_dir),
        )

    def scan_corpus(
        self,
        input_dir: str,
        *,
        workers: int = 1,
        progress: bool = True,
    ) -> list[ScanResult]:
        """Run scan() against every file in input_dir using a thread pool."""
        inputs = sorted(Path(input_dir).iterdir())
        # Only regular files
        inputs = [p for p in inputs if p.is_file()]

        if not inputs:
            if not self.quiet:
                print(f"[heapsentry] No input files found in {input_dir}")
            return []

        results: list[ScanResult] = []
        total = len(inputs)

        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            future_map = {
                pool.submit(self.scan, str(p)): p for p in inputs
            }
            done = 0
            for fut in as_completed(future_map):
                inp = future_map[fut]
                done += 1
                try:
                    result = fut.result()
                    results.append(result)
                    if progress and not self.quiet:
                        finding_summary = _count_severity(result.findings)
                        print(
                            f"  [{done}/{total}] {inp.name} — "
                            f"{finding_summary}"
                        )
                except Exception as exc:
                    if not self.quiet:
                        print(f"  [{done}/{total}] {inp.name} — ERROR: {exc}")

        return results


# ---------------------------------------------------------------------------
# Library auto-build
# ---------------------------------------------------------------------------

def build_library(source_dir: str, build_dir: str) -> str:
    """
    Auto-build the HeapSentry detection library if not already built.

    Invokes ``make -f Makefile.heapsentry library`` in *source_dir* and
    expects the output to land in *build_dir*.

    Returns the absolute path to the built .dylib (macOS) or .so (Linux).
    Raises RuntimeError if the build fails.
    """
    lib_name = (
        "libheapsentry_detect.dylib"
        if sys.platform == "darwin"
        else "libheapsentry_detect.so"
    )
    lib_path = Path(build_dir) / lib_name

    if lib_path.exists():
        return str(lib_path)

    makefile = Path(source_dir) / "Makefile.heapsentry"
    if not makefile.exists():
        raise RuntimeError(
            f"Makefile not found at {makefile}. "
            "Pass --no-build or build the library manually."
        )

    result = subprocess.run(
        ["make", "-f", str(makefile), "library"],
        cwd=source_dir,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Library build failed (exit {result.returncode}):\n"
            f"{result.stdout}\n{result.stderr}"
        )

    if not lib_path.exists():
        raise RuntimeError(
            f"Build succeeded but library not found at expected path: {lib_path}"
        )

    return str(lib_path)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _finding_to_dict(f: Finding) -> dict:
    return {
        "bug_class": f.bug_class.value,
        "severity": f.severity.value,
        "address": f.address,
        "allocation_id": f.allocation_id,
        "size": f.size,
        "description": f.description,
        "event_id": f.event_id,
        "overflow_side": f.overflow_side,
        "evidence": f.evidence,
    }


def _count_severity(findings: list[Finding]) -> str:
    from heapsentry.models import Severity
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    parts = []
    for sev in ("critical", "high", "medium", "info"):
        n = counts.get(sev, 0)
        if n:
            parts.append(f"{n} {sev}")
    return ", ".join(parts) if parts else "clean"
