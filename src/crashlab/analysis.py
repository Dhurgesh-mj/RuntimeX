"""Crash analysis, evidence correlation, and crash-group preservation.

Analysis combines three independent evidence sources:

* the terminating signal observed by the runner;
* optional AddressSanitizer text (captured in stderr or supplied from a
  separately instrumented build);
* optional scripted GDB findings.

The promotion rule is intentionally conservative. Only concrete ASan classes
(or an unambiguous glibc allocator diagnosis) set
``classification=confirmed_vulnerability``. A bare signal stays ``crash`` even
when GDB shows a plausible null-pointer dereference.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from crashlab.config import RunConfig
from crashlab.debugger.asan import AsanParser
from crashlab.debugger.gdb import (
    GdbBridge,
    GdbError,
    GdbRequest,
    GdbTimeoutError,
    GdbUnavailableError,
    LiveGdbBridge,
)
from crashlab.models import (
    CRASH_RECORD_SCHEMA,
    AsanFinding,
    Classification,
    Confidence,
    CrashGroup,
    CrashRecord,
    GdbFindings,
    InputMode,
    RunResult,
    RunStatus,
    RuntimeTraceRef,
    StackFrame,
    VulnerabilityClass,
    group_by_signature,
    utc_now_iso,
)
from crashlab.runner import discover_runs
from crashlab.signatures import compute_signature

LOGGER = logging.getLogger("crashlab.analysis")

#: ASan classes that are concrete enough to promote a crash to confirmed.
_CONFIRMING_ASAN_CLASSES = {
    VulnerabilityClass.HEAP_BUFFER_OVERFLOW,
    VulnerabilityClass.STACK_BUFFER_OVERFLOW,
    VulnerabilityClass.GLOBAL_BUFFER_OVERFLOW,
    VulnerabilityClass.BUFFER_OVERFLOW,
    VulnerabilityClass.CONTAINER_OVERFLOW,
    VulnerabilityClass.USE_AFTER_FREE,
    VulnerabilityClass.USE_AFTER_RETURN,
    VulnerabilityClass.USE_AFTER_SCOPE,
    VulnerabilityClass.DOUBLE_FREE,
    VulnerabilityClass.INVALID_FREE,
    VulnerabilityClass.STACK_OVERFLOW,
}

_MITIGATIONS: dict[VulnerabilityClass, str] = {
    VulnerabilityClass.HEAP_BUFFER_OVERFLOW: (
        "Add allocation-aware bounds checks and use size-carrying containers "
        "(std::span, std::vector::at, gsl::span). Re-run the corpus under ASan and "
        "UBSan, then fuzz the parser around the reported allocation size."
    ),
    VulnerabilityClass.STACK_BUFFER_OVERFLOW: (
        "Replace fixed stack buffers with length-checked APIs (snprintf, "
        "std::string) and compile with _FORTIFY_SOURCE=3 and stack protector. "
        "Verify every copy length against the destination capacity."
    ),
    VulnerabilityClass.GLOBAL_BUFFER_OVERFLOW: (
        "Audit indexing into global/static tables and const arrays; add explicit "
        "length parameters and static assertions where possible."
    ),
    VulnerabilityClass.BUFFER_OVERFLOW: (
        "Add explicit bounds validation before the access and use a container that "
        "tracks its own length."
    ),
    VulnerabilityClass.CONTAINER_OVERFLOW: (
        "Validate iterator/offset arithmetic before dereferencing container "
        "storage; enable libc++/libstdc++ debug modes in test builds."
    ),
    VulnerabilityClass.USE_AFTER_FREE: (
        "Tie allocation lifetime to an owning smart pointer, null out raw pointers "
        "on free, and avoid retaining references across ownership transfer. Run "
        "the reproducer under ASan with detect_leaks=1 to catch related leaks."
    ),
    VulnerabilityClass.USE_AFTER_RETURN: (
        "Never return pointers/references to stack storage. Prefer value returns "
        "or caller-provided output buffers; enable ASan "
        "detect_stack_use_after_return=1."
    ),
    VulnerabilityClass.USE_AFTER_SCOPE: (
        "Extend the lifetime of the referenced object (or copy it) so it outlives "
        "the scope where it is used."
    ),
    VulnerabilityClass.DOUBLE_FREE: (
        "Make ownership unique (std::unique_ptr with move semantics) and set raw "
        "pointers to NULL immediately after release. Audit all error paths for a "
        "second free."
    ),
    VulnerabilityClass.INVALID_FREE: (
        "Free only pointers returned by the matching allocator family; match "
        "new/delete, new[]/delete[], malloc/free. Avoid freeing interior pointers."
    ),
    VulnerabilityClass.HEAP_CORRUPTION: (
        "Treat allocator metadata corruption as a serious memory-safety defect. "
        "Reproduce under ASan, isolate the first out-of-bounds write with a "
        "hardened allocator or heap canary, and audit all writes near the "
        "reported chunk."
    ),
    VulnerabilityClass.STACK_OVERFLOW: (
        "Bound recursion depth and validate input-driven sizes before stack "
        "allocation. Consider an explicit stack budget for parser recursion."
    ),
    VulnerabilityClass.NULL_POINTER_DEREFERENCE: (
        "Usually a denial-of-service bug: validate pointers and error returns "
        "before dereference. Confirm whether an attacker can influence the "
        "pointer value before rating severity."
    ),
    VulnerabilityClass.ARITHMETIC_ERROR: (
        "Validate divisors and arithmetic ranges derived from input; enable UBSan "
        "integer checks to find related undefined behavior."
    ),
    VulnerabilityClass.ILLEGAL_INSTRUCTION: (
        "Check for corrupted control flow or unsupported CPU instructions; "
        "correlate with the runtime event log to see whether code memory was "
        "modified."
    ),
    VulnerabilityClass.UNKNOWN: (
        "No specific memory-safety class was confirmed. Re-run the reproducer on "
        "an ASan-instrumented build and capture a symbolized GDB backtrace before "
        "assigning severity."
    ),
}

_GLIBC_PATTERNS: tuple[tuple[re.Pattern[str], VulnerabilityClass, Confidence, str], ...] = (
    (
        re.compile(r"free\(\):\s*double free detected", re.IGNORECASE),
        VulnerabilityClass.DOUBLE_FREE,
        Confidence.HIGH,
        "glibc reported an explicit double free",
    ),
    (
        re.compile(r"double free or corruption", re.IGNORECASE),
        VulnerabilityClass.HEAP_CORRUPTION,
        Confidence.MEDIUM,
        "glibc reported double free or heap corruption",
    ),
    (
        re.compile(r"free\(\):\s*invalid pointer|munmap_chunk\(\):\s*invalid pointer", re.IGNORECASE),
        VulnerabilityClass.INVALID_FREE,
        Confidence.HIGH,
        "glibc reported an invalid free",
    ),
    (
        re.compile(
            r"malloc\(\):\s*(?:corrupted|invalid)|"
            r"corrupted size vs\. prev_size|"
            r"malloc_consolidate\(\)|"
            r"(?:smallbin|unsorted|largebin) double linked list corrupted",
            re.IGNORECASE,
        ),
        VulnerabilityClass.HEAP_CORRUPTION,
        Confidence.MEDIUM,
        "glibc reported corrupted heap metadata",
    ),
)


@dataclass
class GlibcEvidence:
    """Allocator diagnostic extracted from stderr."""

    vulnerability_class: VulnerabilityClass
    confidence: Confidence
    message: str


class CrashAnalyzer:
    """Turn crash :class:`RunResult` objects into :class:`CrashRecord` objects."""

    def __init__(
        self,
        *,
        gdb_bridge: GdbBridge | None = None,
        asan_parser: AsanParser | None = None,
        top_n: int = 5,
        enable_gdb: bool = True,
        gdb_timeout: float = 30.0,
    ) -> None:
        self.gdb = gdb_bridge if gdb_bridge is not None else LiveGdbBridge()
        self.asan_parser = asan_parser or AsanParser()
        self.top_n = max(1, top_n)
        self.enable_gdb = enable_gdb
        self.gdb_timeout = gdb_timeout

    # -- public API --------------------------------------------------------

    def analyze(
        self,
        run: RunResult,
        *,
        asan_text: str | None = None,
        asan_path: str | os.PathLike[str] | None = None,
        enable_gdb: bool | None = None,
        persist_evidence: bool = True,
    ) -> CrashRecord | None:
        """Analyze one crashed run.

        Returns ``None`` for NORMAL/TIMEOUT/ERROR runs — those are execution
        outcomes, not crashes. Evidence files are written next to the run
        manifest when ``persist_evidence`` is true.
        """

        if run.status is not RunStatus.CRASH:
            return None

        source_text, asan_source = self._resolve_asan_text(run, asan_text, asan_path)
        asan_finding: AsanFinding | None = None
        if source_text:
            reports = self.asan_parser.parse_all(source_text)
            asan_finding = next(
                (item for item in reports if item.sanitizer == "AddressSanitizer"),
                None,
            )
            if asan_finding is None and reports:
                # Keep non-ASan findings out of the crash record: leaks/UBSan
                # do not explain a signal termination.
                LOGGER.debug("ignoring non-ASan sanitizer report for %s", run.run_id)

        gdb_findings = self._collect_gdb(run, enable_gdb)
        glibc = self._detect_glibc(run)

        classification, vulnerability_class, confidence, evidence = self._classify(
            run, gdb_findings, asan_finding, glibc
        )
        signature = self._signature(run, gdb_findings, asan_finding)

        if persist_evidence:
            self._persist_evidence(run, gdb_findings, asan_finding, source_text)

        top_frame = gdb_findings.backtrace[0] if gdb_findings.backtrace else None
        suspected = self._suspected_root_cause(
            run, gdb_findings, asan_finding, glibc, top_frame
        )
        triage = self._triage_summary(
            run,
            classification,
            vulnerability_class,
            confidence,
            evidence,
            signature.text,
            gdb_findings,
            asan_finding,
        )

        return CrashRecord(
            run_id=run.run_id,
            timestamp=run.timestamp_start,
            input=run.input,
            crash_signature=signature.text,
            signature_hash=signature.digest,
            signature_method=signature.method,
            classification=classification,
            vulnerability_class=vulnerability_class,
            gdb=gdb_findings,
            asan=asan_finding,
            runtime_trace_ref=RuntimeTraceRef(
                run_id=run.run_id,
                timestamp_start=run.timestamp_start,
                timestamp_end=run.timestamp_end,
                batch_id=run.batch_id,
            ),
            signal=run.signal,
            exit_code=run.exit_code,
            duration_ms=run.duration_ms,
            confidence=confidence,
            reproduction_command=run.command,
            suspected_root_cause=suspected,
            mitigation_notes=_MITIGATIONS.get(
                vulnerability_class, _MITIGATIONS[VulnerabilityClass.UNKNOWN]
            ),
            triage_summary=triage,
            evidence_sources=evidence,
            batch_id=run.batch_id,
            run_dir=run.run_dir,
            timestamp_start=run.timestamp_start,
            timestamp_end=run.timestamp_end,
            schema_version=CRASH_RECORD_SCHEMA,
        )

    # -- evidence resolution ----------------------------------------------

    @staticmethod
    def _read_text(path: Path, limit: int = 4 * 1024 * 1024) -> str:
        try:
            with path.open("rb") as handle:
                return handle.read(limit).decode("utf-8", errors="replace")
        except OSError as exc:
            LOGGER.warning("cannot read %s: %s", path, exc)
            return ""

    def _resolve_asan_text(
        self,
        run: RunResult,
        asan_text: str | None,
        asan_path: str | os.PathLike[str] | None,
    ) -> tuple[str | None, str | None]:
        """Return ``(text, source_description)``."""

        if asan_path is not None:
            path = Path(asan_path)
            text = self._read_text(path)
            return (text or None), str(path)
        if asan_text is not None:
            return (asan_text or None), "supplied text"
        stderr_path = run.stderr_path()
        if not stderr_path.is_file():
            return None, None
        text = self._read_text(stderr_path)
        if "AddressSanitizer" in text or "Sanitizer:" in text:
            return text, str(stderr_path)
        return None, None

    def _collect_gdb(self, run: RunResult, enable_gdb: bool | None) -> GdbFindings:
        enabled = self.enable_gdb if enable_gdb is None else enable_gdb
        if not enabled:
            return GdbFindings(available=False, error="GDB analysis disabled")
        if not self.gdb.available:
            return GdbFindings(
                available=False,
                error=(
                    f"GDB is not available ({getattr(self.gdb, 'gdb_path', 'gdb')}); "
                    "signature falls back to sanitizer/signal evidence"
                ),
            )
        if not Path(run.binary_resolved).is_file():
            return GdbFindings(
                available=False,
                error=f"binary no longer exists: {run.binary_resolved}",
            )

        request = build_gdb_request(run, timeout=self.gdb_timeout)
        try:
            findings = self.gdb.collect(request)
        except GdbUnavailableError as exc:
            return GdbFindings(available=False, error=str(exc))
        except GdbTimeoutError as exc:
            return GdbFindings(available=True, error=str(exc))
        except GdbError as exc:
            return GdbFindings(available=True, error=str(exc))
        except Exception as exc:  # pragma: no cover - defensive around subprocess
            LOGGER.exception("unexpected GDB failure for %s", run.run_id)
            return GdbFindings(available=True, error=f"unexpected GDB failure: {exc}")
        return findings

    @staticmethod
    def _detect_glibc(run: RunResult) -> GlibcEvidence | None:
        stderr_path = run.stderr_path()
        if not stderr_path.is_file():
            return None
        text = CrashAnalyzer._read_text(stderr_path, limit=1024 * 1024)
        for pattern, vuln_class, confidence, message in _GLIBC_PATTERNS:
            if pattern.search(text):
                return GlibcEvidence(vuln_class, confidence, message)
        return None

    # -- classification ----------------------------------------------------

    @staticmethod
    def _classify(
        run: RunResult,
        gdb: GdbFindings,
        asan: AsanFinding | None,
        glibc: GlibcEvidence | None,
    ) -> tuple[Classification, VulnerabilityClass, Confidence, list[str]]:
        evidence: list[str] = ["signal" if run.signal else "exit-status"]
        if gdb.available and (gdb.crashed or gdb.backtrace):
            evidence.append("gdb")

        if asan is not None:
            evidence.append("asan")
            if asan.is_specific and asan.vulnerability_class in _CONFIRMING_ASAN_CLASSES:
                return (
                    Classification.CONFIRMED_VULNERABILITY,
                    asan.vulnerability_class,
                    Confidence.HIGH,
                    evidence,
                )
        if glibc is not None:
            evidence.append("glibc")
            return (
                Classification.CONFIRMED_VULNERABILITY,
                glibc.vulnerability_class,
                glibc.confidence,
                evidence,
            )

        signal_name = run.signal.name if run.signal else None
        if asan is not None and asan.error_type.upper() == "SEGV":
            return (
                Classification.CRASH,
                asan.vulnerability_class,
                Confidence.MEDIUM
                if asan.vulnerability_class is VulnerabilityClass.NULL_POINTER_DEREFERENCE
                else Confidence.LOW,
                evidence,
            )

        suspected = VulnerabilityClass.UNKNOWN
        confidence = Confidence.LOW
        if signal_name == "SIGFPE":
            suspected = VulnerabilityClass.ARITHMETIC_ERROR
        elif signal_name == "SIGILL":
            suspected = VulnerabilityClass.ILLEGAL_INSTRUCTION
        elif signal_name in {"SIGSEGV", "SIGBUS"}:
            fa = gdb.fault_address or (asan.fault_address if asan else None)
            if _is_near_null(fa):
                suspected = VulnerabilityClass.NULL_POINTER_DEREFERENCE
                confidence = Confidence.MEDIUM if gdb.available else Confidence.LOW
        return Classification.CRASH, suspected, confidence, evidence

    def _signature(
        self,
        run: RunResult,
        gdb: GdbFindings,
        asan: AsanFinding | None,
    ):
        if gdb.backtrace:
            return compute_signature(
                run.signal, gdb.backtrace, top_n=self.top_n, method="gdb"
            )
        if asan is not None:
            frames = asan.crash_stack or [*asan.alloc_stack, *asan.free_stack]
            if frames:
                return compute_signature(
                    run.signal,
                    frames,
                    top_n=self.top_n,
                    method="asan-stack",
                )
        pointer = gdb.fault_address or gdb.pc or (asan.fault_address if asan else None)
        return compute_signature(
            run.signal,
            None,
            fault_ip=pointer,
            top_n=self.top_n,
        )

    # -- narrative generation ---------------------------------------------

    @staticmethod
    def _suspected_root_cause(
        run: RunResult,
        gdb: GdbFindings,
        asan: AsanFinding | None,
        glibc: GlibcEvidence | None,
        top_frame: StackFrame | None,
    ) -> str:
        parts: list[str] = []
        if asan is not None:
            detail = f"AddressSanitizer reports {asan.error_type}"
            if asan.access_type and asan.access_size:
                detail += f" ({asan.access_type.upper()} of size {asan.access_size})"
            elif asan.access_type:
                detail += f" ({asan.access_type.upper()} access)"
            if asan.fault_address:
                detail += f" at {asan.fault_address}"
            if asan.region:
                detail += f"; region: {asan.region}"
            detail += "."
            parts.append(detail)
            if asan.alloc_stack:
                frame = asan.alloc_stack[0]
                parts.append(
                    f"Allocation site: {frame.function} ({frame.location or 'unknown'})."
                )
            if asan.free_stack:
                frame = asan.free_stack[0]
                parts.append(f"Free site: {frame.function} ({frame.location or 'unknown'}).")
        if glibc is not None:
            parts.append(f"{glibc.message.capitalize()}.")
        if gdb.available and gdb.crashed:
            signal = gdb.signal_name or (run.signal.name if run.signal else "signal")
            detail = f"GDB observed {signal}"
            if gdb.pc:
                detail += f" at pc {gdb.pc}"
            if gdb.fault_address:
                detail += f" with faulting address {gdb.fault_address}"
            detail += "."
            parts.append(detail)
            if top_frame is not None:
                location = top_frame.location or top_frame.module or "unknown location"
                parts.append(
                    f"Innermost frame: {top_frame.function} ({location})."
                )
        if not parts:
            label = run.signal.label if run.signal else "an abnormal exit"
            parts.append(
                f"Process terminated with {label}; no ASan or symbolic GDB evidence "
                "was available, so the root cause is not confirmed."
            )
        return " ".join(parts)

    @staticmethod
    def _triage_summary(
        run: RunResult,
        classification: Classification,
        vulnerability_class: VulnerabilityClass,
        confidence: Confidence,
        evidence: Sequence[str],
        signature_text: str,
        gdb: GdbFindings,
        asan: AsanFinding | None,
    ) -> str:
        signal_label = run.signal.label if run.signal else "fatal sanitizer exit (no signal)"
        frame = gdb.backtrace[0] if gdb.backtrace else None
        where = ""
        if frame is not None:
            where = f" in {frame.function} ({frame.location or frame.module or 'unknown'})"
        elif asan is not None and asan.crash_stack:
            top = asan.crash_stack[0]
            where = f" in {top.function} ({top.location or 'unknown'})"
        elif asan is not None:
            where = " (ASan report; no stack frames parsed)"

        lines = [
            f"{signal_label}{where}.",
            f"Signature: {signature_text}",
            f"Evidence: {', '.join(evidence)}.",
        ]
        if asan is not None:
            access = ""
            if asan.access_type and asan.access_size:
                access = f" ({asan.access_type.upper()} of size {asan.access_size})"
            elif asan.access_type:
                access = f" ({asan.access_type.upper()})"
            lines.append(f"Sanitizer: {asan.error_type}{access}.")
        if classification is Classification.CONFIRMED_VULNERABILITY:
            lines.append(
                f"Assessment: confirmed {vulnerability_class.value} "
                f"(confidence: {confidence.value})."
            )
            lines.append(
                "Next step: reproduce under the instrumented build, identify the "
                "attacker-controlled length/pointer, and assess reachability."
            )
        else:
            lines.append(
                f"Assessment: crash, unconfirmed; suspected class "
                f"{vulnerability_class.value} (confidence: {confidence.value})."
            )
            lines.append(
                "Next step: do not promote. Re-run with ASan/symbolized GDB and "
                "correlate with runtime events before rating exploitability."
            )
        return "\n".join(lines)

    # -- persistence -------------------------------------------------------

    @staticmethod
    def _persist_evidence(
        run: RunResult,
        gdb: GdbFindings,
        asan: AsanFinding | None,
        asan_text: str | None,
    ) -> None:
        run_dir = Path(run.run_dir)
        if not run_dir.is_dir():
            return
        if gdb.raw_output:
            path = run_dir / "gdb_output.txt"
            path.write_text(gdb.raw_output, encoding="utf-8")
            gdb.raw_output_path = str(path)
            gdb.raw_output = None
        if asan is not None and asan_text:
            path = run_dir / "asan_report.txt"
            path.write_text(asan_text, encoding="utf-8")
            asan.raw_output_path = str(path)


def _is_near_null(address: str | None) -> bool:
    if not address:
        return False
    try:
        return int(address, 16) < 0x1000
    except (TypeError, ValueError):
        return False


def build_gdb_request(run: RunResult, *, timeout: float = 30.0) -> GdbRequest:
    """Reconstruct the inferior invocation for a GDB rerun.

    File/argv inputs are rewritten to the run's preserved ``input.bin`` copy so
    analysis keeps working after the original corpus is moved. Environment
    overrides (LD_PRELOAD, ASAN_OPTIONS, CRASHLAB_*) are carried over.
    """

    stored = run.input_path()
    original = run.input.original_path
    args = run.argv_without_binary()

    if run.input.mode is InputMode.FILE:
        if original:
            args = [arg.replace(original, str(stored)) for arg in args]
        if stored.is_file() and str(stored) not in args:
            # Keep behavior identical even if the original argv was edited.
            args.append(str(stored))
    elif run.input.mode is InputMode.ARG:
        try:
            text = stored.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        if args:
            args[-1] = text
        else:
            args.append(text)

    env = dict(os.environ)
    env.update(run.env_overrides)
    # The debugger is not the inferior: do not propagate the target's
    # LD_PRELOAD instrumentation into gdb. Otherwise gdb itself is
    # instrumented, which pollutes the runtime-event log with gdb's own
    # allocator activity (verified in a 14k-event log where gdb ran under
    # the preload alongside the target) and can destabilize debugging.
    # Correlation variables (CRASHLAB_*) stay in place.
    env.pop("LD_PRELOAD", None)
    cwd = run.cwd if run.cwd and Path(run.cwd).is_dir() else run.run_dir
    return GdbRequest(
        binary=run.binary_resolved,
        argv=args,
        stdin_file=str(stored) if run.input.mode is InputMode.STDIN else None,
        cwd=cwd,
        timeout=timeout,
        env=env,
    )


def write_crash_record(record: CrashRecord, path: str | os.PathLike[str] | None = None) -> Path:
    """Write one ``crash_record.json`` (atomically)."""

    target = Path(path) if path is not None else Path(record.run_dir or ".") / "crash_record.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(record.to_json() + "\n", encoding="utf-8", newline="\n")
    os.replace(temporary, target)
    return target


def load_crash_record(path: str | os.PathLike[str]) -> CrashRecord:
    """Load a crash record from a file or run directory."""

    target = Path(path)
    if target.is_dir():
        target = target / "crash_record.json"
    return CrashRecord.from_dict(__import__("json").loads(target.read_text(encoding="utf-8")))


def load_crash_records(results_dir: str | os.PathLike[str]) -> list[CrashRecord]:
    """Load every per-run crash record under ``results_dir/runs``."""

    records: list[CrashRecord] = []
    for path in sorted(Path(results_dir).glob("runs/*/crash_record.json")):
        try:
            records.append(load_crash_record(path))
        except Exception as exc:  # pragma: no cover - corrupted record
            LOGGER.warning("ignoring unreadable crash record %s: %s", path, exc)
    return records


def find_asan_log(run: RunResult, asan_dir: str | os.PathLike[str]) -> Path | None:
    """Locate a separately captured ASan log for ``run``.

    Accepted names, in priority order::

        <run_id>.txt, <run_id>.asan.txt, <run_id>.log,
        <input_sha256>.txt, <input_sha256[:12]>*.txt

    The first two forms are preferred because they are unambiguous when the
    same input was run through plain and instrumented builds.
    """

    directory = Path(asan_dir)
    if not directory.is_dir():
        return None
    for name in (
        f"{run.run_id}.txt",
        f"{run.run_id}.asan.txt",
        f"{run.run_id}.log",
        f"{run.input.sha256}.txt",
    ):
        candidate = directory / name
        if candidate.is_file():
            return candidate
    for candidate in sorted(directory.glob(f"*{run.input.sha256[:12]}*")):
        if candidate.is_file():
            return candidate
    return None


def analyze_run_list(
    runs: Iterable[RunResult],
    analyzer: CrashAnalyzer,
    *,
    asan_dir: str | os.PathLike[str] | None = None,
    asan_log: str | os.PathLike[str] | None = None,
    persist: bool = True,
) -> list[CrashRecord]:
    """Analyze a concrete set of runs (used by ``run`` and ``analyze``)."""

    crashed = [run for run in runs if run.status is RunStatus.CRASH]
    if asan_log is not None and len(crashed) > 1:
        raise ValueError(
            "--asan-log is ambiguous for multiple crash records; use --asan-dir "
            "with <run_id>.<ext> files instead"
        )

    records: list[CrashRecord] = []
    for run in crashed:
        text: str | None = None
        source: Path | None = None
        if asan_log is not None:
            source = Path(asan_log)
        elif asan_dir is not None:
            source = find_asan_log(run, asan_dir)
        if source is not None and source.is_file():
            text = source.read_text(encoding="utf-8", errors="replace")
        record = analyzer.analyze(run, asan_text=text, persist_evidence=persist)
        if record is None:
            continue
        if persist:
            write_crash_record(record)
        records.append(record)
    return records


def analyze_results(
    results_dir: str | os.PathLike[str],
    analyzer: CrashAnalyzer,
    *,
    asan_dir: str | os.PathLike[str] | None = None,
    asan_log: str | os.PathLike[str] | None = None,
    persist: bool = True,
) -> list[CrashRecord]:
    """Analyze all crashed runs in a results tree and persist records.

    ``asan_log`` applies to a single run only; for batches use ``asan_dir``.
    """

    runs = discover_runs(results_dir)
    if not runs:
        return []
    records = analyze_run_list(
        runs,
        analyzer,
        asan_dir=asan_dir,
        asan_log=asan_log,
        persist=persist,
    )
    if persist and records:
        preserve_crash_groups(records, results_dir)
    return records


def preserve_crash_groups(
    records: Iterable[CrashRecord], results_dir: str | os.PathLike[str]
) -> list[CrashGroup]:
    """Copy reproducing inputs into ``results/crashes/<signature>/``.

    Inputs are always copied, never moved. Existing crash directories are
    augmented rather than deleted so earlier evidence survives a re-analysis.
    """

    records = list(records)
    groups = group_by_signature(records)
    root = Path(results_dir) / "crashes"
    root.mkdir(parents=True, exist_ok=True)

    for group in groups:
        group_dir = root / group.signature_hash
        inputs_dir = group_dir / "inputs"
        records_dir = group_dir / "records"
        inputs_dir.mkdir(parents=True, exist_ok=True)
        records_dir.mkdir(parents=True, exist_ok=True)

        for record in group.records:
            source = record.input.stored_path(record.run_dir or ".")
            if source.is_file():
                target = inputs_dir / f"{record.input.sha256[:16]}.bin"
                if not target.exists():
                    shutil.copy2(source, target)
            (records_dir / f"{record.run_id}.json").write_text(
                record.to_json() + "\n", encoding="utf-8", newline="\n"
            )

        representative = group.representative
        repro_source = representative.input.stored_path(representative.run_dir or ".")
        repro_target = group_dir / "repro_input.bin"
        if repro_source.is_file() and not repro_target.exists():
            shutil.copy2(repro_source, repro_target)

        payload = {
            "generated_at": utc_now_iso(),
            "signature_hash": group.signature_hash,
            "crash_signature": group.crash_signature,
            "classification": group.classification.value,
            "vulnerability_class": group.vulnerability_class.value,
            "confidence": group.confidence.value,
            "record_count": len(group.records),
            "unique_inputs": len(group.input_hashes),
            "input_hashes": group.input_hashes,
            "representative_run_id": representative.run_id,
            "records": [record.run_id for record in group.records],
        }
        (group_dir / "group.json").write_text(
            __import__("json").dumps(payload, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    index_payload = {
        "generated_at": utc_now_iso(),
        "schema_version": CRASH_RECORD_SCHEMA,
        "groups": [group.summary_dict() for group in groups],
    }
    (root / "groups.json").write_text(
        __import__("json").dumps(index_payload, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return groups


def analyzer_from_config(config: RunConfig) -> CrashAnalyzer:
    """Build the standard analyzer described by a :class:`RunConfig`."""

    return CrashAnalyzer(
        gdb_bridge=LiveGdbBridge(config.gdb_path),
        top_n=config.signature_frames,
        enable_gdb=config.enable_gdb,
        gdb_timeout=config.gdb_timeout,
    )
