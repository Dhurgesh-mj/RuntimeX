"""Shared fixtures/helpers for the crashlab test suite."""

from __future__ import annotations

import sys
from pathlib import Path

from crashlab.debugger.gdb import GdbBridge, GdbRequest
from crashlab.models import (
    AsanFinding,
    Classification,
    Confidence,
    CrashRecord,
    GdbFindings,
    InputMode,
    InputRef,
    RunResult,
    RunStatus,
    RuntimeTraceRef,
    SignalInfo,
    VulnerabilityClass,
    sha256_bytes,
)

FIXTURES = Path(__file__).parent / "fixtures"

SIGNAL_NUMBERS = {
    "SIGSEGV": 11,
    "SIGABRT": 6,
    "SIGBUS": 7,
    "SIGFPE": 8,
    "SIGILL": 4,
    "SIGKILL": 9,
    "SIGTERM": 15,
}


def load_fixture(kind: str, name: str) -> str:
    return (FIXTURES / kind / name).read_text(encoding="utf-8")


def make_signal(name: str = "SIGSEGV", number: int | None = None) -> SignalInfo:
    return SignalInfo(
        name=name,
        number=SIGNAL_NUMBERS.get(name, number) if number is None else number,
        description=f"test {name}",
        platform="test",
    )


def make_run(
    tmp_path: Path,
    *,
    run_id: str = "20260101T000000000000_deadbeefcafe_abcd",
    status: RunStatus = RunStatus.CRASH,
    signal: SignalInfo | None = None,
    stderr_text: str = "",
    stdout_text: str = "",
    payload: bytes = b"TEST",
    input_mode: InputMode = InputMode.STDIN,
    command: str = "env CRASHLAB_RUN_ID=x ./target < input.bin",
    binary_resolved: str | None = None,
    results_root: Path | None = None,
    argv: list[str] | None = None,
    with_signal: bool = True,
) -> RunResult:
    """Create a realistic run directory + manifest under ``tmp_path``."""

    if signal is None and status is RunStatus.CRASH and with_signal:
        signal = make_signal()

    root = Path(results_root) if results_root is not None else tmp_path / "results"
    run_dir = root / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "input.bin").write_bytes(payload)
    (run_dir / "stdout.txt").write_text(stdout_text, encoding="utf-8")
    (run_dir / "stderr.txt").write_text(stderr_text, encoding="utf-8")

    original = tmp_path / "case.bin"
    if not original.exists():
        original.write_bytes(payload)

    binary = binary_resolved or sys.executable
    if argv is None:
        argv = [binary]
        if input_mode is not InputMode.STDIN:
            argv.append(str(original))

    result = RunResult(
        run_id=run_id,
        status=status,
        timestamp_start="2026-01-01T00:00:00.000Z",
        timestamp_end="2026-01-01T00:00:01.000Z",
        binary=binary,
        binary_resolved=binary,
        argv=argv,
        input=InputRef(
            sha256=sha256_bytes(payload),
            size=len(payload),
            mode=input_mode,
            original_path=str(original),
            stored_name="input.bin",
        ),
        timeout_seconds=5.0,
        duration_ms=123,
        exit_code=0 if status is RunStatus.NORMAL else None,
        signal=signal,
        command=command,
        run_dir=str(run_dir),
        env_overrides={"CRASHLAB_RUN_ID": run_id},
        host_platform="test",
    )
    (run_dir / "run_manifest.json").write_text(result.to_json(), encoding="utf-8")
    return result


def make_record(
    *,
    run_id: str = "run-1",
    signature_hash: str = "0123456789abcdef",
    crash_signature: str = "SIGSEGV | main @ demo.c:39",
    classification: Classification = Classification.CRASH,
    vulnerability_class: VulnerabilityClass = VulnerabilityClass.UNKNOWN,
    confidence: Confidence = Confidence.LOW,
    asan: AsanFinding | None = None,
    gdb: GdbFindings | None = None,
    reproduction_command: str = "./target < input.bin",
    suspected_root_cause: str = "Suspected test cause.",
    triage_summary: str = "SIGSEGV in main.\nAssessment: crash, unconfirmed.",
    mitigation_notes: str = "Add bounds checks.",
    timestamp: str = "2026-01-01T00:00:00.000Z",
    signal: SignalInfo | None = None,
    run_dir: str = ".",
) -> CrashRecord:
    return CrashRecord(
        run_id=run_id,
        timestamp=timestamp,
        input=InputRef(
            sha256="a" * 64,
            size=4,
            mode=InputMode.STDIN,
            original_path="case.bin",
            stored_name="input.bin",
        ),
        crash_signature=crash_signature,
        signature_hash=signature_hash,
        signature_method="gdb",
        classification=classification,
        vulnerability_class=vulnerability_class,
        gdb=gdb or GdbFindings(available=False, error="not collected"),
        asan=asan,
        confidence=confidence,
        reproduction_command=reproduction_command,
        suspected_root_cause=suspected_root_cause,
        mitigation_notes=mitigation_notes,
        triage_summary=triage_summary,
        runtime_trace_ref=RuntimeTraceRef(
            run_id=run_id,
            timestamp_start=timestamp,
            timestamp_end=timestamp,
        ),
        signal=signal or make_signal(),
        evidence_sources=["signal"],
        run_dir=run_dir,
        timestamp_start=timestamp,
        timestamp_end=timestamp,
    )


class FakeGdbBridge(GdbBridge):
    """Deterministic GDB bridge for analyzer tests (no live GDB)."""

    def __init__(
        self,
        findings: GdbFindings | None = None,
        *,
        available: bool = True,
        error: Exception | None = None,
    ) -> None:
        self.findings = findings or GdbFindings(
            available=True,
            crashed=True,
            signal_name="SIGSEGV",
            signal_number=11,
            fault_address="0x0",
            pc="0x401234",
            backtrace=[],
            registers={},
        )
        self._available = available
        self.error = error
        self.requests: list[GdbRequest] = []

    @property
    def available(self) -> bool:
        return self._available

    def collect(self, request: GdbRequest) -> GdbFindings:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.findings
