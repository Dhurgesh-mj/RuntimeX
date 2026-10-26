from __future__ import annotations

from pathlib import Path

from crashlab.analysis import (
    CrashAnalyzer,
    build_gdb_request,
    preserve_crash_groups,
    write_crash_record,
)
from crashlab.debugger.gdb import (
    GdbOutputParser,
    GdbTimeoutError,
    GdbUnavailableError,
)
from crashlab.models import (
    Classification,
    Confidence,
    GdbFindings,
    InputMode,
    RunStatus,
    StackFrame,
    VulnerabilityClass,
    group_by_signature,
)

from _helpers import FakeGdbBridge, load_fixture, make_run


def gdb_findings(address: str = "0x5555555551c4") -> GdbFindings:
    findings = GdbOutputParser().parse(load_fixture("gdb", "heap_overflow.txt"))
    findings.backtrace[0].address = address
    return findings


def test_asan_evidence_confirms_and_keeps_both_sources(tmp_path: Path) -> None:
    run = make_run(
        tmp_path,
        stderr_text=load_fixture("asan", "heap_buffer_overflow.txt"),
    )
    analyzer = CrashAnalyzer(gdb_bridge=FakeGdbBridge(gdb_findings()))
    record = analyzer.analyze(run)

    assert record is not None
    assert record.classification is Classification.CONFIRMED_VULNERABILITY
    assert record.vulnerability_class is VulnerabilityClass.HEAP_BUFFER_OVERFLOW
    assert record.confidence is Confidence.HIGH
    assert record.asan is not None
    assert record.asan.error_type == "heap-buffer-overflow"
    assert record.gdb.crashed is True
    assert record.signature_method == "gdb"
    assert "asan" in record.evidence_sources and "gdb" in record.evidence_sources
    assert record.runtime_trace_ref is not None
    assert record.runtime_trace_ref.run_id == run.run_id
    assert record.timestamp_start == run.timestamp_start
    assert record.timestamp_end == run.timestamp_end
    assert record.runtime_trace_ref.timestamp_start == run.timestamp_start
    assert record.runtime_trace_ref.timestamp_end == run.timestamp_end
    assert record.reproduction_command == run.command

    run_dir = Path(run.run_dir)
    assert (run_dir / "gdb_output.txt").is_file()
    assert (run_dir / "asan_report.txt").is_file()
    assert record.gdb.raw_output is None
    assert record.gdb.raw_output_path is not None
    assert record.asan.raw_output_path is not None


def test_bare_sigsegv_is_never_promoted(tmp_path: Path) -> None:
    findings = GdbFindings(
        available=True,
        crashed=True,
        signal_name="SIGSEGV",
        signal_number=11,
        fault_address="0x0",
        pc="0x401234",
        backtrace=[
            StackFrame(
                index=0,
                function="main",
                file="demo.c",
                line=10,
                address="0x401234",
            )
        ],
    )
    run = make_run(tmp_path, stderr_text="")
    record = CrashAnalyzer(gdb_bridge=FakeGdbBridge(findings)).analyze(run)

    assert record is not None
    assert record.classification is Classification.CRASH
    assert record.confidence is Confidence.MEDIUM
    assert record.vulnerability_class is VulnerabilityClass.NULL_POINTER_DEREFERENCE
    assert "unconfirmed" in record.triage_summary.lower()
    assert record.asan is None


def test_asan_segv_remains_unconfirmed(tmp_path: Path) -> None:
    run = make_run(tmp_path, stderr_text=load_fixture("asan", "segv_null.txt"))
    record = CrashAnalyzer(
        gdb_bridge=FakeGdbBridge(available=False), enable_gdb=False
    ).analyze(run)

    assert record is not None
    assert record.classification is Classification.CRASH
    assert record.vulnerability_class is VulnerabilityClass.NULL_POINTER_DEREFERENCE
    assert record.confidence is Confidence.MEDIUM
    assert record.signature_method == "asan-stack"


def test_glibc_double_free_is_confirmed_medium_high(tmp_path: Path) -> None:
    run = make_run(tmp_path, stderr_text="free(): double free detected in tcache 2\n")
    record = CrashAnalyzer(gdb_bridge=FakeGdbBridge(available=False)).analyze(run)

    assert record is not None
    assert record.classification is Classification.CONFIRMED_VULNERABILITY
    assert record.vulnerability_class is VulnerabilityClass.DOUBLE_FREE
    assert record.confidence is Confidence.HIGH
    assert "glibc" in record.evidence_sources


def test_glibc_ambiguous_corruption_is_confirmed_medium(tmp_path: Path) -> None:
    run = make_run(tmp_path, stderr_text="double free or corruption (out)\n")
    record = CrashAnalyzer(gdb_bridge=FakeGdbBridge(available=False)).analyze(run)
    assert record is not None
    assert record.classification is Classification.CONFIRMED_VULNERABILITY
    assert record.vulnerability_class is VulnerabilityClass.HEAP_CORRUPTION
    assert record.confidence is Confidence.MEDIUM


def test_no_evidence_stays_unconfirmed(tmp_path: Path) -> None:
    run = make_run(tmp_path, stderr_text="")
    record = CrashAnalyzer(gdb_bridge=FakeGdbBridge(available=False)).analyze(run)
    assert record is not None
    assert record.classification is Classification.CRASH
    assert record.vulnerability_class is VulnerabilityClass.UNKNOWN
    assert record.confidence is Confidence.LOW
    assert "not confirmed" in record.suspected_root_cause.lower()


def test_asan_exit_without_signal_uses_asan_stack(tmp_path: Path) -> None:
    run = make_run(
        tmp_path,
        signal=None,
        with_signal=False,
        status=RunStatus.CRASH,
        stderr_text=load_fixture("asan", "heap_buffer_overflow.txt"),
    )
    record = CrashAnalyzer(
        gdb_bridge=FakeGdbBridge(available=False), enable_gdb=False
    ).analyze(run)
    assert record is not None
    assert record.signal is None
    assert record.classification is Classification.CONFIRMED_VULNERABILITY
    assert record.signature_method == "asan-stack"
    assert record.vulnerability_class is VulnerabilityClass.HEAP_BUFFER_OVERFLOW


def test_supplied_asan_text_is_persisted(tmp_path: Path) -> None:
    run = make_run(tmp_path, stderr_text="")
    text = load_fixture("asan", "use_after_free.txt")
    record = CrashAnalyzer(
        gdb_bridge=FakeGdbBridge(available=False), enable_gdb=False
    ).analyze(run, asan_text=text)
    assert record is not None and record.asan is not None
    saved = Path(run.run_dir) / "asan_report.txt"
    assert saved.read_text(encoding="utf-8") == text
    assert record.asan.raw_output_path == str(saved)


def test_gdb_timeout_is_recorded_not_raised(tmp_path: Path) -> None:
    run = make_run(tmp_path)
    bridge = FakeGdbBridge(error=GdbTimeoutError("timed out"))
    record = CrashAnalyzer(gdb_bridge=bridge).analyze(run)
    assert record is not None
    assert record.gdb.available is True
    assert record.gdb.error == "timed out"
    assert record.classification is Classification.CRASH


def test_gdb_unavailable_is_recorded(tmp_path: Path) -> None:
    run = make_run(tmp_path)
    bridge = FakeGdbBridge(error=GdbUnavailableError("missing gdb"))
    record = CrashAnalyzer(gdb_bridge=bridge).analyze(run)
    assert record is not None
    assert record.gdb.available is False
    assert "missing gdb" in (record.gdb.error or "")


def test_aslr_differences_group_together(tmp_path: Path) -> None:
    first_run = make_run(tmp_path, run_id="run-a", payload=b"A", stderr_text="")
    second_run = make_run(tmp_path, run_id="run-b", payload=b"B", stderr_text="")

    analyzer = CrashAnalyzer(gdb_bridge=FakeGdbBridge(gdb_findings("0x1111")))
    first = analyzer.analyze(first_run)
    analyzer = CrashAnalyzer(gdb_bridge=FakeGdbBridge(gdb_findings("0xffff")))
    second = analyzer.analyze(second_run)

    assert first is not None and second is not None
    assert first.signature_hash == second.signature_hash
    assert len(group_by_signature([first, second])) == 1


def test_non_crash_returns_none(tmp_path: Path) -> None:
    run = make_run(tmp_path, status=RunStatus.NORMAL, signal=None)
    assert CrashAnalyzer(gdb_bridge=FakeGdbBridge()).analyze(run) is None


def test_preserve_crash_groups_copies_inputs(tmp_path: Path) -> None:
    run = make_run(tmp_path, payload=b"BUG", stderr_text="")
    record = CrashAnalyzer(gdb_bridge=FakeGdbBridge(available=False)).analyze(run)
    assert record is not None
    results = tmp_path / "results"
    groups = preserve_crash_groups([record], results)

    assert len(groups) == 1
    group_dir = results / "crashes" / record.signature_hash
    assert (group_dir / "repro_input.bin").read_bytes() == b"BUG"
    assert (group_dir / "inputs" / f"{record.input.sha256[:16]}.bin").is_file()
    assert (group_dir / "records" / f"{run.run_id}.json").is_file()
    assert (group_dir / "group.json").is_file()
    assert (results / "crashes" / "groups.json").is_file()
    # Original preserved input remains untouched (copy, never move).
    assert (Path(run.run_dir) / "input.bin").read_bytes() == b"BUG"


def test_write_and_load_crash_record(tmp_path: Path) -> None:
    from crashlab.analysis import load_crash_record

    run = make_run(tmp_path)
    record = CrashAnalyzer(gdb_bridge=FakeGdbBridge(available=False)).analyze(run)
    assert record is not None
    path = write_crash_record(record, tmp_path / "record.json")
    loaded = load_crash_record(path)
    assert loaded.run_id == record.run_id
    assert loaded.classification is record.classification


def test_build_gdb_request_rewrites_file_input_to_copy(tmp_path: Path) -> None:
    run = make_run(tmp_path, input_mode=InputMode.FILE, payload=b"FILE")
    request = build_gdb_request(run)
    stored = str(Path(run.run_dir) / "input.bin")
    assert request.argv[-1] == stored
    assert request.stdin_file is None
    assert request.binary == run.binary_resolved
    assert request.env["CRASHLAB_RUN_ID"] == run.run_id


def test_build_gdb_request_uses_stdin_copy(tmp_path: Path) -> None:
    run = make_run(tmp_path, input_mode=InputMode.STDIN)
    request = build_gdb_request(run)
    assert request.stdin_file == str(Path(run.run_dir) / "input.bin")
    assert request.argv == []
