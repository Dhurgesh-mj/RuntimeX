from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from crashlab.debugger.asan import AsanParser
from crashlab.models import (
    CRASH_RECORD_SCHEMA,
    REPORT_SCHEMA,
    REQUIRED_CRASH_RECORD_FIELDS,
    RUN_MANIFEST_SCHEMA,
    AsanFinding,
    Classification,
    Confidence,
    CrashRecord,
    GdbFindings,
    InputRef,
    InputMode,
    ReportConfig,
    RunResult,
    RunStatus,
    RuntimeTraceRef,
    SignalInfo,
    StackFrame,
    VulnerabilityClass,
    datetime_to_iso,
    group_by_signature,
    iso_to_datetime,
    sha256_bytes,
    sha256_file,
    to_jsonable,
    utc_now_iso,
)

from _helpers import load_fixture, make_record, make_run


def test_schema_constants_are_versioned() -> None:
    assert CRASH_RECORD_SCHEMA == "crashlab.crash_record/1.0"
    assert RUN_MANIFEST_SCHEMA == "crashlab.run_manifest/1.0"
    assert REPORT_SCHEMA == "crashlab.report/1.0"


def test_required_record_fields_are_all_dataclass_fields() -> None:
    from dataclasses import fields

    declared = {item.name for item in fields(CrashRecord)}
    assert set(REQUIRED_CRASH_RECORD_FIELDS) <= declared


def test_crash_record_round_trip_preserves_nested_evidence(tmp_path: Path) -> None:
    finding = AsanParser().parse(load_fixture("asan", "use_after_free.txt"))
    assert finding is not None
    record = make_record(
        classification=Classification.CONFIRMED_VULNERABILITY,
        vulnerability_class=VulnerabilityClass.USE_AFTER_FREE,
        confidence=Confidence.HIGH,
        asan=finding,
        gdb=GdbFindings(
            available=True,
            crashed=True,
            signal_name="SIGSEGV",
            signal_number=11,
            fault_address="0x602000000010",
            pc="0x401234",
            backtrace=[
                StackFrame(
                    index=0,
                    function="use_after_free",
                    file="target_demo.c",
                    line=72,
                    address="0x401234",
                )
            ],
            registers={"rip": "0x401234"},
            disassembly=["=> 0x401234 <use_after_free+4>: mov eax, DWORD PTR [rax]"],
            raw_output_path="/tmp/gdb.txt",
        ),
    )

    restored = CrashRecord.from_dict(record.to_dict())

    assert restored.run_id == record.run_id
    assert restored.classification is Classification.CONFIRMED_VULNERABILITY
    assert restored.vulnerability_class is VulnerabilityClass.USE_AFTER_FREE
    assert restored.confidence is Confidence.HIGH
    assert restored.is_confirmed is True
    assert restored.input == record.input
    assert restored.asan is not None
    assert restored.asan.free_stack[0].function == "free"
    assert restored.gdb.backtrace[0].location == "target_demo.c:72"
    assert restored.gdb.registers["rip"] == "0x401234"
    assert restored.gdb.raw_output is None
    assert restored.runtime_trace_ref is not None
    assert restored.runtime_trace_ref.timestamp_start == restored.timestamp


def test_legacy_record_without_window_falls_back_to_timestamp() -> None:
    record = make_record(timestamp="2026-02-03T04:05:06.000Z")
    payload = record.to_dict()
    del payload["timestamp_start"]
    del payload["timestamp_end"]

    restored = CrashRecord.from_dict(payload)

    assert restored.timestamp_start == restored.timestamp
    assert restored.timestamp_end == restored.timestamp
    assert restored.to_dict()["timestamp_start"] == "2026-02-03T04:05:06.000Z"


def test_run_result_round_trip_preserves_signal_and_input(tmp_path: Path) -> None:
    run = make_run(tmp_path, payload=b"ROUNDTRIP", with_signal=True)
    restored = RunResult.from_dict(run.to_dict())

    assert restored.run_id == run.run_id
    assert restored.status is RunStatus.CRASH
    assert restored.timestamp == run.timestamp_start
    assert restored.signal is not None
    assert restored.signal.name == "SIGSEGV"
    assert restored.input.mode is InputMode.STDIN
    assert restored.input.size == len(b"ROUNDTRIP")
    assert restored.input_path() == Path(run.run_dir) / "input.bin"
    assert restored.argv_without_binary() == run.argv[1:]
    assert restored.batch_id == run.batch_id


def test_run_result_tolerates_unknown_fields_and_bad_enums(tmp_path: Path) -> None:
    run = make_run(tmp_path)
    payload = run.to_dict()
    payload["unknown_future_field"] = {"ignored": True}
    payload["status"] = "not-a-real-status"

    restored = RunResult.from_dict(payload)
    assert restored.status is RunStatus.ERROR
    assert not hasattr(restored, "unknown_future_field")


def test_unknown_enum_values_fall_back_conservatively(tmp_path: Path) -> None:
    record = make_record()
    payload = record.to_dict()
    payload["classification"] = "definitely-not-valid"
    payload["vulnerability_class"] = "not-in-taxonomy"
    payload["confidence"] = "certain"

    restored = CrashRecord.from_dict(payload)
    assert restored.classification is Classification.CRASH
    assert restored.vulnerability_class is VulnerabilityClass.UNKNOWN
    assert restored.confidence is Confidence.LOW


def test_signal_info_label_and_native_status() -> None:
    info = SignalInfo(
        name="SIGSEGV",
        number=11,
        description="Access violation",
        native_status=0xC0000005,
        platform="windows",
    )
    assert info.label == "SIGSEGV (11)"
    assert SignalInfo.from_dict(info.to_dict()) == info
    assert SignalInfo.from_dict(None) is None


def test_input_ref_stored_path_and_enum_coercion() -> None:
    ref = InputRef.from_dict(
        {
            "sha256": "a" * 64,
            "size": 12,
            "mode": "file",
            "original_path": "/corpus/case.bin",
            "stored_name": "input.bin",
        }
    )
    assert ref.mode is InputMode.FILE
    assert ref.stored_path("/tmp/run") == Path("/tmp/run/input.bin")


def test_datetime_helpers_use_utc_and_accept_z_suffix() -> None:
    naive = datetime(2026, 1, 2, 3, 4, 5, 678000)
    rendered = datetime_to_iso(naive)
    assert rendered == "2026-01-02T03:04:05.678Z"
    parsed = iso_to_datetime(rendered)
    assert parsed.tzinfo is timezone.utc
    assert parsed.year == 2026 and parsed.microsecond == 678000
    assert iso_to_datetime("2026-01-02T03:04:05Z").tzinfo is timezone.utc

    now = utc_now_iso()
    assert now.endswith("Z")
    assert iso_to_datetime(now) <= datetime.now(timezone.utc)


def test_hashing_helpers(tmp_path: Path) -> None:
    payload = b"hash-me"
    path = tmp_path / "blob.bin"
    path.write_bytes(payload)
    assert sha256_bytes(payload) == sha256_file(path)
    assert len(sha256_bytes(payload)) == 64


def test_to_jsonable_handles_paths_sets_enums_and_dataclasses(tmp_path: Path) -> None:
    payload = {
        "path": tmp_path / "x.bin",
        "classification": Classification.CRASH,
        "values": {3, 1, 2},
        "nested": [SignalInfo(name="SIGSEGV", number=11)],
    }
    rendered = to_jsonable(payload)

    assert rendered["path"] == str(tmp_path / "x.bin")
    assert rendered["classification"] == "crash"
    assert sorted(rendered["values"]) == [1, 2, 3]
    assert rendered["nested"][0]["name"] == "SIGSEGV"


def test_report_config_defaults_and_serialization() -> None:
    config = ReportConfig()
    assert config.generated_at.endswith("Z")
    assert config.schema_version == REPORT_SCHEMA
    assert config.include_raw_evidence is True
    payload = config.to_dict()
    assert payload["title"] == "Crashlab crash report"


def test_group_by_signature_orders_confirmed_first_and_counts_inputs() -> None:
    confirmed = make_record(
        run_id="confirmed",
        signature_hash="aaaa",
        classification=Classification.CONFIRMED_VULNERABILITY,
        vulnerability_class=VulnerabilityClass.HEAP_BUFFER_OVERFLOW,
        confidence=Confidence.HIGH,
    )
    confirmed.input.sha256 = "b" * 64
    unconfirmed = make_record(run_id="unconfirmed", signature_hash="bbbb")
    same_group = make_record(
        run_id="confirmed-2",
        signature_hash="aaaa",
        classification=Classification.CONFIRMED_VULNERABILITY,
        vulnerability_class=VulnerabilityClass.HEAP_BUFFER_OVERFLOW,
        confidence=Confidence.HIGH,
    )

    groups = group_by_signature([unconfirmed, confirmed, same_group])

    assert [group.signature_hash for group in groups] == ["aaaa", "bbbb"]
    assert len(groups[0].records) == 2
    assert groups[0].representative.run_id == "confirmed"
    assert groups[0].input_hashes == sorted({"a" * 64, "b" * 64})
    summary = groups[0].summary_dict()
    assert summary["record_count"] == 2
    assert summary["unique_inputs"] == 2
    assert summary["classification"] == "confirmed_vulnerability"
    assert set(summary["run_ids"]) == {"confirmed", "confirmed-2"}


def test_empty_group_properties_are_conservative() -> None:
    from crashlab.models import CrashGroup

    group = CrashGroup(signature_hash="x", crash_signature="sig")
    assert group.classification is Classification.CRASH
    assert group.vulnerability_class is VulnerabilityClass.UNKNOWN
    assert group.confidence is Confidence.LOW
    assert group.input_hashes == []


def test_runtime_trace_ref_round_trip_ignores_unknown_keys() -> None:
    ref = RuntimeTraceRef(
        run_id="run-1",
        timestamp_start="2026-01-01T00:00:00.000Z",
        timestamp_end="2026-01-01T00:00:01.000Z",
        batch_id="batch-1",
    )
    payload = ref.to_dict()
    payload["future_key"] = "ignored"
    restored = RuntimeTraceRef.from_dict(payload)

    assert restored == ref
    assert "run_id" in restored.join_keys
    assert "timestamp_window" in restored.join_keys
    assert restored.producer == "person1-runtime-events"
    assert RuntimeTraceRef.from_dict(None) is None


def test_asan_finding_from_dict_rehydrates_stacks() -> None:
    payload = {
        "available": True,
        "sanitizer": "AddressSanitizer",
        "error_type": "heap-buffer-overflow",
        "vulnerability_class": "heap-buffer-overflow",
        "access_type": "write",
        "access_size": 4,
        "fault_address": "0x602000000014",
        "thread_id": 2,
        "crash_stack": [
            {"index": 0, "function": "parse", "file": "/a/demo.c", "line": 10}
        ],
        "alloc_stack": [
            {"index": 0, "function": "malloc", "module": "/lib/libc.so.6"}
        ],
        "free_stack": [],
    }
    finding = AsanFinding.from_dict(payload)
    assert finding is not None
    assert finding.vulnerability_class is VulnerabilityClass.HEAP_BUFFER_OVERFLOW
    assert finding.is_specific is True
    assert finding.crash_stack[0].location == "/a/demo.c:10"
    assert finding.alloc_stack[0].module == "/lib/libc.so.6"
    assert AsanFinding.from_dict(None) is None


@pytest.mark.parametrize(
    ("error_type", "expected"),
    [
        ("SEGV", False),
        ("FPE", False),
        ("ILL", False),
        ("unknown", False),
        ("double-free", True),
    ],
)
def test_asan_specificity_gate(error_type: str, expected: bool) -> None:
    from crashlab.debugger.asan import classify_asan_error

    finding = AsanFinding(
        error_type=error_type,
        vulnerability_class=classify_asan_error(error_type),
    )
    assert finding.is_specific is expected
