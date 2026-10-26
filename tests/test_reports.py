from __future__ import annotations

import json
from pathlib import Path

import pytest

from crashlab.debugger.asan import AsanParser
from crashlab.models import (
    REQUIRED_CRASH_RECORD_FIELDS,
    Classification,
    Confidence,
    ReportConfig,
    VulnerabilityClass,
)
from crashlab.reports import (
    render_html,
    render_json,
    validate_payload,
    write_html_report,
    write_json_report,
)

from _helpers import load_fixture, make_record


def asan_finding():
    finding = AsanParser().parse(load_fixture("asan", "heap_buffer_overflow.txt"))
    assert finding is not None
    return finding


def test_json_report_is_a_top_level_array_with_required_fields(tmp_path: Path) -> None:
    records = [
        make_record(run_id="run-a"),
        make_record(run_id="run-b", signature_hash="fedcba9876543210"),
    ]
    target = write_json_report(tmp_path / "report.json", records)

    payload = json.loads(target.read_text(encoding="utf-8"))
    assert isinstance(payload, list)
    assert len(payload) == 2
    assert [item["run_id"] for item in payload] == ["run-a", "run-b"]
    for item in payload:
        for field_name in REQUIRED_CRASH_RECORD_FIELDS:
            assert field_name in item
        assert item["classification"] in {"crash", "confirmed_vulnerability"}
        assert item["confidence"] in {"low", "medium", "high"}
        assert isinstance(item["input"]["sha256"], str)
        assert isinstance(item["gdb"], dict)
        assert isinstance(item["runtime_trace_ref"], dict)

    assert validate_payload(payload) == []
    assert target.read_text(encoding="utf-8").endswith("\n")


def test_render_json_round_trips_through_model(tmp_path: Path) -> None:
    from crashlab.models import CrashRecord

    record = make_record(
        classification=Classification.CONFIRMED_VULNERABILITY,
        vulnerability_class=VulnerabilityClass.HEAP_BUFFER_OVERFLOW,
        confidence=Confidence.HIGH,
        asan=asan_finding(),
    )
    payload = json.loads(render_json([record]))
    restored = CrashRecord.from_dict(payload[0])

    assert restored.run_id == record.run_id
    assert restored.classification is Classification.CONFIRMED_VULNERABILITY
    assert restored.vulnerability_class is VulnerabilityClass.HEAP_BUFFER_OVERFLOW
    assert restored.asan is not None
    assert restored.asan.error_type == "heap-buffer-overflow"
    assert restored.asan.crash_stack[0].function == "heap_overflow"
    assert restored.runtime_trace_ref is not None
    assert restored.runtime_trace_ref.run_id == record.run_id


def test_validate_payload_reports_missing_and_mistyped_fields() -> None:
    errors = validate_payload([{"run_id": 7}])
    assert any("schema_version is missing" in item for item in errors)
    assert any("run_id must be a string" in item for item in errors)
    assert validate_payload({"not": "an array"}) == [
        "report payload must be a JSON array of crash records"
    ]


def test_empty_json_report_is_an_empty_array(tmp_path: Path) -> None:
    target = write_json_report(tmp_path / "report.json", [])
    assert json.loads(target.read_text(encoding="utf-8")) == []
    assert validate_payload([]) == []


def test_html_report_is_self_contained(tmp_path: Path) -> None:
    record = make_record(run_id="run-html")
    html = render_html([record])

    assert html.startswith("<!doctype html>")
    assert "<style>" in html and "</style>" in html
    assert "<details" in html and "<summary>" in html
    assert record.crash_signature in html
    assert record.run_id in html
    assert "Window start" in html and "Window end" in html
    assert record.timestamp_start in html
    assert record.timestamp_end in html

    # No external assets or script execution.
    lowered = html.lower()
    for marker in ("<script", "<link", "@import", "src=", "http://", "https://", "url("):
        assert marker not in lowered
    assert "javascript:" not in lowered


def test_html_escapes_untrusted_evidence(tmp_path: Path) -> None:
    raw_path = tmp_path / "gdb_output.txt"
    raw_path.write_text("<script>alert('raw')</script>", encoding="utf-8")
    record = make_record(
        run_id="run-escape",
        crash_signature="SIGSEGV | <img src=x onerror=alert(1)>",
        suspected_root_cause="<b>not html</b>",
        triage_summary="<script>alert('triage')</script>",
    )
    record.gdb.raw_output_path = str(raw_path)

    html = render_html(
        [record], ReportConfig(title="<script>alert('title')</script>")
    )

    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;alert" in html
    assert "&lt;b&gt;not html&lt;/b&gt;" in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_html_raw_evidence_is_included_only_when_requested(tmp_path: Path) -> None:
    raw_path = tmp_path / "gdb_output.txt"
    raw_path.write_text("raw gdb marker", encoding="utf-8")
    record = make_record(run_id="run-raw")
    record.gdb.raw_output_path = str(raw_path)

    with_raw = render_html([record], ReportConfig(include_raw_evidence=True))
    without_raw = render_html([record], ReportConfig(include_raw_evidence=False))

    assert "raw gdb marker" in with_raw
    assert "raw gdb marker" not in without_raw


def test_html_groups_records_and_marks_confirmation(tmp_path: Path) -> None:
    confirmed = make_record(
        run_id="run-confirmed",
        signature_hash="aaaa",
        classification=Classification.CONFIRMED_VULNERABILITY,
        vulnerability_class=VulnerabilityClass.HEAP_BUFFER_OVERFLOW,
        confidence=Confidence.HIGH,
        asan=asan_finding(),
    )
    unconfirmed = make_record(
        run_id="run-unconfirmed",
        signature_hash="bbbb",
        classification=Classification.CRASH,
    )

    html = render_html([unconfirmed, confirmed])

    assert "Confirmed vulnerability" in html
    assert "Crash, unconfirmed" in html
    assert html.count("<details class=\"details-card\"") == 2
    # Confirmed group sorts first in the summary table.
    assert html.index("run-confirmed") < html.index("run-unconfirmed")
    assert "Unique signatures" in html


def test_empty_html_report_is_valid_and_explicit() -> None:
    html = render_html([], ReportConfig(title="Empty report"))

    assert "<title>Empty report</title>" in html
    assert "No crash records" in html
    assert "Crash summary" in html
    assert "<script" not in html.lower()
    assert "No signatures to display." in html


def test_html_writer_creates_parent_directories(tmp_path: Path) -> None:
    target = write_html_report(tmp_path / "nested" / "report.html", [make_record()])
    assert target.is_file()
    assert target.read_text(encoding="utf-8").startswith("<!doctype html>")


@pytest.mark.parametrize("include_raw", [True, False])
def test_html_rendering_is_deterministic(
    tmp_path: Path, include_raw: bool
) -> None:
    record = make_record(run_id="run-stable")
    config = ReportConfig(generated_at="2026-01-01T00:00:00.000Z", include_raw_evidence=include_raw)
    first = render_html([record], config)
    second = render_html([record], config)
    assert first == second
