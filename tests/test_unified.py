"""Tests for the RuntimeX unified toolkit, orchestrator, and report generator."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from runtimex.cli import main as runtimex_main
from unified_report import load_heapsentry_data, load_crashlab_data, render_unified_html


def test_doctor_command(capsys: pytest.CaptureFixture[str]) -> None:
    code = runtimex_main(["doctor"])
    assert code == 0
    captured = capsys.readouterr().out
    assert "RuntimeX Unified Security Toolkit" in captured
    assert "HeapSentry:" in captured
    assert "GDB:" in captured


def test_render_unified_html_smoke() -> None:
    hs_data = {
        "findings": [
            {
                "bug_class": "heap_buffer_overflow",
                "severity": "critical",
                "address": "0x12345678",
                "allocation_id": 1,
                "size": 32,
                "description": "Right side canary corrupted",
                "overflow_side": "right",
                "evidence": {"canary": "0xFEEDFACEDEADBEEF"},
            }
        ],
        "events": [],
        "timeline": [{"alloc_id": 1, "size": 32, "address": "0x12345678", "thread_id": 1, "fate": "overflowed"}],
        "runs": [],
        "dir": "/tmp",
    }
    cl_data = {
        "records": [
            {
                "run_id": "test_run_1",
                "crash_signature": "SIGSEGV | main @ target.c:10",
                "signature_hash": "abcd1234ef567890",
                "classification": "confirmed_vulnerability",
                "vulnerability_class": "heap-buffer-overflow",
                "confidence": "high",
                "input": {"original_path": "/tmp/test.bin"},
                "gdb": {"available": True, "backtrace": [{"index": 0, "function": "main", "file": "target.c", "line": 10}]},
            }
        ],
        "groups": [
            {
                "signature_hash": "abcd1234ef567890",
                "crash_signature": "SIGSEGV | main @ target.c:10",
                "classification": "confirmed_vulnerability",
                "vulnerability_class": "heap-buffer-overflow",
                "confidence": "high",
                "records": [
                    {
                        "run_id": "test_run_1",
                        "crash_signature": "SIGSEGV | main @ target.c:10",
                        "signature_hash": "abcd1234ef567890",
                        "classification": "confirmed_vulnerability",
                        "vulnerability_class": "heap-buffer-overflow",
                        "confidence": "high",
                        "input": {"original_path": "/tmp/test.bin"},
                        "gdb": {"available": True, "backtrace": [{"index": 0, "function": "main", "file": "target.c", "line": 10}]},
                    }
                ],
            }
        ],
        "dir": "/tmp",
    }

    html_out = render_unified_html(hs_data, cl_data, binary_name="target_test")
    assert "<!doctype html>" in html_out
    assert "RuntimeX" in html_out
    assert "target_test" in html_out
    assert "CRITICAL RISK" in html_out
    assert "abcd1234ef567890" in html_out
    assert "0xFEEDFACEDEADBEEF" in html_out


def test_unified_report_cli(tmp_path: Path) -> None:
    hs_dir = tmp_path / "hs"
    hs_dir.mkdir()
    (hs_dir / "findings.json").write_text(json.dumps([
        {
            "bug_class": "double_free",
            "severity": "critical",
            "address": "0xdeadbeef",
            "allocation_id": 5,
            "size": 64,
            "description": "Double free detected",
            "evidence": {},
        }
    ]))

    cl_dir = tmp_path / "cl"
    cl_dir.mkdir()
    (cl_dir / "report.json").write_text(json.dumps([
        {
            "run_id": "r1",
            "crash_signature": "SIGABRT | abort",
            "signature_hash": "sig123",
            "classification": "confirmed_vulnerability",
            "vulnerability_class": "double-free",
            "confidence": "high",
            "input": {"original_path": "input.bin"},
            "gdb": {},
        }
    ]))

    out_html = tmp_path / "report.html"
    out_json = tmp_path / "report.json"

    code = runtimex_main([
        "report",
        "--heapsentry", str(hs_dir),
        "--crashlab", str(cl_dir),
        "--binary", "demo_bin",
        "--out", str(out_html),
        "--out-json", str(out_json),
    ])

    assert code == 0
    assert out_html.is_file()
    assert out_json.is_file()
    assert "demo_bin" in out_html.read_text()
    data = json.loads(out_json.read_text())
    assert data["heapsentry_findings"] == 1
    assert data["crashlab_crashes"] == 1
