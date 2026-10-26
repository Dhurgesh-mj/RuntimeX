from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from crashlab.analysis import load_crash_record
from crashlab.cli import main
from crashlab.models import Classification, VulnerabilityClass

from _helpers import load_fixture, make_run

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_TARGET = PROJECT_ROOT / "examples" / "synthetic_target.py"


def write_script(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def manifests(results: Path) -> list[dict]:
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((results / "runs").glob("*/run_manifest.json"))
    ]


def run_args(
    *,
    target: Path,
    input_file: Path,
    results: Path,
    extra: list[str] | None = None,
) -> list[str]:
    args = [
        "run",
        "--binary",
        sys.executable,
        "--binary-arg",
        str(target),
        "--input",
        str(input_file),
        "--out",
        str(results),
        "--timeout",
        "5",
        "--no-gdb",
    ]
    args.extend(extra or [])
    return args


def test_doctor_reports_platform_and_capabilities(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["doctor"])
    output = capsys.readouterr().out

    assert code == 0
    assert "crashlab 0.1.0" in output
    assert "python:" in output
    assert "platform:" in output
    assert "LD_PRELOAD:" in output
    assert "ASan runtime:" in output


def test_run_normal_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    script = write_script(
        tmp_path,
        "normal.py",
        "import sys\nprint('bytes:' + str(len(sys.stdin.buffer.read())))\n",
    )
    case = tmp_path / "case.bin"
    case.write_bytes(b"NORMAL")
    results = tmp_path / "results"

    code = main(run_args(target=script, input_file=case, results=results))

    assert code == 0
    assert "1 normal" in capsys.readouterr().out
    payloads = manifests(results)
    assert len(payloads) == 1
    assert payloads[0]["status"] == "normal"
    assert payloads[0]["input"]["size"] == len(b"NORMAL")
    run_dir = (results / "runs").iterdir().__next__()
    assert (run_dir / "input.bin").read_bytes() == b"NORMAL"
    assert "bytes:6" in (run_dir / "stdout.txt").read_text(encoding="utf-8")


def test_run_crash_analyze_and_report_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    case = tmp_path / "crash.bin"
    case.write_bytes(b"H\n")
    results = tmp_path / "results"
    json_report = tmp_path / "run-report.json"
    html_report = tmp_path / "run-report.html"

    code = main(
        run_args(
            target=SYNTHETIC_TARGET,
            input_file=case,
            results=results,
            extra=[
                "--report-json",
                str(json_report),
                "--report-html",
                str(html_report),
            ],
        )
    )

    assert code == 0
    assert manifests(results)[0]["status"] == "crash"
    record = load_crash_record(next((results / "runs").iterdir()))
    assert record.classification is Classification.CRASH
    assert record.is_confirmed is False
    assert "unconfirmed" in record.triage_summary.lower()
    assert json.loads(json_report.read_text(encoding="utf-8"))[0]["run_id"] == record.run_id
    assert "Crash, unconfirmed" in html_report.read_text(encoding="utf-8")

    # Standalone report command rebuilds from saved records.
    report_json = tmp_path / "report.json"
    report_html = tmp_path / "report.html"
    code = main(
        [
            "report",
            "--results",
            str(results),
            "--json",
            str(report_json),
            "--html",
            str(report_html),
            "--title",
            "Custom report title",
        ]
    )
    assert code == 0
    assert json.loads(report_json.read_text(encoding="utf-8"))[0]["run_id"] == record.run_id
    html = report_html.read_text(encoding="utf-8")
    assert "Custom report title" in html
    assert record.run_id in html

    # Re-analysis of the persisted run keeps the record loadable.
    code = main(["analyze", "--results", str(results), "--no-gdb"])
    assert code == 0
    reanalyzed = load_crash_record(next((results / "runs").iterdir()))
    assert reanalyzed.run_id == record.run_id
    assert (results / "crashes" / reanalyzed.signature_hash / "group.json").is_file()


def test_fail_on_crash_returns_exit_code_three(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    case = tmp_path / "crash.bin"
    case.write_bytes(b"H\n")
    results = tmp_path / "results"

    code = main(
        run_args(
            target=SYNTHETIC_TARGET,
            input_file=case,
            results=results,
            extra=["--fail-on-crash", "--no-analyze"],
        )
    )

    assert code == 3
    assert manifests(results)[0]["status"] == "crash"


def test_asan_report_is_confirmed_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    case = tmp_path / "asan.bin"
    case.write_bytes(b"A\n")
    results = tmp_path / "results"

    code = main(
        run_args(
            target=SYNTHETIC_TARGET,
            input_file=case,
            results=results,
            extra=["--report-html", str(tmp_path / "asan.html")],
        )
    )

    assert code == 0
    manifest = manifests(results)[0]
    assert manifest["status"] == "crash"
    assert manifest["signal"] is None
    assert "sanitizer" in manifest["error"]

    record = load_crash_record(next((results / "runs").iterdir()))
    assert record.classification is Classification.CONFIRMED_VULNERABILITY
    assert record.vulnerability_class is VulnerabilityClass.HEAP_BUFFER_OVERFLOW
    assert record.asan is not None and record.asan.error_type == "heap-buffer-overflow"
    assert "asan" in record.evidence_sources
    assert (Path(record.run_dir) / "asan_report.txt").is_file()

    html = (tmp_path / "asan.html").read_text(encoding="utf-8")
    assert "Confirmed vulnerability" in html
    assert "heap-buffer-overflow" in html


def test_batch_mode_runs_every_input_with_workers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a_normal.bin").write_bytes(b"N\n")
    (corpus / "b_crash.bin").write_bytes(b"H\n")
    results = tmp_path / "results"

    code = main(
        [
            "run",
            "--binary",
            sys.executable,
            "--binary-arg",
            str(SYNTHETIC_TARGET),
            "--input-dir",
            str(corpus),
            "--out",
            str(results),
            "--workers",
            "2",
            "--timeout",
            "5",
            "--no-gdb",
            "--no-analyze",
        ]
    )

    assert code == 0
    payloads = manifests(results)
    assert len(payloads) == 2
    statuses = sorted(item["status"] for item in payloads)
    assert statuses == ["crash", "normal"]


def test_config_file_supplies_run_and_report_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    script = write_script(tmp_path, "normal.py", "print('configured')\n")
    case = tmp_path / "case.bin"
    case.write_bytes(b"N\n")
    config = tmp_path / "crashlab.toml"
    config.write_text(
        "[run]\n"
        f"binary = '{Path(sys.executable).as_posix()}'\n"
        f"extra_args = ['{script.as_posix()}']\n"
        "timeout = 5.0\n"
        "enable_gdb = false\n"
        "results_dir = 'configured-results'\n"
        "\n[report]\n"
        "title = 'Configured title'\n"
        "subtitle = 'Configured subtitle'\n",
        encoding="utf-8",
    )

    code = main(
        ["run", "--config", str(config), "--input", str(case), "--timeout", "5"]
    )
    assert code == 0
    results = tmp_path / "configured-results"
    assert manifests(results)[0]["status"] == "normal"

    # A crash is needed before the report command can load records.
    crash = tmp_path / "crash.bin"
    crash.write_bytes(b"H\n")
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            f"extra_args = ['{script.as_posix()}']",
            f"extra_args = ['{SYNTHETIC_TARGET.as_posix()}']",
        ),
        encoding="utf-8",
    )
    code = main(["run", "--config", str(config), "--input", str(crash)])
    assert code == 0

    code = main(["report", "--config", str(config)])
    assert code == 0
    html = (results / "report.html").read_text(encoding="utf-8")
    assert "<title>Configured title</title>" in html
    assert "Configured subtitle" in html
    assert (results / "report.json").is_file()


def test_cli_reports_usage_errors_without_tracebacks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)

    assert main(["report", "--results", str(tmp_path / "empty")]) == 1
    assert "No crash records found" in capsys.readouterr().err

    assert main(["analyze", "--results", str(tmp_path / "empty")]) == 1
    assert "No run manifests found" in capsys.readouterr().err

    assert main(["run"]) == 2
    assert "no target binary configured" in capsys.readouterr().err

    missing = tmp_path / "missing.bin"
    code = main(
        [
            "run",
            "--binary",
            sys.executable,
            "--input",
            str(missing),
            "--out",
            str(tmp_path / "results"),
        ]
    )
    assert code == 2
    assert "input file not found" in capsys.readouterr().err

    case = tmp_path / "case.bin"
    case.write_bytes(b"H\n")
    code = main(
        run_args(
            target=SYNTHETIC_TARGET,
            input_file=case,
            results=tmp_path / "results2",
            extra=["--no-analyze", "--report-json", str(tmp_path / "nope.json")],
        )
    )
    assert code == 2
    assert "require analysis" in capsys.readouterr().err


def test_ambiguous_asan_log_for_batch_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    make_run(tmp_path, run_id="run-a", payload=b"a", stderr_text="")
    make_run(tmp_path, run_id="run-b", payload=b"b", stderr_text="")
    asan_log = tmp_path / "one.log"
    asan_log.write_text(load_fixture("asan", "heap_buffer_overflow.txt"), encoding="utf-8")

    code = main(
        [
            "analyze",
            "--results",
            str(tmp_path / "results"),
            "--no-gdb",
            "--asan-log",
            str(asan_log),
        ]
    )

    assert code == 2
    assert "ambiguous" in capsys.readouterr().err


def test_analyze_single_run_uses_its_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    run = make_run(
        tmp_path,
        run_id="single-run",
        payload=b"asan",
        stderr_text=load_fixture("asan", "use_after_free.txt"),
    )

    code = main(
        [
            "analyze",
            "--run",
            str(Path(run.run_dir)),
            "--results",
            str(tmp_path / "results"),
            "--no-gdb",
        ]
    )

    assert code == 0
    assert "1 crash" in capsys.readouterr().out
    record = load_crash_record(Path(run.run_dir))
    assert record.classification is Classification.CONFIRMED_VULNERABILITY
    assert record.vulnerability_class is VulnerabilityClass.USE_AFTER_FREE
