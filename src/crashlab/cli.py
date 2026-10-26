"""Command-line interface: ``crashlab run|analyze|report|doctor``."""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Iterable, Sequence

from crashlab import __version__
from crashlab.analysis import (
    analyze_run_list,
    analyzer_from_config,
    load_crash_records,
    preserve_crash_groups,
)
from crashlab.config import (
    ConfigError,
    discover_config,
    load_report_config,
    load_run_config,
)
from crashlab.debugger import LiveGdbBridge
from crashlab.logging_setup import configure_logging
from crashlab.models import (
    CrashGroup,
    CrashRecord,
    InputMode,
    ReportConfig,
    RunResult,
    RunStatus,
    group_by_signature,
    utc_now_iso,
)
from crashlab.reports import write_html_report, write_json_report
from crashlab.runner import (
    RunnerError,
    TestRunner,
    discover_runs,
    load_run_result,
    make_batch_id,
)
from crashlab.signatures import describe_group

LOGGER = logging.getLogger("crashlab.cli")


class CliError(RuntimeError):
    """User-facing CLI error (exit code 2)."""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _add_logging_flags(parser: argparse.ArgumentParser, *, suppress_defaults: bool = False) -> None:
    default = argparse.SUPPRESS if suppress_defaults else False
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=default, help="debug logging"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", default=default, help="errors only"
    )


def _add_gdb_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--gdb-path", dest="gdb_path", default=None, help="GDB executable")
    parser.add_argument(
        "--gdb",
        dest="enable_gdb",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable/disable GDB analysis (default: enabled)",
    )
    parser.add_argument("--gdb-timeout", dest="gdb_timeout", type=float, default=None)
    parser.add_argument("--signature-frames", dest="signature_frames", type=int, default=None)


def _add_analysis_input_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--asan-dir",
        default=None,
        help="directory of separately captured ASan logs named <run_id>.*",
    )
    parser.add_argument(
        "--asan-log",
        default=None,
        help="single ASan report file (ambiguous for batches; use --asan-dir)",
    )


def _add_report_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--report-json", default=None, help="write JSON report to this path")
    parser.add_argument("--report-html", default=None, help="write HTML report to this path")
    parser.add_argument("--title", default=None, help="report title override")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crashlab",
        description=(
            "Reproducible crash detection and exploitability triage for local test "
            "binaries. Defensive research tooling only."
        ),
        epilog=(
            "Examples:\n"
            "  crashlab run --binary ./target --input ./corpus/case1.bin --timeout 5\n"
            "  crashlab run --binary ./target --input-dir ./corpus --workers 4\n"
            "  crashlab analyze --results results --gdb-path /usr/bin/gdb\n"
            "  crashlab report --results results --json report.json --html report.html"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"crashlab {__version__}")
    _add_logging_flags(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # -- run -------------------------------------------------------------
    run_parser = subparsers.add_parser(
        "run", help="execute a binary against one input or a corpus directory"
    )
    _add_logging_flags(run_parser, suppress_defaults=True)
    run_parser.add_argument("--binary", default=None, help="path to the test binary")
    run_parser.add_argument(
        "--input", action="append", default=None, help="input file (repeatable)"
    )
    run_parser.add_argument(
        "--input-dir", action="append", default=None, help="directory of inputs (repeatable)"
    )
    run_parser.add_argument("--preload", default=None, help="LD_PRELOAD library (POSIX only)")
    run_parser.add_argument("--timeout", type=float, default=None, help="per-run timeout (s)")
    run_parser.add_argument("--workers", type=int, default=None, help="parallel workers")
    run_parser.add_argument(
        "--input-mode",
        choices=[mode.value for mode in InputMode],
        default=None,
        help="deliver input via stdin, file path, or argv (default: stdin)",
    )
    run_parser.add_argument(
        "--arg-template",
        default=None,
        help="single argv template; {input} is replaced by the path/text",
    )
    run_parser.add_argument(
        "--binary-arg",
        action="append",
        dest="binary_arg",
        default=None,
        help="extra argument passed to the target (repeatable)",
    )
    run_parser.add_argument("--cwd", default=None, help="working directory for the child")
    run_parser.add_argument(
        "--out", dest="results_dir", default=None, help="results directory (default: results)"
    )
    run_parser.add_argument("--config", default=None, help="TOML config path")
    run_parser.add_argument(
        "--asan-options", dest="asan_options", default=None, help="ASAN_OPTIONS value"
    )
    run_parser.add_argument(
        "--no-analyze", action="store_true", help="skip crash analysis after running"
    )
    run_parser.add_argument(
        "--fail-on-crash",
        action="store_true",
        help="exit 3 when any crash/timeout was observed",
    )
    _add_gdb_flags(run_parser)
    _add_analysis_input_flags(run_parser)
    _add_report_flags(run_parser)
    run_parser.set_defaults(func=cmd_run)

    # -- analyze ---------------------------------------------------------
    analyze_parser = subparsers.add_parser(
        "analyze", help="re-run GDB/ASan analysis over saved runs"
    )
    _add_logging_flags(analyze_parser, suppress_defaults=True)
    analyze_parser.add_argument(
        "--results", dest="results_dir", default=None, help="results directory"
    )
    analyze_parser.add_argument(
        "--run",
        action="append",
        default=None,
        help="re-analyze only this run directory/manifest (repeatable)",
    )
    analyze_parser.add_argument("--config", default=None, help="TOML config path")
    _add_gdb_flags(analyze_parser)
    _add_analysis_input_flags(analyze_parser)
    _add_report_flags(analyze_parser)
    analyze_parser.set_defaults(func=cmd_analyze)

    # -- report ----------------------------------------------------------
    report_parser = subparsers.add_parser(
        "report", help="render JSON and/or HTML from saved crash records"
    )
    _add_logging_flags(report_parser, suppress_defaults=True)
    report_parser.add_argument(
        "--results", dest="results_dir", default=None, help="results directory"
    )
    report_parser.add_argument("--json", dest="json_path", default=None, help="JSON output path ('-' for stdout)")
    report_parser.add_argument("--html", dest="html_path", default=None, help="HTML output path ('-' for stdout)")
    report_parser.add_argument("--title", default=None)
    report_parser.add_argument("--subtitle", default=None)
    report_parser.add_argument(
        "--no-raw-evidence",
        action="store_true",
        help="omit raw ASan/GDB text from the HTML report",
    )
    report_parser.add_argument("--config", default=None, help="TOML config path")
    report_parser.set_defaults(func=cmd_report)

    # -- doctor ----------------------------------------------------------
    doctor_parser = subparsers.add_parser(
        "doctor", help="show platform/GDB/ASan capability diagnostics"
    )
    _add_logging_flags(doctor_parser, suppress_defaults=True)
    doctor_parser.add_argument("--config", default=None, help="TOML config path")
    doctor_parser.add_argument("--gdb-path", dest="gdb_path", default=None)
    doctor_parser.set_defaults(func=cmd_doctor)

    return parser


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _config_path(args: argparse.Namespace) -> Path | None:
    return discover_config(getattr(args, "config", None))


def _run_overrides(args: argparse.Namespace) -> dict[str, object]:
    mapping = {
        "binary": "binary",
        "preload": "preload",
        "timeout": "timeout",
        "results_dir": "results_dir",
        "input_mode": "input_mode",
        "workers": "workers",
        "cwd": "cwd",
        "arg_template": "arg_template",
        "asan_options": "asan_options",
        "gdb_path": "gdb_path",
        "enable_gdb": "enable_gdb",
        "gdb_timeout": "gdb_timeout",
        "signature_frames": "signature_frames",
    }
    overrides: dict[str, object] = {}
    for arg_name, config_name in mapping.items():
        value = getattr(args, arg_name, None)
        if value is not None:
            overrides[config_name] = value
    if getattr(args, "binary_arg", None):
        overrides["extra_args"] = list(args.binary_arg)
    return overrides


def _collect_inputs(explicit: Sequence[str] | None, directories: Sequence[str] | None) -> list[Path]:
    inputs: list[Path] = []
    seen: set[Path] = set()

    def add(path: Path) -> None:
        resolved = path.expanduser().resolve()
        if resolved not in seen:
            seen.add(resolved)
            inputs.append(resolved)

    for item in explicit or []:
        path = Path(item)
        if not path.is_file():
            raise CliError(f"input file not found: {path}")
        add(path)
    for item in directories or []:
        directory = Path(item).expanduser()
        if not directory.is_dir():
            raise CliError(f"input directory not found: {directory}")
        files = sorted(
            child for child in directory.iterdir() if child.is_file() and not child.name.startswith(".")
        )
        if not files:
            raise CliError(f"input directory contains no files: {directory}")
        for child in files:
            add(child)
    if not inputs:
        raise CliError("no inputs supplied; use --input FILE and/or --input-dir DIR")
    return inputs


def _progress_printer() -> tuple[threading.Lock, object]:
    lock = threading.Lock()

    def emit(run: RunResult) -> None:
        signal = run.signal.name if run.signal else "-"
        name = Path(run.input.original_path).name if run.input.original_path else "(payload)"
        with lock:
            print(
                f"  {run.status.value:<7} {run.run_id}  signal={signal:<8} "
                f"exit={str(run.exit_code):<6} {name}",
                flush=True,
            )

    return lock, emit


def _status_counts(results: Iterable[RunResult]) -> Counter[RunStatus]:
    return Counter(run.status for run in results)


def _print_run_summary(results: Sequence[RunResult]) -> None:
    counts = _status_counts(results)
    total = len(results)
    print(
        f"Ran {total} input(s): "
        f"{counts.get(RunStatus.NORMAL, 0)} normal, "
        f"{counts.get(RunStatus.CRASH, 0)} crash, "
        f"{counts.get(RunStatus.TIMEOUT, 0)} timeout, "
        f"{counts.get(RunStatus.ERROR, 0)} error."
    )


def _print_groups(groups: Sequence[CrashGroup]) -> None:
    if not groups:
        print("No crash groups.")
        return
    print(f"Crash groups ({len(groups)}):")
    for group in groups:
        print(f"  {describe_group(group)}")
        print(f"    {group.crash_signature}")


def _report_config(args: argparse.Namespace, config_path: Path | None) -> ReportConfig:
    overrides: dict[str, object] = {}
    if getattr(args, "title", None):
        overrides["title"] = args.title
    if getattr(args, "subtitle", None):
        overrides["subtitle"] = args.subtitle
    if getattr(args, "no_raw_evidence", False):
        overrides["include_raw_evidence"] = False
    config = load_report_config(config_path, overrides)
    if not config.generated_at:
        config.generated_at = utc_now_iso()
    return config


def _write_reports(
    records: Sequence[CrashRecord],
    *,
    json_path: str | None,
    html_path: str | None,
    config: ReportConfig,
) -> None:
    if json_path:
        if json_path == "-":
            from crashlab.reports import render_json

            print(render_json(records))
        else:
            target = write_json_report(json_path, records, config=config)
            print(f"JSON report: {target}")
    if html_path:
        if html_path == "-":
            from crashlab.reports import render_html

            print(render_html(records, config))
        else:
            target = write_html_report(html_path, records, config=config)
            print(f"HTML report: {target}")


def _merge_records(*collections: Iterable[CrashRecord]) -> list[CrashRecord]:
    by_id: dict[str, CrashRecord] = {}
    for collection in collections:
        for record in collection:
            by_id[record.run_id] = record
    return sorted(by_id.values(), key=lambda item: item.timestamp)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_run(args: argparse.Namespace) -> int:
    config_path = _config_path(args)
    config = load_run_config(config_path, _run_overrides(args))
    if not config.binary:
        raise CliError("no target binary configured; pass --binary PATH or set [run] binary")

    inputs = _collect_inputs(args.input, args.input_dir)
    runner = TestRunner(config)
    batch_id = make_batch_id()
    _, progress = _progress_printer()

    print(
        f"crashlab: {len(inputs)} input(s), binary={config.binary}, "
        f"timeout={config.timeout:g}s, workers={config.workers}"
    )

    started = time.perf_counter()
    if len(inputs) == 1:
        results = [runner.run_one(inputs[0], batch_id=batch_id, progress=progress)]
    else:
        results = runner.run_batch(
            inputs, workers=config.workers, batch_id=batch_id, progress=progress
        )
    elapsed = time.perf_counter() - started
    if not results:
        raise CliError("no runs completed (see messages above)")
    print(f"Finished in {elapsed:.2f}s")
    _print_run_summary(results)

    all_records: list[CrashRecord] = []
    groups: list[CrashGroup] = []
    if not args.no_analyze:
        crashed = [run for run in results if run.status is RunStatus.CRASH]
        if crashed:
            analyzer = analyzer_from_config(config)
            records = analyze_run_list(
                crashed,
                analyzer,
                asan_dir=args.asan_dir,
                asan_log=args.asan_log,
            )
            all_records = _merge_records(load_crash_records(runner.results_dir), records)
            if all_records:
                groups = preserve_crash_groups(all_records, runner.results_dir)
        else:
            all_records = load_crash_records(runner.results_dir)
        _print_groups(groups)

    if args.report_json or args.report_html:
        if args.no_analyze:
            raise CliError("--report-json/--report-html require analysis (remove --no-analyze)")
        if not all_records:
            print("Report requested but there are no crash records to render.")
        else:
            _write_reports(
                all_records,
                json_path=args.report_json,
                html_path=args.report_html,
                config=_report_config(args, config_path),
            )

    if args.fail_on_crash:
        counts = _status_counts(results)
        if counts.get(RunStatus.CRASH, 0) or counts.get(RunStatus.TIMEOUT, 0):
            return 3
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    config_path = _config_path(args)
    config = load_run_config(config_path, _run_overrides(args))
    results_dir = Path(config.results_dir)
    if not results_dir.is_absolute():
        results_dir = (Path.cwd() / results_dir).resolve()

    if args.run:
        runs = [load_run_result(item) for item in args.run]
    else:
        runs = discover_runs(results_dir)
    if not runs:
        print(
            f"No run manifests found under {results_dir / 'runs'}. "
            "Use `crashlab run` first or pass --results.",
            file=sys.stderr,
        )
        return 1

    analyzer = analyzer_from_config(config)
    records = analyze_run_list(
        runs,
        analyzer,
        asan_dir=args.asan_dir,
        asan_log=args.asan_log,
    )
    _print_run_summary(runs)
    if records:
        all_records = _merge_records(load_crash_records(results_dir), records)
        groups = preserve_crash_groups(all_records, results_dir)
        _print_groups(groups)
    else:
        all_records = load_crash_records(results_dir)
        groups = group_by_signature(all_records)
        print("No crashes to analyze.")

    if args.report_json or args.report_html:
        if not all_records:
            print("Report requested but there are no crash records to render.")
        else:
            _write_reports(
                all_records,
                json_path=args.report_json,
                html_path=args.report_html,
                config=_report_config(args, config_path),
            )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    config_path = _config_path(args)
    config = load_run_config(config_path, {})
    results_dir = Path(args.results_dir or config.results_dir)
    if not results_dir.is_absolute():
        results_dir = (Path.cwd() / results_dir).resolve()

    records = load_crash_records(results_dir)
    if not records:
        print(
            f"No crash records found under {results_dir / 'runs'}. "
            "Run `crashlab run` or `crashlab analyze` first.",
            file=sys.stderr,
        )
        return 1

    report_config = _report_config(args, config_path)
    json_path = args.json_path
    html_path = args.html_path
    if not json_path and not html_path:
        json_path = str(results_dir / "report.json")
        html_path = str(results_dir / "report.html")

    groups = group_by_signature(records)
    print(
        f"Loaded {len(records)} crash record(s) across {len(groups)} unique signature(s) "
        f"from {results_dir}"
    )
    _write_reports(
        records, json_path=json_path, html_path=html_path, config=report_config
    )
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    config_path = _config_path(args)
    overrides = {"gdb_path": args.gdb_path} if args.gdb_path else {}
    config = load_run_config(config_path, overrides)

    print(f"crashlab {__version__}")
    print(f"python:        {sys.version.split()[0]} ({sys.executable})")
    print(f"platform:      {sys.platform} ({os.name})")
    print(f"cwd:           {Path.cwd()}")
    preload_support = os.name != "nt"
    print(
        "LD_PRELOAD:    "
        + ("supported" if preload_support else "not supported on Windows (recorded only)")
    )
    print(f"config:        {config_path or '(none; defaults)'}")

    bridge = LiveGdbBridge(config.gdb_path)
    gdb_status = "available" if bridge.available else "not found"
    print(f"gdb:           {config.gdb_path!r} -> {gdb_status}")
    if not bridge.available:
        print(
            "               analysis will still run, but signatures fall back to "
            "sanitizer/signal evidence"
        )

    asan = _detect_asan_runtime()
    print(f"ASan runtime:  {asan or 'not detected (supply --preload PATH or use an ASan build)'}")

    example = Path.cwd() / "examples" / "target"
    print(
        "sample target: "
        + (str(example) if example.is_file() else "not built (see examples/README.md)")
    )
    corpus = Path.cwd() / "corpus"
    if corpus.is_dir():
        count = sum(1 for item in corpus.iterdir() if item.is_file())
        print(f"corpus:        {corpus} ({count} file(s))")
    else:
        print("corpus:        missing (create ./corpus or pass --input-dir)")
    return 0


def _detect_asan_runtime() -> str | None:
    preload = os.environ.get("LD_PRELOAD", "").strip()
    if preload:
        return f"LD_PRELOAD={preload}"
    gcc = shutil.which("gcc") or shutil.which("clang")
    if not gcc:
        return None
    try:
        completed = subprocess.run(
            [gcc, "-print-file-name=libasan.so"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    candidate = completed.stdout.strip()
    if candidate and candidate != "libasan.so" and Path(candidate).is_file():
        return candidate
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "verbose", False):
        level = "DEBUG"
    elif getattr(args, "quiet", False):
        level = "ERROR"
    else:
        level = "INFO"
    configure_logging(level)

    try:
        return int(args.func(args))
    except (CliError, ConfigError, RunnerError, ValueError) as exc:
        print(f"crashlab: error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("crashlab: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
