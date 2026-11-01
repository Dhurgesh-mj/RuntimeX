"""RuntimeX CLI — scan, run, report, doctor."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from runtimex import __version__
from runtimex.orchestrator import Orchestrator
from unified_report import load_heapsentry_data, load_crashlab_data, render_unified_html


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="runtimex",
        description="RuntimeX — Unified Memory-Safety Detection & Crash Triage Toolkit.",
    )
    parser.add_argument(
        "--version", action="version", version=f"RuntimeX {__version__}"
    )

    sub = parser.add_subparsers(dest="command")

    # ---- scan / run ----
    for cmd_name in ("scan", "run"):
        scan_p = sub.add_parser(
            cmd_name,
            help="Run both HeapSentry and CrashLab on target binary and generate unified report.",
        )
        scan_p.add_argument("binary", help="Target binary to test.")
        scan_p.add_argument("--input", "-i", metavar="FILE", help="Single input file.")
        scan_p.add_argument(
            "--input-dir", "-d", metavar="DIR", help="Corpus directory of test inputs."
        )
        scan_p.add_argument(
            "--out",
            "-o",
            metavar="DIR",
            default="runtimex_out",
            help="Results directory (default: runtimex_out).",
        )
        scan_p.add_argument(
            "--workers",
            "-w",
            type=int,
            default=4,
            metavar="N",
            help="Parallel workers for corpus execution (default: 4).",
        )
        scan_p.add_argument(
            "--timeout",
            "-t",
            type=float,
            default=5.0,
            metavar="SEC",
            help="Per-run timeout in seconds (default: 5.0).",
        )
        scan_p.add_argument(
            "--no-gdb",
            action="store_true",
            help="Disable GDB batch triage for crashes.",
        )
        scan_p.add_argument(
            "--quiet", "-q", action="store_true", help="Quiet output."
        )

    # ---- report ----
    rpt_p = sub.add_parser(
        "report",
        help="Generate unified HTML report from existing HeapSentry & CrashLab directories.",
    )
    rpt_p.add_argument(
        "--heapsentry",
        "-hs",
        required=True,
        metavar="DIR",
        help="HeapSentry results directory.",
    )
    rpt_p.add_argument(
        "--crashlab",
        "-cl",
        required=True,
        metavar="DIR",
        help="CrashLab results directory.",
    )
    rpt_p.add_argument(
        "--binary",
        default="target_binary",
        metavar="NAME",
        help="Target binary name.",
    )
    rpt_p.add_argument(
        "--out",
        "-o",
        default="unified_report.html",
        metavar="FILE",
        help="Output HTML file (default: unified_report.html).",
    )
    rpt_p.add_argument(
        "--out-json",
        metavar="FILE",
        help="Optional output JSON summary file.",
    )

    # ---- doctor ----
    sub.add_parser("doctor", help="Check system dependencies for both HeapSentry and CrashLab.")

    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    orchestrator = Orchestrator(
        binary=args.binary,
        out_dir=args.out,
        workers=args.workers,
        timeout=args.timeout,
        enable_gdb=not args.no_gdb,
        quiet=args.quiet,
    )
    orchestrator.run(input_path=args.input, input_dir=args.input_dir)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    hs_data = load_heapsentry_data(args.heapsentry)
    cl_data = load_crashlab_data(args.crashlab)

    html_out = render_unified_html(
        hs_data=hs_data,
        cl_data=cl_data,
        binary_name=args.binary,
        title="RuntimeX Unified Security Report",
    )
    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_out, encoding="utf-8")
    print(f"Unified HTML report generated: file://{out_path} ({len(html_out):,} bytes)")

    if args.out_json:
        import json
        json_path = Path(args.out_json).resolve()
        summary = {
            "binary": args.binary,
            "heapsentry_findings": len(hs_data["findings"]),
            "crashlab_crashes": len(cl_data["records"]),
            "crashlab_groups": len(cl_data["groups"]),
        }
        json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"Unified JSON summary generated: file://{json_path}")

    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    print(f"RuntimeX Unified Security Toolkit v{__version__}")
    print(f"Python:       {sys.version.split()[0]} ({sys.executable})")
    print(f"Platform:     {sys.platform} ({os.name})")

    # 1. Detection library
    repo_root = Path(__file__).resolve().parents[2]
    lib_path = repo_root / "build_detect" / "libheapsentry_detect.so"
    if lib_path.is_file():
        print(f"HeapSentry:   ✅ libheapsentry_detect.so ({lib_path})")
    else:
        print(f"HeapSentry:   ⚠️ libheapsentry_detect.so not built (run make -f Makefile.heapsentry library)")

    # 2. LD_PRELOAD support
    preload_ok = os.name != "nt"
    print(f"LD_PRELOAD:   {'✅ Supported (Linux/macOS)' if preload_ok else '❌ Not supported on Windows'}")

    # 3. GDB
    gdb_path = shutil.which("gdb")
    if gdb_path:
        print(f"GDB:          ✅ Available at {gdb_path}")
    else:
        print(f"GDB:          ⚠️ Not found on PATH (crash triage will fall back to signals)")

    # 4. ASan runtime
    from crashlab.cli import _detect_asan_runtime
    asan = _detect_asan_runtime()
    if asan:
        print(f"ASan:         ✅ Detected at {asan}")
    else:
        print(f"ASan:         ℹ️ Not detected by default (pass --preload or use an ASan target)")

    # 5. Compiler
    cc = shutil.which("gcc") or shutil.which("clang")
    if cc:
        print(f"C Compiler:   ✅ {cc}")
    else:
        print(f"C Compiler:   ❌ gcc/clang not found")

    print("\nAll core subsystems operational. Ready to scan.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command in ("scan", "run"):
        return cmd_scan(args)
    elif args.command == "report":
        return cmd_report(args)
    elif args.command == "doctor":
        return cmd_doctor(args)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
