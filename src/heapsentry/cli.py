"""HeapSentry CLI — scan, report, doctor."""

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from heapsentry import __version__


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "command") or args.command is None:
        parser.print_help()
        return 0

    if args.command == "scan":
        return _cmd_scan(args)
    elif args.command == "report":
        return _cmd_report(args)
    elif args.command == "doctor":
        return _cmd_doctor(args)

    parser.print_help()
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="heapsentry",
        description="HeapSentry unified memory-safety scanner.",
    )
    parser.add_argument(
        "--version", action="version", version=f"HeapSentry {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    # ---- scan ----
    scan_p = sub.add_parser("scan", help="Scan a binary for memory-safety bugs.")
    scan_p.add_argument("binary", help="Path to the target binary.")
    scan_p.add_argument(
        "--input", metavar="FILE",
        help="Input file (passed to binary via stdin)."
    )
    scan_p.add_argument(
        "--input-dir", metavar="DIR",
        help="Corpus mode: scan all files in DIR."
    )
    scan_p.add_argument(
        "--out", metavar="DIR", default="heapsentry_out",
        help="Output directory (default: heapsentry_out)."
    )
    scan_p.add_argument(
        "--report", metavar="FILE",
        help="HTML report path (default: <out>/report.html)."
    )
    scan_p.add_argument(
        "--timeout", type=float, default=10.0, metavar="SEC",
        help="Per-run timeout in seconds (default: 10.0)."
    )
    scan_p.add_argument(
        "--workers", type=int, default=1, metavar="N",
        help="Parallel workers for corpus mode (default: 1)."
    )
    scan_p.add_argument(
        "--no-build", action="store_true",
        help="Skip auto-build of the detection library."
    )
    scan_p.add_argument(
        "--quiet", action="store_true",
        help="Suppress progress output."
    )
    scan_p.add_argument(
        "--args", nargs=argparse.REMAINDER, metavar="ARG",
        help="Extra arguments passed to binary after input."
    )

    # ---- report ----
    rpt_p = sub.add_parser(
        "report", help="Regenerate HTML from an existing results directory."
    )
    rpt_p.add_argument("results_dir", help="Directory containing findings.json.")
    rpt_p.add_argument(
        "--out", metavar="FILE",
        help="Output HTML file (default: <results_dir>/report.html)."
    )

    # ---- doctor ----
    sub.add_parser("doctor", help="Check HeapSentry environment and dependencies.")

    return parser


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

def _cmd_scan(args: argparse.Namespace) -> int:
    from heapsentry.scanner import Scanner, build_library
    from heapsentry.reports.html import write_html_report

    # ---- Locate the detection library ------------------------------------
    library_path = _locate_library(args)
    if library_path is None:
        return 2

    # ---- Create scanner -------------------------------------------------
    extra_args: list[str] = list(args.args) if args.args else []
    scanner = Scanner(
        args.binary,
        library_path=library_path,
        out_dir=args.out,
        timeout=args.timeout,
        extra_args=extra_args,
        quiet=args.quiet,
    )

    # ---- Run ------------------------------------------------------------
    try:
        if args.input_dir:
            results = scanner.scan_corpus(
                args.input_dir,
                workers=args.workers,
                progress=not args.quiet,
            )
            # For corpus mode, merge all findings for a summary, use last result
            # for the report; write individual findings in sub-dirs already.
            if not results:
                print("[heapsentry] No inputs processed.")
                return 2
            # Write a combined report using the aggregate
            all_findings = [f for r in results for f in r.findings]
            result = results[-1]  # use last result as template for header
        else:
            result = scanner.scan(
                input_path=args.input,
            )
            results = [result]
    except Exception as exc:
        print(f"[heapsentry] Scan error: {exc}", file=sys.stderr)
        return 2

    # ---- Summary --------------------------------------------------------
    if not args.quiet:
        _print_summary(results)

    # ---- HTML report ----------------------------------------------------
    report_path = args.report or str(Path(args.out) / "report.html")
    Path(args.out).mkdir(parents=True, exist_ok=True)

    # For corpus scans use the last result; single scan uses its own result.
    try:
        write_html_report(result, report_path)
        if not args.quiet:
            print(f"Report: {report_path}")
    except Exception as exc:
        print(f"[heapsentry] Warning: could not write report: {exc}", file=sys.stderr)

    # ---- Exit code ------------------------------------------------------
    from heapsentry.models import Severity
    has_critical_high = any(
        f.severity in (Severity.CRITICAL, Severity.HIGH)
        for r in results
        for f in r.findings
    )
    return 1 if has_critical_high else 0


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------

def _cmd_report(args: argparse.Namespace) -> int:
    """Regenerate an HTML report from an existing findings.json."""
    from heapsentry.models import (
        ScanResult, Finding, BugClass, Severity, CrashInfo
    )
    from heapsentry.reports.html import write_html_report

    results_dir = Path(args.results_dir)
    findings_file = results_dir / "findings.json"

    if not findings_file.exists():
        print(f"[heapsentry] findings.json not found in {results_dir}", file=sys.stderr)
        return 2

    raw_findings: list[dict] = json.loads(findings_file.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for d in raw_findings:
        try:
            findings.append(Finding(
                bug_class=BugClass(d["bug_class"]),
                severity=Severity(d["severity"]),
                address=d.get("address"),
                allocation_id=d.get("allocation_id"),
                size=d.get("size"),
                description=d.get("description", ""),
                event_id=d.get("event_id"),
                overflow_side=d.get("overflow_side"),
                evidence=d.get("evidence", {}),
            ))
        except (KeyError, ValueError) as exc:
            print(f"[heapsentry] Skipping malformed finding: {exc}", file=sys.stderr)

    # Rebuild a minimal ScanResult from the available metadata.
    result = ScanResult(
        run_id=results_dir.name,
        binary=str(results_dir),
        input_path=None,
        timestamp_start="",
        timestamp_end="",
        crashed=False,
        timed_out=False,
        exit_code=0,
        crash_info=None,
        events=[],
        findings=findings,
        event_log_path=None,
        out_dir=str(results_dir),
    )

    out_path = args.out or str(results_dir / "report.html")
    write_html_report(result, out_path)
    print(f"Report: {out_path}")
    return 0


# ---------------------------------------------------------------------------
# doctor command
# ---------------------------------------------------------------------------

def _cmd_doctor(_args: argparse.Namespace) -> int:
    """Check HeapSentry environment health."""
    ok = True

    # ---- Library ----
    lib_path = _find_library_path()
    if lib_path and Path(lib_path).exists():
        _check("Detection library", True, str(lib_path))
    else:
        _check("Detection library", False,
               "Not found. Run `make -f Makefile.heapsentry library` or pass --no-build.")
        ok = False

    # ---- LLDB ----
    lldb_bin = shutil.which("lldb")
    _check("LLDB available", lldb_bin is not None, lldb_bin or "not found on PATH")

    # ---- Platform injection mechanism ----
    if sys.platform == "darwin":
        _check(
            "Injection mechanism",
            True,
            "DYLD_INSERT_LIBRARIES (macOS). "
            "NOTE: Stripped by the kernel for setuid binaries. "
            "SIP blocks injection for system binaries — disable SIP in recovery "
            "mode or use a non-system binary.",
        )
    else:
        _check("Injection mechanism", True, "LD_PRELOAD (Linux).")

    # ---- Python version ----
    py_ver = sys.version_info
    py_ok = (py_ver.major, py_ver.minor) >= (3, 10)
    _check(
        f"Python {py_ver.major}.{py_ver.minor}",
        py_ok,
        "OK" if py_ok else "Python 3.10+ recommended for union-type hints.",
    )

    # ---- DYLD_FORCE_FLAT_NAMESPACE reminder ----
    if sys.platform == "darwin":
        print(
            "\n  💡 Reminder: DYLD_FORCE_FLAT_NAMESPACE=1 is set automatically by "
            "HeapSentry and is required for DYLD_INSERT_LIBRARIES interposition on "
            "modern macOS two-level namespace binaries."
        )

    return 0 if ok else 1


def _check(label: str, passed: bool, detail: str = "") -> None:
    mark = "✅" if passed else "❌"
    detail_str = f"  → {detail}" if detail else ""
    print(f"  {mark} {label}{detail_str}")


# ---------------------------------------------------------------------------
# Library location helpers
# ---------------------------------------------------------------------------

def _find_library_path() -> str | None:
    """Return the path to the detection library relative to the package root."""
    lib_name = (
        "libheapsentry_detect.dylib"
        if sys.platform == "darwin"
        else "libheapsentry_detect.so"
    )
    # Walk up from the heapsentry package to find build_detect/
    pkg_dir = Path(__file__).parent
    for base in (pkg_dir, pkg_dir.parent, pkg_dir.parent.parent):
        candidate = base / "build_detect" / lib_name
        if candidate.exists():
            return str(candidate)
    return None


def _locate_library(args: argparse.Namespace) -> str | None:
    """
    Find (or build) the detection library.

    Returns the path string or None on failure.
    """
    existing = _find_library_path()
    if existing:
        return existing

    if getattr(args, "no_build", False):
        print(
            "[heapsentry] Detection library not found and --no-build is set.",
            file=sys.stderr,
        )
        return None

    # Attempt auto-build
    from heapsentry.scanner import build_library
    pkg_dir = Path(__file__).parent
    # Look for Makefile.heapsentry up the tree
    for base in (pkg_dir, pkg_dir.parent, pkg_dir.parent.parent):
        makefile = base / "Makefile.heapsentry"
        if makefile.exists():
            build_dir = base / "build_detect"
            build_dir.mkdir(parents=True, exist_ok=True)
            try:
                lib = build_library(str(base), str(build_dir))
                print(f"[heapsentry] Built detection library: {lib}")
                return lib
            except RuntimeError as exc:
                print(f"[heapsentry] Build failed: {exc}", file=sys.stderr)
                return None

    print(
        "[heapsentry] Detection library not found and no Makefile.heapsentry available. "
        "Build it manually and place it at build_detect/libheapsentry_detect.dylib "
        "(macOS) or build_detect/libheapsentry_detect.so (Linux).",
        file=sys.stderr,
    )
    return None


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------

def _print_summary(results: list) -> None:
    from heapsentry.models import Severity
    total = len(results)
    all_findings = [f for r in results for f in r.findings]
    counts: dict[str, int] = {}
    for f in all_findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    parts = []
    for sev in ("critical", "high", "medium", "info"):
        n = counts.get(sev, 0)
        if n:
            parts.append(f"{n} {sev}")

    summary = ", ".join(parts) if parts else "clean"
    run_word = "run" if total == 1 else "runs"
    print(
        f"Scan complete. {total} {run_word}. "
        f"{len(all_findings)} finding(s): {summary}."
    )


if __name__ == "__main__":
    sys.exit(main())
