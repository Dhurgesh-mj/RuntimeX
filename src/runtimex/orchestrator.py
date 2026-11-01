"""RuntimeX Orchestrator — Unified execution of HeapSentry + CrashLab."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from heapsentry.scanner import Scanner, build_library
from crashlab.config import RunConfig
from crashlab.runner import TestRunner, discover_runs
from crashlab.analysis import (
    analyzer_from_config,
    analyze_run_list,
    preserve_crash_groups,
    load_crash_records,
)
from crashlab.models import RunStatus, group_by_signature

from unified_report import load_heapsentry_data, load_crashlab_data, render_unified_html


class Orchestrator:
    """Coordinates HeapSentry active detection and CrashLab crash triage."""

    def __init__(
        self,
        binary: str | os.PathLike[str],
        *,
        out_dir: str | os.PathLike[str] = "runtimex_out",
        workers: int = 4,
        timeout: float = 5.0,
        enable_gdb: bool = True,
        quiet: bool = False,
    ) -> None:
        self.binary_path = Path(binary).resolve()
        if not self.binary_path.is_file():
            raise FileNotFoundError(f"target binary not found: {self.binary_path}")

        self.out_dir = Path(out_dir).resolve()
        self.workers = max(1, workers)
        self.timeout = timeout
        self.enable_gdb = enable_gdb
        self.quiet = quiet

        self.hs_out = self.out_dir / "heapsentry"
        self.cl_out = self.out_dir / "crashlab"

    def run(
        self,
        *,
        input_path: str | os.PathLike[str] | None = None,
        input_dir: str | os.PathLike[str] | None = None,
    ) -> dict[str, Any]:
        """Execute the full unified pipeline."""
        start_time = time.perf_counter()
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.hs_out.mkdir(parents=True, exist_ok=True)
        self.cl_out.mkdir(parents=True, exist_ok=True)

        if not self.quiet:
            print(f"============================================================")
            print(f" RuntimeX Unified Memory-Safety & Crash Triage Pipeline")
            print(f" Target:  {self.binary_path}")
            print(f" Mode:    {'Corpus (' + str(input_dir) + ')' if input_dir else 'Single Input (' + str(input_path) + ')'}")
            print(f" Workers: {self.workers}  |  Timeout: {self.timeout}s  |  GDB: {'Enabled' if self.enable_gdb else 'Disabled'}")
            print(f"============================================================")

        # -------------------------------------------------------------------
        # Phase 1: HeapSentry Active Memory-Safety Interposition
        # -------------------------------------------------------------------
        if not self.quiet:
            print(f"\n[Phase 1/3] Running HeapSentry Active Canary & Quarantine Detection...")

        library_path = self._locate_or_build_library()
        hs_scanner = Scanner(
            str(self.binary_path),
            library_path=library_path,
            out_dir=str(self.hs_out),
            timeout=self.timeout,
            quiet=self.quiet,
        )

        hs_results = []
        if input_dir:
            hs_results = hs_scanner.scan_corpus(
                input_dir,
                workers=self.workers,
                progress=not self.quiet,
            )
        else:
            hs_res = hs_scanner.scan(input_path=str(input_path) if input_path else None)
            hs_results = [hs_res]

        # -------------------------------------------------------------------
        # Phase 2: CrashLab Signal & GDB Backtrace Triage
        # -------------------------------------------------------------------
        if not self.quiet:
            print(f"\n[Phase 2/3] Running CrashLab Signal Monitoring & GDB Triage...")

        cl_config = RunConfig(
            binary=str(self.binary_path),
            results_dir=str(self.cl_out),
            timeout=self.timeout,
            workers=self.workers,
            enable_gdb=self.enable_gdb,
        )
        cl_runner = TestRunner(cl_config)

        # Collect input files
        input_files: list[Path] = []
        if input_dir:
            input_files = sorted(Path(input_dir).glob("*"))
            input_files = [p for p in input_files if p.is_file()]
        elif input_path:
            input_files = [Path(input_path)]

        if input_files:
            cl_results = cl_runner.run_batch(input_files, workers=self.workers)
        else:
            # Stdin with empty input if nothing specified
            import tempfile
            with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
                temp_input = Path(tf.name)
            try:
                cl_results = [cl_runner.run_one(temp_input)]
            finally:
                if temp_input.exists():
                    temp_input.unlink()

        # Run GDB triage analysis on crashed runs
        crashed_runs = [r for r in cl_results if r.status is RunStatus.CRASH]
        cl_records = []
        if crashed_runs:
            cl_analyzer = analyzer_from_config(cl_config)
            cl_records = analyze_run_list(crashed_runs, cl_analyzer)
            if cl_records:
                preserve_crash_groups(cl_records, self.cl_out)

        # Write CrashLab report.json
        all_records = load_crash_records(self.cl_out)
        cl_groups = group_by_signature(all_records)
        import json
        cl_report_json = self.cl_out / "report.json"
        cl_report_json.write_text(
            json.dumps([r.to_dict() for r in all_records], indent=2),
            encoding="utf-8",
        )

        # -------------------------------------------------------------------
        # Phase 3: Unified Report Generation
        # -------------------------------------------------------------------
        if not self.quiet:
            print(f"\n[Phase 3/3] Generating Unified RuntimeX Report...")

        hs_data = load_heapsentry_data(self.hs_out)
        cl_data = load_crashlab_data(self.cl_out)

        html_out = self.out_dir / "unified_report.html"
        json_out = self.out_dir / "unified_report.json"

        html_content = render_unified_html(
            hs_data=hs_data,
            cl_data=cl_data,
            binary_name=self.binary_path.name,
            title="RuntimeX Unified Security Report",
        )
        html_out.write_text(html_content, encoding="utf-8")

        summary_json = {
            "target": str(self.binary_path),
            "timestamp": time.time(),
            "elapsed_seconds": round(time.perf_counter() - start_time, 2),
            "heapsentry": {
                "findings_count": len(hs_data["findings"]),
                "findings": hs_data["findings"],
                "runs_count": len(hs_data["runs"]),
            },
            "crashlab": {
                "records_count": len(cl_data["records"]),
                "groups_count": len(cl_data["groups"]),
                "groups": [
                    {
                        "signature_hash": g["signature_hash"],
                        "crash_signature": g["crash_signature"],
                        "classification": g["classification"],
                        "vulnerability_class": g["vulnerability_class"],
                        "count": len(g["records"]),
                    }
                    for g in cl_data["groups"]
                ],
            },
        }
        json_out.write_text(json.dumps(summary_json, indent=2), encoding="utf-8")

        elapsed = round(time.perf_counter() - start_time, 2)
        if not self.quiet:
            self._print_terminal_summary(hs_data, cl_data, elapsed, html_out, json_out)

        return summary_json

    def _locate_or_build_library(self) -> str:
        """Find libheapsentry_detect.so or compile it."""
        candidates = [
            Path.cwd() / "build_detect" / "libheapsentry_detect.so",
            Path(__file__).resolve().parents[2] / "build_detect" / "libheapsentry_detect.so",
        ]
        for c in candidates:
            if c.is_file():
                return str(c)

        # Build it
        repo_root = Path(__file__).resolve().parents[2]
        built = build_library(repo_root)
        if built and Path(built).is_file():
            return built
        raise RuntimeError("failed to locate or build libheapsentry_detect.so")

    def _print_terminal_summary(
        self,
        hs_data: dict[str, Any],
        cl_data: dict[str, Any],
        elapsed: float,
        html_out: Path,
        json_out: Path,
    ) -> None:
        findings = hs_data["findings"]
        groups = cl_data["groups"]

        crit = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")

        print("\n" + "=" * 60)
        print(" RuntimeX Execution Summary")
        print("=" * 60)
        print(f" Elapsed Time:           {elapsed}s")
        print(f" HeapSentry Violations:  {len(findings)} ({crit} critical, {high} high)")
        for f in findings:
            bclass = f.get("bug_class", "unknown")
            sev = f.get("severity", "info").upper()
            addr = f.get("address") or ""
            print(f"   • [{sev}] {bclass} {addr}")

        print(f" CrashLab Crash Groups:  {len(groups)} unique signatures ({len(cl_data['records'])} total crashes)")
        for g in groups:
            shash = g["signature_hash"]
            vclass = g["vulnerability_class"]
            clsf = g["classification"].upper()
            cnt = len(g["records"])
            print(f"   • [{clsf}] {vclass} (x{cnt}) -> signature {shash}")

        print("-" * 60)
        print(f" 📊 HTML Report: file://{html_out}")
        print(f" 📄 JSON Report: file://{json_out}")
        print("=" * 60 + "\n")
