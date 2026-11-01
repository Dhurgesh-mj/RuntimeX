#!/usr/bin/env python3
"""RuntimeX Unified Report Generator.

Combines HeapSentry runtime memory-safety detection with CrashLab GDB/ASan crash triage
into a single, cohesive, interactive, dark-themed HTML report and JSON summary.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

# Ensure src/ is on python path
_SRC_DIR = Path(__file__).resolve().parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

try:
    from heapsentry.analyzer import build_allocation_timeline, _BUG_META
    from heapsentry.events import parse_events
    from heapsentry.models import AllocationEvent, BugClass, Finding, Severity
except ImportError:
    _BUG_META = {}

# ---------------------------------------------------------------------------
# Colors & Styles (Dark Navy Theme)
# ---------------------------------------------------------------------------
_COLORS = {
    "bg":           "#0a0f1e",
    "panel":        "#111827",
    "panel2":       "#1a2235",
    "border":       "#1e2d45",
    "border2":      "#2a3f5f",
    "critical":     "#ff4757",
    "high":         "#ff6b35",
    "medium":       "#ffd32a",
    "info":         "#3b82f6",
    "clean":        "#2ed573",
    "text":         "#e8f0fe",
    "muted":        "#8899bb",
    "code_bg":      "#060c18",
    "accent":       "#00d4ff",
    "accent_glow":  "rgba(0, 212, 255, 0.2)",
    "freed":        "#2ed573",
    "leaked":       "#ff4757",
    "overflowed":   "#ff4757",
    "double_freed": "#ff6b35",
    "use_after_freed": "#a855f7",
    "confirmed_vulnerability": "#ff4757",
    "crash":        "#ff6b35",
}

# Fallback bug meta if heapsentry import fails
if not _BUG_META:
    _BUG_META = {
        "heap_buffer_overflow": {
            "icon": "💥",
            "impact": (
                "An attacker can overwrite adjacent heap metadata or object data, "
                "enabling arbitrary code execution (ACE), privilege escalation, or "
                "controlled data corruption. This is one of the most exploited "
                "vulnerability classes in modern exploit chains."
            ),
            "remediation": [
                "Always validate buffer lengths before copying: use strncpy/strlcpy instead of strcpy.",
                "Prefer safe allocation helpers: malloc(sizeof(T) * n + guard) with explicit bounds.",
                "Enable compiler mitigations: -fsanitize=address (ASan), -D_FORTIFY_SOURCE=2.",
                "Use memory-safe languages for new code; apply bounds-checked wrappers in C/C++.",
            ],
            "code_bad": "char *buf = malloc(16);\nstrcpy(buf, user_input); // ❌ no bounds check",
            "code_good": "char *buf = malloc(16);\nstrncpy(buf, user_input, 15); // ✅ bounded copy\nbuf[15] = '\\0';",
        },
        "double_free": {
            "icon": "♻️",
            "impact": (
                "Freeing the same pointer twice corrupts the allocator's free-list, "
                "enabling heap layout manipulation. Exploited to achieve write-what-where "
                "primitives leading to remote code execution."
            ),
            "remediation": [
                "Set pointers to NULL immediately after free(): free(p); p = NULL;",
                "Use smart pointers in C++ (std::unique_ptr) that auto-null on destruction.",
                "Apply strict ownership discipline: a single owner per allocation.",
            ],
            "code_bad": "free(ptr);\n// ...\nfree(ptr); // ❌ double-free",
            "code_good": "free(ptr);\nptr = NULL; // ✅ poison immediately\nif (ptr) free(ptr);",
        },
        "use_after_free_write": {
            "icon": "👻",
            "impact": (
                "Writing to memory after it has been freed corrupts whichever object "
                "subsequently reallocates the same memory chunk. Turns into type confusion "
                "or arbitrary code execution."
            ),
            "remediation": [
                "Zero-out or poison freed memory before calling free().",
                "Set pointer to NULL immediately after free().",
                "Enable AddressSanitizer (-fsanitize=address) in test suites.",
            ],
            "code_bad": "free(obj);\nobj->field = 42; // ❌ use-after-free write",
            "code_good": "free(obj);\nobj = NULL; // ✅ pointer neutralized",
        },
        "memory_leak": {
            "icon": "🕳️",
            "impact": (
                "Unreleased heap memory causes memory exhaustion and crashes over time. "
                "In sensitive software, stale heap chunks may leak secret keys."
            ),
            "remediation": [
                "Ensure every malloc() has a matching free() on all exit paths.",
                "Adopt RAII or arena allocators for complex object lifetimes.",
            ],
            "code_bad": "void f() { char *b = malloc(64); if (err) return; free(b); }",
            "code_good": "void f() { char *b = malloc(64); if (err) { free(b); return; } free(b); }",
        },
        "crash": {
            "icon": "💀",
            "impact": "The process terminated abnormally from an unhandled fault or assertion.",
            "remediation": ["Inspect debugger backtrace and address to locate root cause."],
            "code_bad": None,
            "code_good": None,
        },
        "clean": {
            "icon": "✅",
            "impact": "No memory safety issues or abnormal terminations detected.",
            "remediation": ["Continue testing with diverse inputs."],
            "code_bad": None,
            "code_good": None,
        },
    }


def _e(val: Any) -> str:
    """HTML-escape helper."""
    if val is None:
        return ""
    return html.escape(str(val), quote=True)


def _sev_color(sev: str) -> str:
    s = str(sev).lower()
    return _COLORS.get(s, _COLORS["info"])


def _relative_ns(ns: int, base_ns: int) -> str:
    if ns == 0 or base_ns == 0:
        return "–"
    delta = ns - base_ns
    if abs(delta) < 1_000:
        return f"+{delta} ns"
    if abs(delta) < 1_000_000:
        return f"+{delta/1_000:.1f} µs"
    return f"+{delta/1_000_000:.2f} ms"


# ---------------------------------------------------------------------------
# Data Loading & Ingestion
# ---------------------------------------------------------------------------

def load_heapsentry_data(heapsentry_dir: Path | str) -> dict[str, Any]:
    """Load HeapSentry findings, events, and runs."""
    hs_path = Path(heapsentry_dir).resolve()
    findings: list[dict[str, Any]] = []
    events_raw: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []

    # 1. Check if hs_path is itself a single run directory
    if (hs_path / "findings.json").is_file():
        try:
            findings = json.loads((hs_path / "findings.json").read_text(encoding="utf-8"))
        except Exception:
            pass
        events_file = hs_path / "events.jsonl"
        if events_file.is_file():
            for line in events_file.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    try:
                        events_raw.append(json.loads(line))
                    except Exception:
                        pass
        runs.append({
            "run_id": hs_path.name,
            "findings_count": len(findings),
            "events_count": len(events_raw),
            "dir": str(hs_path),
        })
    elif hs_path.is_dir():
        # Check subdirectories
        for sub in sorted(hs_path.iterdir()):
            fj = sub / "findings.json"
            if fj.is_file():
                try:
                    f_list = json.loads(fj.read_text(encoding="utf-8"))
                    findings.extend(f_list)
                    runs.append({
                        "run_id": sub.name,
                        "findings_count": len(f_list),
                        "dir": str(sub),
                    })
                except Exception:
                    pass
            ef = sub / "events.jsonl"
            if ef.is_file() and not events_raw:  # grab primary events
                for line in ef.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.strip():
                        try:
                            events_raw.append(json.loads(line))
                        except Exception:
                            pass

    # Timeline calculation
    timeline: list[dict[str, Any]] = []
    try:
        from heapsentry.events import parse_events
        from heapsentry.analyzer import build_allocation_timeline
        # Find first valid events.jsonl
        ef_to_parse = None
        if (hs_path / "events.jsonl").is_file():
            ef_to_parse = hs_path / "events.jsonl"
        else:
            for sub in hs_path.iterdir():
                if (sub / "events.jsonl").is_file():
                    ef_to_parse = sub / "events.jsonl"
                    break
        if ef_to_parse:
            parsed_evs = parse_events(ef_to_parse)
            timeline = build_allocation_timeline(parsed_evs)
    except Exception:
        pass

    return {
        "findings": findings,
        "events": events_raw,
        "timeline": timeline,
        "runs": runs,
        "dir": str(hs_path),
    }


def load_crashlab_data(crashlab_dir: Path | str) -> dict[str, Any]:
    """Load CrashLab report.json and runs."""
    cl_path = Path(crashlab_dir).resolve()
    records: list[dict[str, Any]] = []
    report_file = cl_path / "report.json"
    if report_file.is_file():
        try:
            records = json.loads(report_file.read_text(encoding="utf-8"))
            if not isinstance(records, list):
                records = [records]
        except Exception:
            pass

    # If no report.json, discover runs
    if not records and (cl_path / "runs").is_dir():
        for manifest_path in sorted((cl_path / "runs").glob("*/run_manifest.json")):
            try:
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
                if data.get("status") == "crash":
                    records.append(data)
            except Exception:
                pass

    # Group records by crash signature / hash
    groups_dict: dict[str, dict[str, Any]] = {}
    for r in records:
        sig_hash = r.get("signature_hash") or r.get("crash_signature", "unknown")[:16]
        if sig_hash not in groups_dict:
            groups_dict[sig_hash] = {
                "signature_hash": sig_hash,
                "crash_signature": r.get("crash_signature", "SIG Unknown"),
                "classification": r.get("classification", "crash"),
                "vulnerability_class": r.get("vulnerability_class", "unknown"),
                "confidence": r.get("confidence", "low"),
                "records": [],
            }
        groups_dict[sig_hash]["records"].append(r)

    groups = list(groups_dict.values())
    # Sort: confirmed vulns first, then high confidence, then count
    groups.sort(key=lambda g: (
        0 if g["classification"] == "confirmed_vulnerability" else 1,
        0 if g["confidence"] == "high" else (1 if g["confidence"] == "medium" else 2),
        -len(g["records"]),
    ))

    return {
        "records": records,
        "groups": groups,
        "dir": str(cl_path),
    }


# ---------------------------------------------------------------------------
# HTML Building Blocks
# ---------------------------------------------------------------------------

def _badge(label: str, color: str, dot: bool = True) -> str:
    dot_html = f'<span class="badge-dot" style="background:{color};"></span>' if dot else ""
    return (
        f'<span class="badge" '
        f'style="background:{color}18;color:{color};border:1px solid {color}50;">'
        f'{dot_html}{_e(label)}</span>'
    )


def _render_executive_summary(
    hs_data: dict[str, Any],
    cl_data: dict[str, Any],
    binary_name: str,
) -> tuple[str, str]:
    """Generate overall risk rating and executive metric cards."""
    hs_findings = hs_data["findings"]
    cl_records = cl_data["records"]
    cl_groups = cl_data["groups"]

    crit_count = sum(1 for f in hs_findings if f.get("severity") == "critical")
    high_count = sum(1 for f in hs_findings if f.get("severity") == "high")
    med_count = sum(1 for f in hs_findings if f.get("severity") == "medium")
    confirmed_crashes = sum(1 for r in cl_records if r.get("classification") == "confirmed_vulnerability")

    # Threat assessment
    if crit_count > 0 or confirmed_crashes > 0:
        overall_risk = "CRITICAL RISK"
        overall_color = _COLORS["critical"]
        overall_desc = (
            f"Active memory corruptions detected! {crit_count} critical HeapSentry finding(s) "
            f"and {confirmed_crashes} confirmed CrashLab vulnerability record(s) were surfaced. "
            "Immediate remediation is required to prevent remote code execution or data corruption."
        )
    elif high_count > 0 or len(cl_records) > 0:
        overall_risk = "HIGH RISK"
        overall_color = _COLORS["high"]
        overall_desc = (
            f"High-severity issues detected: {high_count} HeapSentry finding(s) and {len(cl_records)} "
            "crashes observed under GDB/signal monitoring. Investigate call stacks to patch potential attack vectors."
        )
    elif med_count > 0:
        overall_risk = "MEDIUM RISK"
        overall_color = _COLORS["medium"]
        overall_desc = f"Memory leaks detected ({med_count} unreleased allocations). Process stability may degrade over prolonged execution."
    else:
        overall_risk = "CLEAN"
        overall_color = _COLORS["clean"]
        overall_desc = "No memory safety bugs or crashes detected across all tested inputs and monitoring hooks."

    cards_html = f"""
    <div class="summary-grid">
      <div class="stat-card">
        <div class="stat-num" style="color:{_COLORS['accent']};">{len(hs_findings)}</div>
        <div class="stat-label">HeapSentry Violations</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:{_COLORS['critical']};">{crit_count}</div>
        <div class="stat-label">Critical Corruptions</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:{_COLORS['high']};">{len(cl_records)}</div>
        <div class="stat-label">CrashLab Crashes</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:{_COLORS['info']};">{len(cl_groups)}</div>
        <div class="stat-label">Unique Signatures</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:{_COLORS['confirmed_vulnerability']};">{confirmed_crashes}</div>
        <div class="stat-label">Confirmed Exploitable</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:{_COLORS['clean']};">{len(hs_data['timeline']) or len(hs_data['events'])}</div>
        <div class="stat-label">Tracked Allocations</div>
      </div>
    </div>
    """

    hero_html = f"""
    <div class="hero-box" style="border-left: 5px solid {overall_color};">
      <div class="hero-top">
        <div class="hero-badge" style="background:{overall_color}22;color:{overall_color};border:1px solid {overall_color}60;">
          <span class="pulse-dot" style="background:{overall_color};"></span>
          {overall_risk}
        </div>
        <div class="hero-binary">Target: <code>{_e(binary_name)}</code></div>
      </div>
      <p class="hero-desc">{overall_desc}</p>
      <div class="hero-meta">
        <span>Dual Engines: <strong>HeapSentry Active LD_PRELOAD</strong> + <strong>CrashLab GDB Triage</strong></span>
        <span>Generated: <strong>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</strong></span>
      </div>
    </div>
    """
    return hero_html, cards_html


def _render_cross_correlation(hs_data: dict[str, Any], cl_data: dict[str, Any]) -> str:
    """Render a cross-correlation matrix between HeapSentry detections and CrashLab triage."""
    hs_findings = hs_data["findings"]
    cl_records = cl_data["records"]

    rows: list[str] = []
    # If we have findings and crashes, correlate them
    seen_keys: set[str] = set()

    for r in cl_records:
        inp = r.get("input", {})
        orig = inp.get("original_path") or inp.get("stored_name") or "stdin"
        inp_name = Path(orig).name
        sig = r.get("crash_signature", "—")
        vclass = r.get("vulnerability_class", "unknown")
        clsf = r.get("classification", "crash")
        sig_hash = r.get("signature_hash", "—")

        # Find matching HeapSentry finding if any
        matching_hs = None
        for f in hs_findings:
            desc = f.get("description", "").lower()
            if vclass.replace("-", "_") in desc or (vclass == "double-free" and "double_free" in f.get("bug_class", "")):
                matching_hs = f
                break

        hs_cell = "—"
        if matching_hs:
            bclass = matching_hs.get("bug_class", "")
            sev = matching_hs.get("severity", "info")
            hs_cell = f"{_badge(bclass.replace('_', ' '), _sev_color(sev))} <span class='muted'>Alloc #{matching_hs.get('allocation_id')}</span>"
        else:
            hs_cell = "<span class='muted'>External Signal / No Hook</span>"

        clsf_badge = _badge(
            "Confirmed Vulnerability" if clsf == "confirmed_vulnerability" else "Crash Observed",
            _COLORS["critical"] if clsf == "confirmed_vulnerability" else _COLORS["high"]
        )

        rows.append(f"""
        <tr>
          <td><code>{_e(inp_name)}</code></td>
          <td>{hs_cell}</td>
          <td><strong>{_e(vclass)}</strong><br><small class="muted">{_e(sig[:60])}...</small></td>
          <td><code>{_e(sig_hash)}</code></td>
          <td>{clsf_badge}</td>
        </tr>
        """)

    if not rows:
        return "<p class='muted'>No correlated crash events across runs.</p>"

    return f"""
    <div class="timeline-wrap">
      <table>
        <thead>
          <tr>
            <th>Input File</th>
            <th>HeapSentry Interposition Detection</th>
            <th>CrashLab GDB Triage Class</th>
            <th>Signature Hash</th>
            <th>Verification Status</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </div>
    """


def _render_heapsentry_findings(findings: list[dict[str, Any]]) -> str:
    """Render HeapSentry findings with interactive tabs."""
    if not findings:
        return "<p class='muted'>No active heap violations recorded by HeapSentry hooks.</p>"

    cards: list[str] = []
    for idx, f in enumerate(findings):
        bug_class = f.get("bug_class", "unknown")
        severity = f.get("severity", "info")
        color = _sev_color(severity)
        meta = _BUG_META.get(bug_class, _BUG_META.get("crash", {}))
        icon = meta.get("icon", "⚠️")
        title = bug_class.replace("_", " ").title()

        addr_str = f" @ <code>{_e(f.get('address'))}</code>" if f.get("address") else ""
        alloc_id = f.get("allocation_id")
        alloc_str = f"<span class='pill'>Alloc #{alloc_id}</span>" if alloc_id is not None else ""
        size_val = f.get("size")
        size_str = f"<span class='pill'>{size_val} bytes</span>" if size_val is not None else ""
        side_val = f.get("overflow_side")
        side_str = f"<span class='pill'>{_e(side_val)} side</span>" if side_val else ""

        # Tabs
        tab_id = f"hs_card_{idx}"
        impact_text = meta.get("impact", f.get("description", ""))
        remeds = meta.get("remediation", ["Validate bounds and memory allocations."])
        remed_items = "".join(f"<li>{r}</li>" for r in remeds)
        code_bad = meta.get("code_bad")
        code_good = meta.get("code_good")

        code_tab_html = ""
        if code_bad and code_good:
            code_tab_html = f"""
            <div class="code-compare">
              <div>
                <div class="code-block-label" style="color:{_COLORS['critical']};">❌ Vulnerable C Pattern</div>
                <pre><code class="line-bad">{_e(code_bad)}</code></pre>
              </div>
              <div>
                <div class="code-block-label" style="color:{_COLORS['clean']};">✅ Remediated Safe Pattern</div>
                <pre><code class="line-good">{_e(code_good)}</code></pre>
              </div>
            </div>
            """
        else:
            code_tab_html = "<p class='muted'>Generic termination pattern; no specific side-by-side snippet available.</p>"

        evidence_json = json.dumps(f.get("evidence", {}), indent=2)

        cards.append(f"""
        <div class="finding-card" style="border-left-color:{color};">
          <div class="card-header">
            <div class="card-icon">{icon}</div>
            <div class="card-title-block">
              <div class="card-title">
                {_e(title)}{addr_str}
                {_badge(severity, color)}
              </div>
              <div class="card-subtitle">
                {alloc_str}
                {size_str}
                {side_str}
                <span class="muted">{_e(f.get('description', ''))}</span>
              </div>
            </div>
          </div>

          <div class="card-tabs">
            <button class="tab-btn active" onclick="switchTab(this, '{tab_id}_impact')">💥 Exploit Impact</button>
            <button class="tab-btn" onclick="switchTab(this, '{tab_id}_remed')">🛠️ Remediation</button>
            <button class="tab-btn" onclick="switchTab(this, '{tab_id}_code')">💻 Code Pattern</button>
            <button class="tab-btn" onclick="switchTab(this, '{tab_id}_evid')">🔍 Evidence & Canaries</button>
          </div>

          <div id="{tab_id}_impact" class="tab-pane active">
            <div class="impact-block">{impact_text}</div>
          </div>

          <div id="{tab_id}_remed" class="tab-pane">
            <ul class="remediation-list">{remed_items}</ul>
          </div>

          <div id="{tab_id}_code" class="tab-pane">
            {code_tab_html}
          </div>

          <div id="{tab_id}_evid" class="tab-pane">
            <pre><code>{_e(evidence_json)}</code></pre>
          </div>
        </div>
        """)

    return "".join(cards)


def _render_crashlab_groups(groups: list[dict[str, Any]]) -> str:
    """Render CrashLab deduplicated crash groups with GDB backtraces."""
    if not groups:
        return "<p class='muted'>No crash groups recorded by CrashLab triage engine.</p>"

    cards: list[str] = []
    for idx, grp in enumerate(groups):
        sig_hash = grp["signature_hash"]
        sig = grp["crash_signature"]
        clsf = grp["classification"]
        vclass = grp["vulnerability_class"]
        conf = grp["confidence"]
        records = grp["records"]
        rep = records[0]

        is_confirmed = clsf == "confirmed_vulnerability"
        color = _COLORS["critical"] if is_confirmed else _COLORS["high"]
        gdb = rep.get("gdb", {})
        asan = rep.get("asan", {})

        # GDB stack frames
        frames = gdb.get("backtrace", [])
        frame_rows: list[str] = []
        for fr in frames:
            f_idx = fr.get("index", 0)
            func = fr.get("function", "??")
            file_loc = fr.get("file", "—")
            line = fr.get("line")
            if line:
                file_loc = f"{file_loc}:{line}"
            addr = fr.get("address") or "—"
            frame_rows.append(f"""
            <tr>
              <td><code>#{f_idx}</code></td>
              <td><code><strong>{_e(func)}</strong></code></td>
              <td><span class="muted">{_e(file_loc)}</span></td>
              <td><code>{_e(addr)}</code></td>
            </tr>
            """)

        stack_table = ""
        if frame_rows:
            stack_table = f"""
            <div class="timeline-wrap" style="margin-top:8px;">
              <table>
                <thead>
                  <tr><th>#</th><th>Function</th><th>Source Location</th><th>Instruction Address</th></tr>
                </thead>
                <tbody>
                  {''.join(frame_rows)}
                </tbody>
              </table>
            </div>
            """
        else:
            stack_table = "<p class='muted'>GDB backtrace unavailable or raw signal exit.</p>"

        # Faulting instruction & registers
        fault_inst = gdb.get("fault_instruction")
        registers = gdb.get("registers", {})
        reg_html = ""
        if registers:
            reg_items = "".join(f"<span><code>{_e(k)}</code>: <code>{_e(v)}</code></span> " for k, v in sorted(registers.items())[:12])
            reg_html = f"<div class='reg-dump' style='margin-top:8px;font-size:0.8em;color:var(--muted);'>{reg_items}</div>"

        # Reproduction cmd
        repro = rep.get("reproduction_command") or f"./target < {rep.get('input', {}).get('original_path', 'case.bin')}"

        cards.append(f"""
        <div class="finding-card" style="border-left-color:{color};">
          <div class="card-header">
            <div class="card-icon">🎯</div>
            <div class="card-title-block">
              <div class="card-title">
                Signature: <code>{_e(sig_hash)}</code>
                {_badge(clsf.replace('_', ' ').title(), color)}
                {_badge(f'Confidence: {conf.upper()}', _COLORS['accent'] if conf=='high' else _COLORS['muted'])}
                {_badge(vclass, _COLORS['medium'])}
              </div>
              <div class="card-subtitle">
                <span class="pill">Crashes: {len(records)}</span>
                <span class="pill">Signal: {_e(rep.get('signal', {}).get('name') if isinstance(rep.get('signal'), dict) else rep.get('signal') or 'SIGABRT/SEGV')}</span>
                <span class="muted">{_e(sig)}</span>
              </div>
            </div>
          </div>

          <div style="margin-top:14px;">
            <h4>Root Cause Hypothesis</h4>
            <p class="muted" style="margin-bottom:12px;">{_e(rep.get('suspected_root_cause', 'Abnormal termination under test.'))}</p>

            <h4>GDB Triage Call Stack</h4>
            {stack_table}

            {f"<h4>Faulting Instruction</h4><pre><code>{_e(fault_inst)}</code></pre>" if fault_inst else ""}
            {reg_html}

            <h4 style="margin-top:14px;">Exact Reproduction Command</h4>
            <pre><code>{_e(repro)}</code></pre>

            {f"<h4>Mitigation Notes</h4><p class='muted'>{_e(rep.get('mitigation_notes'))}</p>" if rep.get('mitigation_notes') else ""}
          </div>
        </div>
        """)

    return "".join(cards)


def _render_timeline_table(timeline: list[dict[str, Any]]) -> str:
    """Render allocation fate timeline."""
    if not timeline:
        return "<p class='muted'>No allocation lifecycle events recorded.</p>"

    rows: list[str] = []
    for item in timeline:
        fate = item.get("fate", "unknown")
        fate_color = _COLORS.get(fate, _COLORS["muted"])
        fate_badge = _badge(fate.upper(), fate_color)
        rows.append(f"""
        <tr>
          <td><code>#{item.get('alloc_id')}</code></td>
          <td><code>{_e(item.get('address'))}</code></td>
          <td>{item.get('size')} bytes</td>
          <td>Thread {item.get('thread_id')}</td>
          <td>{fate_badge}</td>
        </tr>
        """)

    return f"""
    <div class="timeline-wrap">
      <table>
        <thead>
          <tr>
            <th>Allocation ID</th>
            <th>Heap Address</th>
            <th>Requested Size</th>
            <th>Thread</th>
            <th>Final Lifecycle Fate</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </div>
    """


def _render_event_stream(events: list[dict[str, Any]]) -> str:
    """Render raw JSONL event stream with highlighted canaries."""
    if not events:
        return "<p class='muted'>No raw runtime events logged.</p>"

    base_ns = events[0].get("timestamp_ns", 0) if events else 0
    rows: list[str] = []

    for ev in events[:60]:  # limit to top 60 for performance
        ev_id = ev.get("event_id", "—")
        ev_type = ev.get("event", "—")
        alloc_id = ev.get("allocation_id", "—")
        addr = ev.get("address") or "—"
        size = ev.get("size")
        size_str = f"{size} B" if size is not None else "—"
        ts_ns = ev.get("timestamp_ns", 0)
        rel_time = _relative_ns(ts_ns, base_ns)
        status = ev.get("status", "ok")

        status_badge = _badge(status.upper(), _COLORS["clean"] if status == "ok" else _COLORS["critical"])
        canary = ev.get("extra", {}).get("canary") or ev.get("canary")
        canary_html = f"<span class='canary'>{_e(canary)}</span>" if canary else "—"

        rows.append(f"""
        <tr>
          <td>#{ev_id}</td>
          <td><span class="event-type">{_e(ev_type)}</span></td>
          <td><code>{_e(addr)}</code></td>
          <td>#{alloc_id}</td>
          <td>{size_str}</td>
          <td>{rel_time}</td>
          <td>{canary_html}</td>
          <td>{status_badge}</td>
        </tr>
        """)

    more_hint = f"<p class='muted' style='margin-top:8px;'>Showing top {min(len(events), 60)} of {len(events)} events.</p>" if len(events) > 60 else ""

    return f"""
    <div class="timeline-wrap">
      <table>
        <thead>
          <tr>
            <th>Event #</th>
            <th>Operation</th>
            <th>Target Address</th>
            <th>Alloc ID</th>
            <th>Size</th>
            <th>Time Delta</th>
            <th>Canary Guard</th>
            <th>Hook Status</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </div>
    {more_hint}
    """


def _render_vuln_matrix(hs_findings: list[dict[str, Any]], cl_records: list[dict[str, Any]]) -> str:
    """Render reference matrix of all memory-safety classes with status badge."""
    classes = [
        ("heap_buffer_overflow", "Heap Buffer Overflow", "Writing beyond allocated chunk boundaries, corrupting adjacent heap chunks and canaries.", "💥"),
        ("double_free", "Double Free", "Freeing already deallocated pointer, corrupting tcache / fastbin free-lists.", "♻️"),
        ("use_after_free_write", "Use-After-Free Write", "Modifying heap memory after deallocation, corrupting subsequent allocations.", "👻"),
        ("memory_leak", "Memory Leak", "Heap allocations that are never reclaimed before process termination.", "🕳️"),
    ]

    all_found_types = {f.get("bug_class") for f in hs_findings}
    for r in cl_records:
        vc = r.get("vulnerability_class", "").replace("-", "_")
        all_found_types.add(vc)

    cards: list[str] = []
    for bug_key, name, desc, icon in classes:
        detected = (bug_key in all_found_types) or (bug_key == "heap_buffer_overflow" and "heap-buffer-overflow" in all_found_types)
        status_badge = _badge("DETECTED IN TEST", _COLORS["critical"]) if detected else _badge("CLEAN / NOT DETECTED", _COLORS["clean"])
        border_col = _COLORS["critical"] if detected else _COLORS["border"]

        cards.append(f"""
        <div class="vuln-ref-card" style="border-left: 3px solid {border_col};">
          <div class="vuln-ref-title">
            <span>{icon} {_e(name)}</span>
            <div style="margin-left:auto;">{status_badge}</div>
          </div>
          <p class="vuln-ref-desc">{_e(desc)}</p>
        </div>
        """)

    return f"<div class='vuln-grid'>{''.join(cards)}</div>"


# ---------------------------------------------------------------------------
# Complete Unified HTML Page Assembly
# ---------------------------------------------------------------------------

def render_unified_html(
    hs_data: dict[str, Any],
    cl_data: dict[str, Any],
    binary_name: str,
    title: str = "RuntimeX Unified Security Report",
) -> str:
    """Render complete, self-contained HTML page combining HeapSentry and CrashLab."""
    hero_html, metrics_html = _render_executive_summary(hs_data, cl_data, binary_name)
    cross_corr_html = _render_cross_correlation(hs_data, cl_data)
    heapsentry_html = _render_heapsentry_findings(hs_data["findings"])
    crashlab_html = _render_crashlab_groups(cl_data["groups"])
    timeline_html = _render_timeline_table(hs_data["timeline"])
    event_stream_html = _render_event_stream(hs_data["events"])
    vuln_matrix_html = _render_vuln_matrix(hs_data["findings"], cl_data["records"])

    css = f"""
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    :root {{
        --bg: {_COLORS['bg']};
        --panel: {_COLORS['panel']};
        --panel2: {_COLORS['panel2']};
        --border: {_COLORS['border']};
        --border2: {_COLORS['border2']};
        --text: {_COLORS['text']};
        --muted: {_COLORS['muted']};
        --accent: {_COLORS['accent']};
        --critical: {_COLORS['critical']};
        --high: {_COLORS['high']};
        --medium: {_COLORS['medium']};
        --info: {_COLORS['info']};
        --clean: {_COLORS['clean']};
        --code-bg: {_COLORS['code_bg']};
    }}

    html {{ scroll-behavior: smooth; }}
    body {{
        background: var(--bg);
        color: var(--text);
        font-family: 'Inter', system-ui, sans-serif;
        font-size: 14px;
        line-height: 1.65;
        min-height: 100vh;
        background-image:
            radial-gradient(ellipse at 15% 0%, rgba(0,212,255,0.06) 0%, transparent 55%),
            radial-gradient(ellipse at 85% 100%, rgba(255,71,87,0.05) 0%, transparent 55%);
    }}

    /* Topbar */
    .topbar {{
        background: rgba(10,15,30,0.92);
        border-bottom: 1px solid var(--border);
        backdrop-filter: blur(14px);
        position: sticky; top: 0; z-index: 100;
        padding: 12px 28px;
        display: flex; align-items: center; gap: 18px;
    }}
    .topbar-logo {{ font-size: 1.25rem; font-weight: 800; letter-spacing: -0.5px; }}
    .topbar-logo span {{ color: var(--accent); }}
    .topbar-nav {{ display: flex; gap: 14px; margin-left: 20px; }}
    .topbar-nav a {{
        color: var(--muted); text-decoration: none; font-size: 0.82em; font-weight: 600;
        transition: color 0.15s;
    }}
    .topbar-nav a:hover {{ color: var(--text); }}
    .topbar-meta {{ font-size: 0.78em; color: var(--muted); margin-left: auto; }}
    .topbar-meta code {{ color: var(--text); background: var(--border); padding: 2px 6px; border-radius: 4px; }}

    .container {{ max-width: 1100px; margin: 0 auto; padding: 36px 20px 80px; }}

    /* Hero */
    .hero-box {{
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 24px 26px;
        margin-bottom: 24px;
        box-shadow: 0 4px 24px rgba(0,0,0,0.3);
    }}
    .hero-top {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; flex-wrap: wrap; gap: 10px; }}
    .hero-badge {{
        display: inline-flex; align-items: center; gap: 8px;
        padding: 6px 14px; border-radius: 20px; font-size: 0.85em; font-weight: 800; letter-spacing: 1px;
    }}
    .pulse-dot {{ width: 8px; height: 8px; border-radius: 50%; box-shadow: 0 0 8px currentColor; }}
    .hero-binary {{ font-size: 0.9em; color: var(--muted); }}
    .hero-binary code {{ color: var(--text); }}
    .hero-desc {{ font-size: 1.05rem; color: var(--text); margin-bottom: 14px; font-weight: 500; line-height: 1.5; }}
    .hero-meta {{ display: flex; gap: 20px; font-size: 0.8em; color: var(--muted); flex-wrap: wrap; border-top: 1px solid var(--border); padding-top: 10px; }}
    .hero-meta strong {{ color: var(--text); }}

    /* Headings */
    h2 {{
        font-size: 0.76em; font-weight: 800; letter-spacing: 2px; text-transform: uppercase;
        color: var(--muted); margin-top: 46px; margin-bottom: 16px;
        padding-bottom: 8px; border-bottom: 1px solid var(--border);
        display: flex; align-items: center; gap: 8px;
    }}
    h2::before {{ content: ''; display: inline-block; width: 4px; height: 14px; background: var(--accent); border-radius: 2px; }}
    h3 {{ font-size: 1.05rem; font-weight: 700; margin-bottom: 6px; }}
    h4 {{ font-size: 0.88rem; font-weight: 700; margin-top: 12px; margin-bottom: 4px; color: var(--text); }}

    /* Summary Grid */
    .summary-grid {{
        display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 12px; margin-bottom: 30px;
    }}
    .stat-card {{
        background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
        padding: 16px; text-align: center; transition: transform 0.2s, border-color 0.2s;
    }}
    .stat-card:hover {{ transform: translateY(-2px); border-color: var(--border2); }}
    .stat-num {{ font-size: 2.1rem; font-weight: 800; line-height: 1; margin-bottom: 4px; }}
    .stat-label {{ font-size: 0.7em; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; color: var(--muted); }}

    /* Badges */
    .badge {{
        display: inline-flex; align-items: center; gap: 5px;
        padding: 3px 10px; border-radius: 20px; font-size: 0.72em; font-weight: 700;
        letter-spacing: 0.6px; text-transform: uppercase; white-space: nowrap;
    }}
    .badge-dot {{ width: 6px; height: 6px; border-radius: 50%; }}

    /* Code */
    code, pre {{
        font-family: 'JetBrains Mono', monospace; background: var(--code-bg); border-radius: 4px; font-size: 0.84em;
    }}
    code {{ padding: 2px 6px; border: 1px solid var(--border); }}
    pre {{
        padding: 14px 16px; overflow-x: auto; border: 1px solid var(--border); margin: 6px 0 12px; line-height: 1.5;
    }}
    pre code {{ background: none; border: 0; padding: 0; }}
    pre .line-bad {{ color: #ff4757; }}
    pre .line-good {{ color: #2ed573; }}

    /* Finding & Crash Cards */
    .finding-card {{
        background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
        padding: 22px; margin-bottom: 18px; border-left: 4px solid;
        transition: transform 0.2s, box-shadow 0.2s;
    }}
    .finding-card:hover {{ transform: translateY(-1px); box-shadow: 0 8px 30px rgba(0,0,0,0.35); }}
    .card-header {{ display: flex; align-items: flex-start; gap: 14px; margin-bottom: 14px; flex-wrap: wrap; }}
    .card-icon {{ font-size: 1.6rem; line-height: 1; flex-shrink: 0; }}
    .card-title-block {{ flex: 1; }}
    .card-title {{ font-size: 1.05rem; font-weight: 700; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
    .card-subtitle {{ font-size: 0.82em; color: var(--muted); margin-top: 6px; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }}
    .pill {{
        background: var(--panel2); border: 1px solid var(--border2); border-radius: 6px;
        padding: 2px 8px; font-size: 0.88em; color: var(--text);
    }}

    /* Tabs */
    .card-tabs {{ display: flex; gap: 4px; margin: 14px 0 12px; border-bottom: 1px solid var(--border); }}
    .tab-btn {{
        background: none; border: none; color: var(--muted); padding: 7px 14px;
        font-size: 0.78em; font-weight: 600; text-transform: uppercase; cursor: pointer;
        border-bottom: 2px solid transparent; margin-bottom: -1px; font-family: inherit;
        transition: color 0.15s, border-color 0.15s;
    }}
    .tab-btn:hover {{ color: var(--text); }}
    .tab-btn.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
    .tab-pane {{ display: none; }}
    .tab-pane.active {{ display: block; }}

    /* Impact & Remediation */
    .impact-block {{
        background: rgba(255,71,87,0.06); border: 1px solid rgba(255,71,87,0.2); border-radius: 8px;
        padding: 12px 14px; font-size: 0.88em; color: var(--text); line-height: 1.6;
    }}
    .remediation-list {{ list-style: none; display: flex; flex-direction: column; gap: 6px; padding: 0; margin-top: 4px; }}
    .remediation-list li {{ display: flex; gap: 8px; font-size: 0.86em; color: var(--text); }}
    .remediation-list li::before {{ content: '→'; color: var(--clean); font-weight: 700; flex-shrink: 0; }}
    .code-compare {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 6px; }}
    @media (max-width: 750px) {{ .code-compare {{ grid-template-columns: 1fr; }} }}
    .code-block-label {{ font-size: 0.72em; font-weight: 700; text-transform: uppercase; margin-bottom: 2px; }}

    /* Tables */
    .timeline-wrap {{ overflow-x: auto; border-radius: 10px; border: 1px solid var(--border); background: var(--panel); }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.84em; min-width: 650px; }}
    thead tr {{ background: var(--panel2); }}
    th {{
        color: var(--muted); text-align: left; padding: 10px 14px; font-weight: 600; font-size: 0.74em;
        text-transform: uppercase; letter-spacing: 0.8px; white-space: nowrap;
    }}
    td {{ padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }}
    tr:last-child td {{ border-bottom: none; }}
    tbody tr:hover {{ background: var(--panel2); }}

    .canary {{ font-family: 'JetBrains Mono', monospace; color: #f97316; font-size: 0.82em; }}
    .muted {{ color: var(--muted); }}

    /* Vuln Matrix */
    .vuln-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; }}
    .vuln-ref-card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }}
    .vuln-ref-title {{ font-size: 0.94rem; font-weight: 700; margin-bottom: 6px; display: flex; align-items: center; gap: 8px; }}
    .vuln-ref-desc {{ font-size: 0.82em; color: var(--muted); line-height: 1.5; }}

    /* Footer */
    footer {{
        margin-top: 60px; padding-top: 20px; border-top: 1px solid var(--border);
        font-size: 0.76em; color: var(--muted); text-align: center;
    }}
    footer code {{ color: var(--accent); }}
    """

    js = """
    function switchTab(btn, paneId) {
        const card = btn.closest('.finding-card');
        card.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        card.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        const target = document.getElementById(paneId);
        if (target) target.classList.add('active');
    }
    """

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_e(title)} - {_e(binary_name)}</title>
  <style>{css}</style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-logo">Runtime<span>X</span></div>
    <div class="topbar-nav">
      <a href="#overview">Overview</a>
      <a href="#correlation">Correlation</a>
      <a href="#heapsentry">HeapSentry ({len(hs_data['findings'])})</a>
      <a href="#crashlab">CrashLab ({len(cl_data['groups'])})</a>
      <a href="#timeline">Timeline</a>
      <a href="#events">Events</a>
      <a href="#matrix">Vuln Matrix</a>
    </div>
    <div class="topbar-meta">
      Binary: <code>{_e(binary_name)}</code>
    </div>
  </header>

  <main class="container">
    <section id="overview">
      {hero_html}
      {metrics_html}
    </section>

    <section id="correlation">
      <h2>Cross-Engine Triage & Correlation</h2>
      <p class="muted" style="margin-bottom:12px;">Correlating active HeapSentry red-zone / quarantine violations with CrashLab GDB debugger signals.</p>
      {cross_corr_html}
    </section>

    <section id="heapsentry">
      <h2>HeapSentry Active Runtime Detections ({len(hs_data['findings'])})</h2>
      <p class="muted" style="margin-bottom:12px;">Violations intercepted live via custom allocator hooks, canaries (<code>0xFEEDFACEDEADBEEF</code>), and quarantine buffers.</p>
      {heapsentry_html}
    </section>

    <section id="crashlab">
      <h2>CrashLab Triage & Deduplicated Signatures ({len(cl_data['groups'])})</h2>
      <p class="muted" style="margin-bottom:12px;">Unique crash groups triaged with automated GDB backtraces and symbolicated stack frames.</p>
      {crashlab_html}
    </section>

    <section id="timeline">
      <h2>Heap Allocation Lifecycle Timeline</h2>
      <p class="muted" style="margin-bottom:12px;">Lifecycle tracking of dynamically allocated buffers and their final fate.</p>
      {timeline_html}
    </section>

    <section id="events">
      <h2>Low-Level Hook Event Stream</h2>
      <p class="muted" style="margin-bottom:12px;">Chronological stream of memory interposition events and canary guard status.</p>
      {event_stream_html}
    </section>

    <section id="matrix">
      <h2>Memory-Safety Vulnerability Matrix</h2>
      <p class="muted" style="margin-bottom:12px;">Diagnostic status across the primary C/C++ heap vulnerability classes.</p>
      {vuln_matrix_html}
    </section>

    <footer>
      <p>RuntimeX Unified Memory-Safety & Crash Triage Toolkit · Defensive Security Testing Only</p>
      <p style="margin-top:4px;">Combines HeapSentry (Active Interposition) + CrashLab (GDB Crash Analysis) · Generated {datetime.now(timezone.utc).isoformat()}</p>
    </footer>
  </main>

  <script>{js}</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="unified_report",
        description="Generate a unified HeapSentry + CrashLab report (HTML and JSON).",
    )
    parser.add_argument("--heapsentry-dir", required=True, help="HeapSentry results directory")
    parser.add_argument("--crashlab-dir", required=True, help="CrashLab results directory")
    parser.add_argument("--binary", default="test_binary", help="Target binary name")
    parser.add_argument("--out", default="unified_report.html", help="Output HTML file path")
    parser.add_argument("--out-json", help="Optional output JSON summary file path")
    parser.add_argument("--title", default="RuntimeX Unified Security Report", help="Report title")

    args = parser.parse_args(argv)

    hs_data = load_heapsentry_data(args.heapsentry_dir)
    cl_data = load_crashlab_data(args.crashlab_dir)

    # Render HTML
    html_content = render_unified_html(
        hs_data=hs_data,
        cl_data=cl_data,
        binary_name=args.binary,
        title=args.title,
    )

    out_path = Path(args.out).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_content, encoding="utf-8")
    print(f"[unified_report] HTML report written to: {out_path} ({len(html_content):,} bytes)")

    # Optional JSON output
    if args.out_json:
        json_summary = {
            "title": args.title,
            "binary": args.binary,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "heapsentry": {
                "findings": hs_data["findings"],
                "events_count": len(hs_data["events"]),
                "timeline_count": len(hs_data["timeline"]),
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
                        "records_count": len(g["records"]),
                    }
                    for g in cl_data["groups"]
                ],
            },
        }
        json_path = Path(args.out_json).resolve()
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(json_summary, indent=2), encoding="utf-8")
        print(f"[unified_report] JSON report written to: {json_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
