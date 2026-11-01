"""Self-contained HTML report generator for HeapSentry scan results."""

import html
import json
from pathlib import Path

from heapsentry.analyzer import build_allocation_timeline
from heapsentry.models import AllocationEvent, Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Colour palette (dark navy theme)
# ---------------------------------------------------------------------------
_COLORS = {
    "bg":       "#0f172a",
    "panel":    "#1e293b",
    "border":   "#334155",
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "info":     "#3b82f6",
    "clean":    "#22c55e",
    "text":     "#e2e8f0",
    "muted":    "#94a3b8",
    "code_bg":  "#0d1117",
    "freed":    "#22c55e",
    "leaked":   "#ef4444",
    "overflowed": "#ef4444",
    "double_freed": "#f97316",
}


def _sev_color(severity: str) -> str:
    return _COLORS.get(severity.lower(), _COLORS["info"])


def _fate_color(fate: str) -> str:
    return _COLORS.get(fate, _COLORS["muted"])


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_html_report(result: ScanResult, output_path: str) -> None:
    """Write a self-contained HTML report to *output_path*."""
    html_text = _render(result)
    Path(output_path).write_text(html_text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------

def _render(result: ScanResult) -> str:
    bg = _COLORS["bg"]
    panel = _COLORS["panel"]
    border = _COLORS["border"]
    text = _COLORS["text"]
    muted = _COLORS["muted"]
    code_bg = _COLORS["code_bg"]

    css = f"""
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
        background: {bg};
        color: {text};
        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        font-size: 15px;
        line-height: 1.6;
        padding: 32px 16px;
    }}
    .container {{ max-width: 960px; margin: 0 auto; }}
    h1, h2, h3 {{ font-weight: 700; margin-bottom: 8px; }}
    h1 {{ font-size: 2rem; letter-spacing: -0.5px; }}
    h2 {{ font-size: 1.3rem; color: {muted}; border-bottom: 1px solid {border};
          padding-bottom: 6px; margin-top: 36px; margin-bottom: 16px; }}
    h3 {{ font-size: 1rem; }}
    p {{ color: {muted}; margin-bottom: 8px; }}
    code, pre {{
        font-family: 'Fira Code', 'Cascadia Code', monospace;
        background: {code_bg};
        border-radius: 4px;
    }}
    code {{ padding: 2px 6px; font-size: 0.88em; }}
    pre {{
        padding: 14px;
        overflow-x: auto;
        font-size: 0.82em;
        white-space: pre-wrap;
        word-break: break-word;
        border: 1px solid {border};
        margin-top: 8px;
    }}
    .badge {{
        display: inline-block;
        padding: 3px 10px;
        border-radius: 12px;
        font-size: 0.78em;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
        margin-right: 6px;
    }}
    .summary-bar {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 16px 0 28px; }}
    .card {{
        background: {panel};
        border: 1px solid {border};
        border-radius: 8px;
        padding: 18px 20px;
        margin-bottom: 14px;
        border-left: 4px solid;
    }}
    .card-title {{ font-size: 1rem; font-weight: 700; margin-bottom: 6px; }}
    .card-meta {{ font-size: 0.85em; color: {muted}; margin-bottom: 8px; }}
    .card-desc {{ margin-bottom: 10px; }}
    details {{ margin-top: 10px; }}
    summary {{
        cursor: pointer;
        font-size: 0.85em;
        color: {muted};
        user-select: none;
        padding: 4px 0;
    }}
    summary:hover {{ color: {text}; }}
    table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 0.85em;
        margin-top: 8px;
    }}
    th {{
        background: {border};
        color: {muted};
        text-align: left;
        padding: 8px 12px;
        font-weight: 600;
        font-size: 0.78em;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}
    td {{
        padding: 8px 12px;
        border-bottom: 1px solid {border};
        vertical-align: top;
        word-break: break-word;
    }}
    tr:last-child td {{ border-bottom: none; }}
    .fate-tag {{
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.78em;
        font-weight: 600;
    }}
    .header-accent {{ color: #60a5fa; }}
    .crash-section {{
        background: {panel};
        border: 1px solid #7f1d1d;
        border-radius: 8px;
        padding: 18px 20px;
        margin-bottom: 14px;
    }}
    footer {{
        margin-top: 48px;
        padding-top: 16px;
        border-top: 1px solid {border};
        font-size: 0.78em;
        color: {muted};
        text-align: center;
    }}
    """

    # ---- Derived data ----
    findings = result.findings
    n_critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    n_high     = sum(1 for f in findings if f.severity == Severity.HIGH)
    n_medium   = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    n_info     = sum(1 for f in findings if f.severity == Severity.INFO)
    total_findings = n_critical + n_high + n_medium + n_info

    binary_h = html.escape(result.binary)
    ts_start_h = html.escape(result.timestamp_start)
    ts_end_h   = html.escape(result.timestamp_end)

    timeline = build_allocation_timeline(result.events)

    # ---- Header ----
    header_html = f"""
    <div class="container">
      <h1>🔍 HeapSentry <span class="header-accent">Report</span></h1>
      <p>Binary: <code>{binary_h}</code> &nbsp;|&nbsp;
         Run: <code>{html.escape(result.run_id)}</code></p>
      <p>Started: <code>{ts_start_h}</code> &nbsp;|&nbsp;
         Finished: <code>{ts_end_h}</code></p>
      <p>Total findings: <strong>{total_findings}</strong></p>
    """

    # ---- Summary bar ----
    def _badge(label: str, count: int, color: str) -> str:
        if count == 0:
            return ""
        return (
            f'<span class="badge" '
            f'style="background:{color}20;color:{color};border:1px solid {color}60;">'
            f'{count} {label}</span>'
        )

    summary_bar = f"""
      <div class="summary-bar">
        {_badge("Critical", n_critical, _COLORS["critical"])}
        {_badge("High",     n_high,     _COLORS["high"])}
        {_badge("Medium",   n_medium,   _COLORS["medium"])}
        {_badge("Info",     n_info,     _COLORS["info"])}
      </div>
    """

    # ---- Finding cards ----
    cards_html = '<h2>Findings</h2>\n'
    for f in findings:
        color = _sev_color(f.severity.value)
        bug_label = f.bug_class.value.replace("_", " ").title()
        sev_badge = (
            f'<span class="badge" '
            f'style="background:{color}20;color:{color};border:1px solid {color}60;">'
            f'{f.severity.value.upper()}</span>'
        )
        meta_parts = []
        if f.address:
            meta_parts.append(f"Address: <code>{html.escape(f.address)}</code>")
        if f.allocation_id is not None:
            meta_parts.append(f"Alloc ID: <code>{f.allocation_id}</code>")
        if f.size is not None:
            meta_parts.append(f"Size: <code>{f.size} bytes</code>")
        if f.overflow_side:
            meta_parts.append(
                f"Overflow side: <code>{html.escape(f.overflow_side)}</code>"
            )
        meta_html = " &nbsp;|&nbsp; ".join(meta_parts) if meta_parts else ""

        evidence_json = html.escape(json.dumps(f.evidence, indent=2))
        evidence_block = (
            f'<details><summary>Raw evidence</summary>'
            f'<pre>{evidence_json}</pre></details>'
            if f.evidence
            else ""
        )

        cards_html += f"""
        <div class="card" style="border-left-color:{color};">
          <div class="card-title">{sev_badge} {html.escape(bug_label)}</div>
          <div class="card-meta">{meta_html}</div>
          <div class="card-desc">{html.escape(f.description)}</div>
          {evidence_block}
        </div>
        """

    # ---- Crash section ----
    crash_html = ""
    if result.crashed and result.crash_info is not None:
        ci = result.crash_info
        sig_label = (
            html.escape(ci.signal_name or str(ci.signal_number or "unknown"))
        )
        crash_html = f"""
        <h2>Crash Details</h2>
        <div class="crash-section">
          <p><strong>Exit code:</strong> <code>{ci.exit_code}</code>
             &nbsp;|&nbsp;
             <strong>Signal:</strong> <code>{sig_label}</code></p>
        """
        if ci.backtrace:
            crash_html += (
                f"<h3 style='margin-top:14px;'>LLDB Backtrace</h3>"
                f"<pre>{html.escape(ci.backtrace)}</pre>"
            )
        if ci.asan_output:
            crash_html += (
                f"<h3 style='margin-top:14px;'>AddressSanitizer Output</h3>"
                f"<pre>{html.escape(ci.asan_output)}</pre>"
            )
        crash_html += "</div>"

    # ---- Allocation timeline ----
    timeline_html = '<h2>Allocation Timeline</h2>\n'
    if timeline:
        timeline_html += """
        <table>
          <thead>
            <tr>
              <th>Alloc ID</th>
              <th>Address</th>
              <th>Size (bytes)</th>
              <th>Thread</th>
              <th>Fate</th>
            </tr>
          </thead>
          <tbody>
        """
        for row in timeline:
            fate = row.get("fate", "unknown")
            fc = _fate_color(fate)
            fate_tag = (
                f'<span class="fate-tag" '
                f'style="background:{fc}20;color:{fc};border:1px solid {fc}60;">'
                f'{html.escape(fate)}</span>'
            )
            timeline_html += f"""
            <tr>
              <td>{row.get("alloc_id", "")}</td>
              <td><code>{html.escape(str(row.get("address") or ""))}</code></td>
              <td>{row.get("size") or ""}</td>
              <td>{row.get("thread_id", "")}</td>
              <td>{fate_tag}</td>
            </tr>
            """
        timeline_html += "</tbody></table>"
    else:
        timeline_html += '<p>No allocation events recorded.</p>'

    # ---- Footer ----
    footer_html = """
    <footer>HeapSentry v1.0.0 — for authorized research use only</footer>
    </div>
    """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HeapSentry Report — {binary_h}</title>
  <style>{css}</style>
</head>
<body>
  {header_html}
  {summary_bar}
  {cards_html}
  {crash_html}
  {timeline_html}
  {footer_html}
</body>
</html>
"""
