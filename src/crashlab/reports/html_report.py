"""Self-contained HTML report generation.

Everything is inline (CSS, markup, escaped raw evidence). There are no external
fonts, scripts, images, or network references, so the report is portable and
safe to archive with the run directory.
"""

from __future__ import annotations

import html
import os
from pathlib import Path
from typing import Any, Iterable, Sequence

from crashlab.models import (
    AsanFinding,
    Classification,
    Confidence,
    CrashGroup,
    CrashRecord,
    GdbFindings,
    ReportConfig,
    StackFrame,
    group_by_signature,
)

_RAW_LIMIT = 200_000

_CSS = """
:root {
  --bg: #f5f7fb;
  --panel: #ffffff;
  --ink: #18212f;
  --muted: #5b6678;
  --line: #d8deea;
  --accent: #0b5cad;
  --accent-dark: #0f2742;
  --critical: #9f1239;
  --high: #b45309;
  --medium: #8a6100;
  --low: #475569;
  --ok: #166534;
  --code-bg: #0f172a;
  --code-ink: #e2e8f0;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.55;
}
.page-header {
  background: linear-gradient(135deg, #0f2742 0%, #144a7c 70%, #0e5f8a 100%);
  color: #f8fafc;
  padding: 2.4rem clamp(1rem, 4vw, 3.25rem) 2rem;
}
.page-header h1 {
  margin: 0.15rem 0 0.5rem;
  font-size: clamp(1.55rem, 3.4vw, 2.4rem);
  line-height: 1.18;
  letter-spacing: -0.015em;
}
.eyebrow {
  margin: 0;
  text-transform: uppercase;
  letter-spacing: 0.18em;
  font-size: 0.72rem;
  font-weight: 700;
  color: #9fd3ff;
}
.subtitle { margin: 0; color: #d4e6fa; max-width: 70ch; }
.notice {
  margin-top: 1.1rem;
  padding: 0.7rem 0.9rem;
  border-left: 4px solid #7dd3fc;
  background: rgba(8, 25, 44, 0.45);
  color: #e6f2ff;
  font-size: 0.9rem;
  max-width: 95ch;
}
.notice strong { color: #ffffff; }
main { max-width: 1200px; margin: 0 auto; padding: 1.6rem clamp(1rem, 3vw, 2rem) 4rem; }
section { margin-top: 1.6rem; }
h2 { font-size: 1.25rem; margin: 0 0 0.7rem; letter-spacing: -0.01em; }
h3 { font-size: 1.02rem; margin: 1.4rem 0 0.5rem; }
h4 { font-size: 0.95rem; margin: 1.25rem 0 0.4rem; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  font-size: 0.86em;
  background: #eef2f8;
  border: 1px solid #e0e6f0;
  border-radius: 4px;
  padding: 0.08rem 0.3rem;
  word-break: break-word;
}
pre {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  background: var(--code-bg);
  color: var(--code-ink);
  padding: 0.9rem 1rem;
  border-radius: 8px;
  overflow-x: auto;
  font-size: 0.82rem;
  line-height: 1.45;
  margin: 0.45rem 0 0.9rem;
}
pre code { background: none; border: 0; color: inherit; padding: 0; }
.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 1rem 1.1rem;
  box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
}
.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 0.75rem;
  margin: 0.4rem 0 1rem;
}
.stat {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 0.8rem 0.9rem;
}
.stat .value { font-size: 1.5rem; font-weight: 750; letter-spacing: -0.02em; }
.stat .label { color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.08em; }
.table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 10px; background: var(--panel); }
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
caption { text-align: left; padding: 0.7rem 0.8rem; color: var(--muted); font-size: 0.82rem; }
th, td { text-align: left; padding: 0.6rem 0.7rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: #edf2f9; font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.07em; color: #415066; }
tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: #f8fafd; }
.badges { display: flex; flex-wrap: wrap; gap: 0.35rem; align-items: center; }
.badge {
  display: inline-block;
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.02em;
  border-radius: 999px;
  padding: 0.16rem 0.55rem;
  border: 1px solid transparent;
  white-space: nowrap;
}
.badge.confirmed { background: #fde7ee; color: var(--critical); border-color: #f5b8c9; }
.badge.unconfirmed { background: #eef2f8; color: #334155; border-color: #d7dfec; }
.badge.high { background: #fde8d7; color: var(--high); border-color: #f3c39a; }
.badge.medium { background: #fff4cc; color: var(--medium); border-color: #f0d884; }
.badge.low { background: #eef2f8; color: var(--low); border-color: #d7dfec; }
.badge.signal { background: #e8f1ff; color: #1d4e89; border-color: #bdd6f7; }
.details-card {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 10px;
  margin: 0.9rem 0;
  overflow: hidden;
  box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
}
.details-card > summary {
  cursor: pointer;
  padding: 0.85rem 1rem;
  display: flex;
  flex-wrap: wrap;
  gap: 0.55rem;
  align-items: center;
  justify-content: space-between;
  list-style: none;
}
.details-card > summary::-webkit-details-marker { display: none; }
.details-card > summary::before {
  content: "\\25B8";
  color: var(--muted);
  font-size: 0.85rem;
  margin-right: 0.15rem;
}
.details-card[open] > summary::before { content: "\\25BE"; }
.details-card > summary:hover { background: #f8fafd; }
.summary-sig { font-weight: 650; overflow-wrap: anywhere; }
.summary-meta { color: var(--muted); font-size: 0.8rem; }
.crash-body { padding: 0 1rem 1.2rem; border-top: 1px solid var(--line); }
.triage {
  margin: 1rem 0;
  padding: 0.85rem 1rem;
  border-left: 4px solid var(--accent);
  background: #f1f7ff;
  border-radius: 0 8px 8px 0;
  white-space: pre-wrap;
}
.triage p { margin: 0; }
.facts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 0.55rem 1.4rem;
  margin: 0.8rem 0 0.4rem;
}
.fact { min-width: 0; }
.fact dt { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
.fact dd { margin: 0.1rem 0 0; overflow-wrap: anywhere; }
.muted { color: var(--muted); }
.warn { color: #92400e; }
.footer { margin-top: 2.2rem; color: var(--muted); font-size: 0.82rem; border-top: 1px solid var(--line); padding-top: 1rem; }
details.nested { margin: 0.5rem 0 0.9rem; }
details.nested > summary { cursor: pointer; color: var(--accent); font-weight: 600; font-size: 0.86rem; }
.raw { max-height: 26rem; }
@media (max-width: 720px) {
  .page-header { padding: 1.5rem 1rem 1.3rem; }
  main { padding: 1rem 0.75rem 3rem; }
  th, td { padding: 0.5rem; }
}
@media print {
  body { background: #ffffff; }
  .page-header { background: #ffffff; color: #000000; border-bottom: 2px solid #000000; }
  .eyebrow, .subtitle, .notice { color: #222222; }
  .notice { background: #ffffff; border-left-color: #000000; }
  details.details-card { break-inside: avoid; }
  pre { white-space: pre-wrap; }
  a { color: #000000; }
}
"""


def _e(value: Any) -> str:
    """HTML-escape any value (quotes included)."""

    return html.escape("" if value is None else str(value), quote=True)


def _anchor(run_id: str) -> str:
    safe = "".join(char if char.isalnum() or char in "-_" else "-" for char in run_id)
    return f"crash-{safe}"


def _badge(label: str, css_class: str) -> str:
    return f'<span class="badge {_e(css_class)}">{_e(label)}</span>'


def _classification_badge(classification: Classification) -> str:
    if classification is Classification.CONFIRMED_VULNERABILITY:
        return _badge("Confirmed vulnerability", "confirmed")
    return _badge("Crash, unconfirmed", "unconfirmed")


def _confidence_badge(confidence: Confidence) -> str:
    return _badge(f"Confidence: {confidence.value}", confidence.value)


def _signal_label(record: CrashRecord) -> str:
    if record.signal is not None:
        return record.signal.label
    return "fatal sanitizer exit (no signal)"


def _frame_location(frame: StackFrame) -> str:
    if frame.file:
        text = frame.file
        if frame.line:
            text += f":{frame.line}"
            if frame.column:
                text += f":{frame.column}"
        return text
    return frame.module or "—"


def _render_stack(frames: Sequence[StackFrame], *, empty: str) -> str:
    if not frames:
        return f'<p class="muted">{_e(empty)}</p>'
    rows: list[str] = []
    for frame in frames:
        rows.append(
            "<tr>"
            f"<td>{_e(frame.index)}</td>"
            f"<td><code>{_e(frame.function)}</code></td>"
            f"<td>{_e(_frame_location(frame))}</td>"
            f"<td><code>{_e(frame.address or '—')}</code></td>"
            f"<td>{_e(frame.module or '')}</td>"
            "</tr>"
        )
    return (
        '<div class="table-wrap"><table>'
        "<thead><tr><th scope=\"col\">#</th><th scope=\"col\">Function</th>"
        "<th scope=\"col\">Location</th><th scope=\"col\">Address</th>"
        "<th scope=\"col\">Module</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
    )


def _render_backtrace(gdb: GdbFindings) -> str:
    if not gdb.available:
        return (
            f'<p class="muted">GDB evidence unavailable: {_e(gdb.error or "not collected")}.</p>'
        )
    if gdb.error:
        return (
            f'<p class="warn">GDB error: {_e(gdb.error)}.</p>'
            + _render_stack(gdb.backtrace, empty="No stack frames parsed.")
        )
    return _render_stack(
        gdb.backtrace, empty="GDB ran but no stack frames were parsed from its output."
    )


def _render_registers(gdb: GdbFindings) -> str:
    if not gdb.registers:
        return '<p class="muted">No register dump available.</p>'
    keys = sorted(gdb.registers, key=lambda item: (item not in {"rip", "eip", "pc"}, item))
    rows = "".join(
        f"<tr><td><code>{_e(key)}</code></td><td><code>{_e(gdb.registers[key])}</code></td></tr>"
        for key in keys
    )
    return (
        '<div class="table-wrap"><table><thead><tr><th scope="col">Register</th>'
        f'<th scope="col">Value</th></tr></thead><tbody>{rows}</tbody></table></div>'
    )


def _read_limited(path: str | os.PathLike[str] | None) -> str | None:
    if not path:
        return None
    target = Path(path)
    if not target.is_file():
        return None
    try:
        with target.open("rb") as handle:
            data = handle.read(_RAW_LIMIT + 1)
    except OSError:
        return None
    text = data[:_RAW_LIMIT].decode("utf-8", errors="replace")
    if len(data) > _RAW_LIMIT:
        text += "\n... [truncated for report] ...\n"
    return text


def _render_raw(path: str | None, label: str) -> str:
    text = _read_limited(path)
    if text is None:
        return ""
    return (
        f'<details class="nested"><summary>{_e(label)}</summary>'
        f'<pre class="raw">{_e(text)}</pre></details>'
    )


def _render_asan(asan: AsanFinding | None, *, include_raw: bool) -> str:
    if asan is None:
        return (
            '<p class="muted">No AddressSanitizer report was available. The crash '
            "remains unconfirmed unless another evidence source names a memory-safety class.</p>"
        )
    access = "—"
    if asan.access_type and asan.access_size:
        access = f"{asan.access_type.upper()} of size {asan.access_size}"
    elif asan.access_type:
        access = asan.access_type.upper()
    facts = [
        ("Sanitizer", asan.sanitizer),
        ("Error type", asan.error_type),
        ("Normalized class", asan.vulnerability_class.value),
        ("Access", access),
        ("Faulting address", asan.fault_address or "—"),
        ("Thread", f"T{asan.thread_id}" if asan.thread_id is not None else "—"),
        ("PC", asan.pc or "—"),
        ("Region", asan.region or "—"),
        ("Region size", f"{asan.region_size} bytes" if asan.region_size is not None else "—"),
        ("Summary", asan.summary or "—"),
    ]
    fact_html = "".join(
        f'<div class="fact"><dt>{_e(key)}</dt><dd>{_e(value)}</dd></div>'
        for key, value in facts
    )
    parts = [f'<div class="facts">{fact_html}</div>']
    if asan.crash_stack:
        parts.append("<h4>Crash stack</h4>")
        parts.append(_render_stack(asan.crash_stack, empty=""))
    if asan.alloc_stack:
        parts.append("<h4>Allocation stack</h4>")
        parts.append(_render_stack(asan.alloc_stack, empty=""))
    if asan.free_stack:
        parts.append("<h4>Free stack</h4>")
        parts.append(_render_stack(asan.free_stack, empty=""))
    if include_raw:
        parts.append(_render_raw(asan.raw_output_path, "Raw sanitizer report"))
    return "".join(parts)


def _render_gdb(gdb: GdbFindings, *, include_raw: bool) -> str:
    parts = [
        '<div class="facts">'
        f'<div class="fact"><dt>Signal</dt><dd>{_e(gdb.signal_name or "—")}</dd></div>'
        f'<div class="fact"><dt>Fault address</dt><dd><code>{_e(gdb.fault_address or "—")}</code></dd></div>'
        f'<div class="fact"><dt>Program counter</dt><dd><code>{_e(gdb.pc or "—")}</code></dd></div>'
        f'<div class="fact"><dt>GDB exit</dt><dd>{_e(gdb.exit_code if gdb.exit_code is not None else "—")}</dd></div>'
        "</div>"
    ]
    if gdb.fault_instruction:
        parts.append("<h4>Faulting instruction</h4>")
        parts.append(f"<pre>{_e(gdb.fault_instruction)}</pre>")
    parts.append("<h4>Backtrace</h4>")
    parts.append(_render_backtrace(gdb))
    if gdb.disassembly:
        parts.append("<h4>Disassembly near $pc</h4>")
        parts.append(f"<pre>{_e(chr(10).join(gdb.disassembly))}</pre>")
    if gdb.registers:
        parts.append(
            '<details class="nested"><summary>Register dump '
            f"({len(gdb.registers)})</summary>{_render_registers(gdb)}</details>"
        )
    if include_raw:
        parts.append(_render_raw(gdb.raw_output_path, "Raw GDB batch output"))
    return "".join(parts)


def _render_correlation(record: CrashRecord) -> str:
    ref = record.runtime_trace_ref
    if ref is None:
        return '<p class="muted">No runtime trace reference was attached.</p>'
    facts = [
        ("Run ID", ref.run_id),
        ("Window start", ref.timestamp_start),
        ("Window end", ref.timestamp_end),
        ("Batch ID", ref.batch_id or "—"),
        ("Producer", ref.producer),
        ("Schema", ref.schema),
        ("Join keys", ", ".join(ref.join_keys)),
        ("Trace log", ref.log_path or "not attached yet"),
    ]
    body = "".join(
        f'<div class="fact"><dt>{_e(key)}</dt><dd>{_e(value)}</dd></div>'
        for key, value in facts
    )
    return f'<div class="facts">{body}</div>'


def _render_record(record: CrashRecord, *, open_by_default: bool, config: ReportConfig) -> str:
    anchor = _anchor(record.run_id)
    input_ref = record.input
    facts = [
        ("Run ID", record.run_id),
        ("Timestamp (UTC)", record.timestamp),
        ("Window start", record.timestamp_start or record.timestamp),
        ("Window end", record.timestamp_end or record.timestamp),
        ("Batch ID", record.batch_id or "—"),
        ("Signal", _signal_label(record)),
        ("Exit code", record.exit_code if record.exit_code is not None else "—"),
        ("Duration", f"{record.duration_ms} ms" if record.duration_ms is not None else "—"),
        ("Input mode", input_ref.mode.value),
        ("Input size", f"{input_ref.size} bytes"),
        ("Input SHA-256", input_ref.sha256),
        ("Original input", input_ref.original_path or "(stdin payload)"),
        ("Signature method", record.signature_method),
        ("Evidence sources", ", ".join(record.evidence_sources) or "—"),
        ("Run directory", record.run_dir or "—"),
    ]
    fact_html = "".join(
        f'<div class="fact"><dt>{_e(key)}</dt><dd>{_e(value)}</dd></div>'
        for key, value in facts
    )
    triage = "".join(f"<p>{_e(line)}</p>" for line in record.triage_summary.splitlines() if line)

    open_attr = " open" if open_by_default else ""
    return f"""
<details class="details-card" id="{_e(anchor)}"{open_attr}>
  <summary>
    <span class="summary-sig">{_e(record.crash_signature)}</span>
    <span class="badges">
      {_classification_badge(record.classification)}
      {_confidence_badge(record.confidence)}
      <span class="badge signal">{_e(_signal_label(record))}</span>
      <span class="summary-meta">run {_e(record.run_id)}</span>
    </span>
  </summary>
  <div class="crash-body">
    <div class="triage">{triage}</div>
    <dl class="facts">{fact_html}</dl>

    <h3>Vulnerability assessment</h3>
    <p><strong>Likely class:</strong> <code>{_e(record.vulnerability_class.value)}</code>
       &nbsp;·&nbsp; <strong>Classification:</strong> {_e(record.classification.value)}
       &nbsp;·&nbsp; <strong>Confidence:</strong> {_e(record.confidence.value)}</p>
    <p>{_e(record.suspected_root_cause)}</p>

    <h3>Reproduction</h3>
    <p class="muted">Exact invocation recorded by the runner (environment overrides included).</p>
    <pre><code>{_e(record.reproduction_command)}</code></pre>

    <h3>GDB evidence</h3>
    {_render_gdb(record.gdb, include_raw=config.include_raw_evidence)}

    <h3>AddressSanitizer evidence</h3>
    {_render_asan(record.asan, include_raw=config.include_raw_evidence)}

    <h3>Mitigation notes</h3>
    <p>{_e(record.mitigation_notes)}</p>

    <h3>Runtime-correlation keys</h3>
    {_render_correlation(record)}
    <p class="muted">Join Person 1's runtime-event records on <code>run_id</code>, or on the
    timestamp window when events were captured out-of-band. The target receives
    <code>CRASHLAB_RUN_ID</code> and <code>CRASHLAB_BATCH_ID</code> in its environment.</p>
  </div>
</details>
"""


def _render_summary(groups: Sequence[CrashGroup]) -> str:
    rows: list[str] = []
    row_number = 0
    for group in groups:
        representative = group.representative
        row_number += 1
        rows.append(
            "<tr>"
            f"<td>{row_number}</td>"
            f'<td><a href="#{_e(_anchor(representative.run_id))}"><code>{_e(group.signature_hash)}</code></a>'
            f'<div class="summary-meta">{_e(group.crash_signature)}</div></td>'
            f"<td><code>{_e(group.vulnerability_class.value)}</code></td>"
            f"<td>{_classification_badge(group.classification)}</td>"
            f"<td>{_confidence_badge(group.confidence)}</td>"
            f"<td>{_e(_signal_label(representative))}</td>"
            f"<td>{_e(len(group.records))}</td>"
            f"<td>{_e(len(group.input_hashes))}</td>"
            "</tr>"
        )
    return (
        '<div class="table-wrap"><table>'
        '<caption>One row per unique crash signature. Expand a row target below for '
        "full evidence.</caption>"
        '<thead><tr><th scope="col">#</th><th scope="col">Signature</th>'
        '<th scope="col">Likely class</th><th scope="col">Classification</th>'
        '<th scope="col">Confidence</th><th scope="col">Signal</th>'
        '<th scope="col">Crashes</th><th scope="col">Inputs</th></tr></thead><tbody>'
        + "".join(rows)
        + "</tbody></table></div>"
    )


def render_html(
    records: Iterable[CrashRecord],
    config: ReportConfig | None = None,
) -> str:
    """Render a complete, self-contained HTML report."""

    config = config or ReportConfig()
    records = list(records)
    groups = group_by_signature(records)

    total = len(records)
    confirmed = sum(1 for record in records if record.is_confirmed)
    unique_inputs = len({record.input.sha256 for record in records})
    high_confidence = sum(1 for record in records if record.confidence is Confidence.HIGH)

    if not records:
        empty_notice = (
            '<div class="panel"><h2>No crash records</h2>'
            '<p class="muted">No crashes were analyzed. Run <code>crashlab run</code> and '
            "<code>crashlab analyze</code> first.</p></div>"
        )
        details = empty_notice
    else:
        details = ""
        for index, group in enumerate(groups):
            for record_index, record in enumerate(group.records):
                details += _render_record(
                    record,
                    open_by_default=(index == 0 and record_index == 0),
                    config=config,
                )

    summary = _render_summary(groups) if groups else ""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="crashlab">
<title>{_e(config.title)}</title>
<style>{_CSS}</style>
</head>
<body>
<header class="page-header">
  <p class="eyebrow">Crashlab · defensive memory-safety research</p>
  <h1>{_e(config.title)}</h1>
  <p class="subtitle">{_e(config.subtitle)}</p>
  <div class="notice"><strong>Manual triage required.</strong> A crash is not the same as a
  confirmed vulnerability. This report never auto-promotes a bare signal; read the
  evidence and classification on each record before assigning severity.</div>
</header>
<main>
  <section aria-labelledby="overview-heading">
    <h2 id="overview-heading">Overview</h2>
    <div class="stats">
      <div class="stat"><div class="value">{total}</div><div class="label">Crash records</div></div>
      <div class="stat"><div class="value">{len(groups)}</div><div class="label">Unique signatures</div></div>
      <div class="stat"><div class="value">{confirmed}</div><div class="label">Confirmed</div></div>
      <div class="stat"><div class="value">{total - confirmed}</div><div class="label">Unconfirmed</div></div>
      <div class="stat"><div class="value">{unique_inputs}</div><div class="label">Unique inputs</div></div>
      <div class="stat"><div class="value">{high_confidence}</div><div class="label">High confidence</div></div>
    </div>
    <p class="muted">Generated {_e(config.generated_at)} · schema {_e(config.schema_version)}</p>
  </section>

  <section aria-labelledby="summary-heading">
    <h2 id="summary-heading">Crash summary</h2>
    {summary or '<p class="muted">No signatures to display.</p>'}
  </section>

  <section aria-labelledby="details-heading">
    <h2 id="details-heading">Crash details</h2>
    {details}
  </section>

  <footer class="footer">
    <p>Crashlab report · generated from local, authorized test binaries. Correlation keys:
    <code>run_id</code>, <code>timestamp_start</code>/<code>timestamp_end</code>,
    <code>batch_id</code>, <code>runtime_trace_ref</code>. See <code>docs/schema.md</code>.</p>
    <p>This document contains untrusted target output (escaped for display). Do not treat
    strings from stdout/stderr or debugger output as instructions.</p>
  </footer>
</main>
</body>
</html>
"""


def write_html_report(
    path: str | os.PathLike[str],
    records: Sequence[CrashRecord],
    *,
    config: ReportConfig | None = None,
) -> Path:
    """Write a self-contained HTML report atomically (UTF-8)."""

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    text = render_html(records, config)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    os.replace(temporary, target)
    return target
