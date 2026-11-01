"""Self-contained HTML report generator for HeapSentry scan results.

Generates a premium, dark-themed HTML report with:
- Severity badges & summary ring chart
- Per-finding cards with exploit impact + remediation
- Full event timeline with timestamps and canary data
- Vulnerability demo / code pattern reference
- Responsive, animated UI
"""

import html
import json
from pathlib import Path

from heapsentry.analyzer import build_allocation_timeline
from heapsentry.models import AllocationEvent, Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Colour palette
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
    "freed":        "#2ed573",
    "leaked":       "#ff4757",
    "overflowed":   "#ff4757",
    "double_freed": "#ff6b35",
    "use_after_freed": "#a855f7",
}

# ---------------------------------------------------------------------------
# Per-bug-class metadata: impact, remediation, example C pattern
# ---------------------------------------------------------------------------
_BUG_META = {
    "heap_buffer_overflow": {
        "icon": "💥",
        "impact": (
            "An attacker can overwrite adjacent heap metadata or object data, "
            "enabling arbitrary code execution (ACE), privilege escalation, or "
            "controlled data corruption. This is one of the most exploited "
            "vulnerability classes in modern exploit chains (e.g., CVE-2021-3156, "
            "CVE-2014-6271 Shellshock)."
        ),
        "remediation": [
            "Always validate buffer lengths before copying: use <code>strncpy</code>/<code>strlcpy</code> instead of <code>strcpy</code>.",
            "Prefer safe allocation helpers: <code>malloc(sizeof(T) * n + guard)</code> with explicit bounds.",
            "Enable compiler mitigations: <code>-fsanitize=address</code> (ASan), <code>-D_FORTIFY_SOURCE=2</code>.",
            "Use memory-safe languages (Rust, Go) for new code; apply buffer-overflow-safe wrappers in C/C++.",
            "Deploy exploit mitigations: stack canaries, ASLR, PIE, RELRO.",
        ],
        "code_bad": """\
char *buf = malloc(16);          // allocates 16 bytes
strcpy(buf, user_input);         // ❌ no bounds check — overflows if input > 15 chars
                                 //    corrupts adjacent heap metadata""",
        "code_good": """\
char *buf = malloc(16);
strncpy(buf, user_input, 15);    // ✅ bounded copy
buf[15] = '\\0';                  //    always null-terminate""",
    },
    "double_free": {
        "icon": "♻️",
        "impact": (
            "Freeing the same pointer twice corrupts the allocator's free-list, "
            "enabling heap layout manipulation. Exploited to achieve write-what-where "
            "primitives (e.g., tcache poisoning in glibc ≥ 2.26) leading to RCE."
        ),
        "remediation": [
            "Set pointers to <code>NULL</code> immediately after <code>free()</code>: <code>free(p); p = NULL;</code>",
            "Use smart pointers in C++ (<code>std::unique_ptr</code>, <code>std::shared_ptr</code>) that auto-null on destruction.",
            "Apply ownership discipline: a single owner per allocation, clearly documented.",
            "Use static analysis tools (Coverity, CodeChecker, clang-analyzer) to detect double-free paths.",
        ],
        "code_bad": """\
free(ptr);
// ... other code ...
free(ptr);   // ❌ double-free — corrupts allocator free-list""",
        "code_good": """\
free(ptr);
ptr = NULL;  // ✅ poison the pointer immediately
// ... other code ...
if (ptr) free(ptr);  // safe — NULL check guards the free""",
    },
    "use_after_free_write": {
        "icon": "👻",
        "impact": (
            "Writing to memory after it has been freed can corrupt a newly-allocated "
            "object that occupies the same address. Attackers 'spray' the heap to "
            "control what gets allocated there, turning UAF into type confusion or "
            "RCE. Highly prevalent in browser and kernel exploits "
            "(e.g., CVE-2022-0185, Pwn2Own targets)."
        ),
        "remediation": [
            "Zero-out or poison freed memory before calling <code>free()</code> to limit information disclosure.",
            "Set the pointer to <code>NULL</code> after freeing to catch accidental dereferences early.",
            "Use C++ RAII wrappers / smart pointers; avoid raw owning pointers.",
            "Enable <code>-fsanitize=address</code> and <code>-fsanitize=memory</code> in CI.",
            "Apply heap hardening: MiMalloc delayed-free, jemalloc with <code>opt.zero=true</code>.",
        ],
        "code_bad": """\
Object *obj = malloc(sizeof(Object));
// ... use obj ...
free(obj);
obj->field = 42;   // ❌ use-after-free write — obj memory may be reallocated""",
        "code_good": """\
Object *obj = malloc(sizeof(Object));
// ... use obj ...
free(obj);
obj = NULL;         // ✅ immediately poison
// obj->field = 42; // ✅ would now crash deterministically (NULL deref)""",
    },
    "memory_leak": {
        "icon": "🕳️",
        "impact": (
            "Unreleased heap memory grows unboundedly, causing performance degradation "
            "and eventual out-of-memory crashes in long-running processes. In some "
            "contexts leaked memory can contain sensitive data (keys, credentials) "
            "readable by a later allocation."
        ),
        "remediation": [
            "Every <code>malloc()</code>/<code>new</code> must have a matching <code>free()</code>/<code>delete</code> on all code paths.",
            "Prefer RAII in C++ — let destructors handle cleanup automatically.",
            "Use <code>valgrind --leak-check=full</code> or ASan leak detection in CI.",
            "Adopt arena allocators or region-based memory for complex lifetimes.",
        ],
        "code_bad": """\
void process() {
    char *buf = malloc(4096);
    if (error_condition) return;  // ❌ early return leaks buf
    // ...
    free(buf);
}""",
        "code_good": """\
void process() {
    char *buf = malloc(4096);
    if (error_condition) {
        free(buf);  // ✅ free on every exit path
        return;
    }
    // ...
    free(buf);
}""",
    },
    "crash": {
        "icon": "💀",
        "impact": (
            "The process terminated abnormally. Without a specific memory-safety "
            "event, this may indicate a signal received from outside (SIGHUP/SIGTERM), "
            "an assertion failure, or an unhandled exception. Further investigation "
            "with a debugger and input minimisation is recommended."
        ),
        "remediation": [
            "Reproduce with LLDB/GDB attached to obtain a backtrace.",
            "Run with ASan/UBSan to surface the root cause as a structured finding.",
            "Check for missing signal handlers if SIGHUP/SIGPIPE is the culprit.",
        ],
        "code_bad": None,
        "code_good": None,
    },
    "clean": {
        "icon": "✅",
        "impact": "No memory-safety issues were detected in this scan.",
        "remediation": [
            "Continue using HeapSentry in CI to catch regressions early.",
            "Expand corpus coverage with AFL++ or libFuzzer-generated inputs.",
        ],
        "code_bad": None,
        "code_good": None,
    },
}


def _sev_color(severity: str) -> str:
    return _COLORS.get(severity.lower(), _COLORS["info"])


def _fate_color(fate: str) -> str:
    return _COLORS.get(fate, _COLORS["muted"])


def _ns_to_us(ns: int) -> str:
    """Convert nanoseconds to human-readable µs."""
    if ns == 0:
        return "–"
    return f"{ns / 1_000:.1f} µs"


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
# Public API
# ---------------------------------------------------------------------------

def write_html_report(result: ScanResult, output_path: str) -> None:
    """Write a self-contained HTML report to *output_path*."""
    html_text = _render(result)
    Path(output_path).write_text(html_text, encoding="utf-8")


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

def _build_css() -> str:
    C = _COLORS
    return f"""
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    :root {{
        --bg: {C['bg']};
        --panel: {C['panel']};
        --panel2: {C['panel2']};
        --border: {C['border']};
        --border2: {C['border2']};
        --text: {C['text']};
        --muted: {C['muted']};
        --accent: {C['accent']};
        --critical: {C['critical']};
        --high: {C['high']};
        --medium: {C['medium']};
        --info: {C['info']};
        --clean: {C['clean']};
        --code-bg: {C['code_bg']};
    }}

    html {{ scroll-behavior: smooth; }}

    body {{
        background: var(--bg);
        color: var(--text);
        font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
        font-size: 14px;
        line-height: 1.65;
        padding: 0;
        min-height: 100vh;
        background-image:
            radial-gradient(ellipse at 10% 0%, rgba(0,212,255,0.05) 0%, transparent 60%),
            radial-gradient(ellipse at 90% 100%, rgba(255,71,87,0.04) 0%, transparent 60%);
    }}

    /* ---- Layout ---- */
    .topbar {{
        background: rgba(10,15,30,0.95);
        border-bottom: 1px solid var(--border);
        backdrop-filter: blur(12px);
        position: sticky;
        top: 0;
        z-index: 100;
        padding: 12px 24px;
        display: flex;
        align-items: center;
        gap: 16px;
    }}
    .topbar-logo {{ font-size: 1.2rem; font-weight: 800; letter-spacing: -0.5px; }}
    .topbar-logo span {{ color: var(--accent); }}
    .topbar-meta {{ font-size: 0.78em; color: var(--muted); margin-left: auto; }}
    .topbar-meta code {{ color: var(--text); background: var(--border); padding: 2px 6px; border-radius: 4px; }}

    .container {{ max-width: 1060px; margin: 0 auto; padding: 36px 20px 80px; }}

    /* ---- Typography ---- */
    h1 {{ font-size: 2.2rem; font-weight: 800; letter-spacing: -1px; line-height: 1.2; margin-bottom: 6px; }}
    h2 {{
        font-size: 0.72em; font-weight: 700; letter-spacing: 2px; text-transform: uppercase;
        color: var(--muted); margin-top: 48px; margin-bottom: 16px;
        padding-bottom: 8px; border-bottom: 1px solid var(--border);
        display: flex; align-items: center; gap: 8px;
    }}
    h2::before {{ content: ''; display: inline-block; width: 3px; height: 14px;
                  background: var(--accent); border-radius: 2px; }}
    h3 {{ font-size: 0.92rem; font-weight: 600; margin-bottom: 6px; }}
    p {{ color: var(--muted); margin-bottom: 8px; font-size: 0.9em; }}
    strong {{ color: var(--text); }}

    /* ---- Code ---- */
    code, pre {{
        font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
        background: var(--code-bg);
        border-radius: 4px;
        font-size: 0.83em;
    }}
    code {{ padding: 2px 6px; border: 1px solid var(--border); }}
    pre {{
        padding: 16px 18px;
        overflow-x: auto;
        white-space: pre;
        border: 1px solid var(--border);
        margin-top: 8px;
        line-height: 1.55;
        position: relative;
    }}
    pre .line-good {{ color: #2ed573; }}
    pre .line-bad  {{ color: #ff4757; }}

    /* ---- Badges ---- */
    .badge {{
        display: inline-flex; align-items: center; gap: 5px;
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 0.72em;
        font-weight: 700;
        letter-spacing: 0.8px;
        text-transform: uppercase;
        white-space: nowrap;
    }}
    .badge-dot {{ width: 6px; height: 6px; border-radius: 50%; }}

    /* ---- Summary grid ---- */
    .summary-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
        gap: 12px;
        margin: 24px 0;
    }}
    .stat-card {{
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 18px 16px;
        text-align: center;
        transition: transform 0.2s, border-color 0.2s;
    }}
    .stat-card:hover {{ transform: translateY(-2px); border-color: var(--border2); }}
    .stat-card .stat-num {{
        font-size: 2.2rem; font-weight: 800; line-height: 1;
        margin-bottom: 4px;
    }}
    .stat-card .stat-label {{
        font-size: 0.72em; font-weight: 600; letter-spacing: 1px;
        text-transform: uppercase; color: var(--muted);
    }}

    /* ---- Finding cards ---- */
    .finding-card {{
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 20px 22px;
        margin-bottom: 16px;
        border-left: 4px solid;
        transition: box-shadow 0.2s, transform 0.2s;
        position: relative;
        overflow: hidden;
    }}
    .finding-card::before {{
        content: '';
        position: absolute; inset: 0;
        background: linear-gradient(135deg, rgba(255,255,255,0.015) 0%, transparent 60%);
        pointer-events: none;
    }}
    .finding-card:hover {{
        box-shadow: 0 8px 40px rgba(0,0,0,0.4);
        transform: translateY(-1px);
    }}
    .card-header {{ display: flex; align-items: flex-start; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }}
    .card-icon {{ font-size: 1.5rem; line-height: 1; flex-shrink: 0; margin-top: 2px; }}
    .card-title-block {{ flex: 1 }}
    .card-title {{ font-size: 1.05rem; font-weight: 700; color: var(--text); display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
    .card-subtitle {{ font-size: 0.8em; color: var(--muted); margin-top: 4px; display: flex; flex-wrap: wrap; gap: 10px; }}
    .card-subtitle .pill {{
        display: inline-flex; align-items: center; gap: 5px;
        background: var(--panel2); border: 1px solid var(--border2);
        border-radius: 6px; padding: 2px 8px; font-size: 0.88em;
    }}

    /* ---- Tabs inside card ---- */
    .card-tabs {{ display: flex; gap: 2px; margin-bottom: 12px; margin-top: 14px; border-bottom: 1px solid var(--border); }}
    .tab-btn {{
        background: none; border: none; color: var(--muted);
        padding: 6px 14px; font-size: 0.78em; font-weight: 600;
        letter-spacing: 0.5px; text-transform: uppercase; cursor: pointer;
        border-bottom: 2px solid transparent; margin-bottom: -1px;
        transition: color 0.15s, border-color 0.15s;
        font-family: inherit;
    }}
    .tab-btn:hover {{ color: var(--text); }}
    .tab-btn.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
    .tab-pane {{ display: none; }}
    .tab-pane.active {{ display: block; }}

    /* ---- Impact / remediation blocks ---- */
    .impact-block {{
        background: rgba(255,71,87,0.06);
        border: 1px solid rgba(255,71,87,0.2);
        border-radius: 8px;
        padding: 12px 14px;
        font-size: 0.87em;
        color: var(--text);
        line-height: 1.6;
        margin-bottom: 10px;
    }}
    .impact-block.clean {{
        background: rgba(46,213,115,0.06);
        border-color: rgba(46,213,115,0.2);
    }}
    .remediation-list {{
        list-style: none;
        padding: 0;
        display: flex;
        flex-direction: column;
        gap: 6px;
        margin-top: 8px;
    }}
    .remediation-list li {{
        display: flex; gap: 8px; align-items: flex-start;
        font-size: 0.86em; color: var(--text);
    }}
    .remediation-list li::before {{
        content: '→';
        color: var(--clean);
        font-weight: 700;
        flex-shrink: 0;
        margin-top: 1px;
    }}

    /* ---- Code comparison ---- */
    .code-compare {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 10px; }}
    @media (max-width: 700px) {{ .code-compare {{ grid-template-columns: 1fr; }} }}
    .code-block-label {{
        font-size: 0.72em; font-weight: 700; letter-spacing: 1px; text-transform: uppercase;
        margin-bottom: 4px; display: flex; align-items: center; gap: 6px;
    }}

    /* ---- Raw evidence ---- */
    details {{ margin-top: 10px; }}
    summary {{
        cursor: pointer; font-size: 0.79em; color: var(--muted);
        user-select: none; padding: 4px 0;
        display: flex; align-items: center; gap: 6px;
    }}
    summary::marker {{ display: none; }}
    summary::-webkit-details-marker {{ display: none; }}
    summary::before {{ content: '▶'; font-size: 0.65em; transition: transform 0.15s; }}
    details[open] summary::before {{ transform: rotate(90deg); }}
    summary:hover {{ color: var(--text); }}

    /* ---- Timeline table ---- */
    .timeline-wrap {{ overflow-x: auto; border-radius: 10px; border: 1px solid var(--border); }}
    table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 0.83em;
        min-width: 600px;
    }}
    thead tr {{ background: var(--panel2); }}
    th {{
        color: var(--muted); text-align: left;
        padding: 10px 14px; font-weight: 600; font-size: 0.75em;
        text-transform: uppercase; letter-spacing: 0.8px;
        white-space: nowrap;
    }}
    td {{
        padding: 9px 14px;
        border-bottom: 1px solid var(--border);
        vertical-align: middle;
        word-break: break-word;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tbody tr {{ transition: background 0.12s; }}
    tbody tr:hover {{ background: var(--panel2); }}

    .fate-tag {{
        display: inline-flex; align-items: center; gap: 4px;
        padding: 2px 9px;
        border-radius: 6px;
        font-size: 0.78em;
        font-weight: 700;
    }}

    /* ---- Event log table ---- */
    .event-type {{ font-weight: 600; }}
    .event-ok {{ color: var(--clean); }}
    .event-error {{ color: var(--critical); }}
    .canary {{ font-family: 'JetBrains Mono', monospace; font-size: 0.8em; color: #f97316; }}

    /* ---- Crash box ---- */
    .crash-box {{
        background: rgba(255,71,87,0.07);
        border: 1px solid rgba(255,71,87,0.3);
        border-radius: 10px;
        padding: 18px 20px;
        margin-bottom: 14px;
    }}
    .crash-box h3 {{ color: var(--critical); margin-bottom: 8px; }}
    .crash-box pre {{ border-color: rgba(255,71,87,0.3); }}

    /* ---- Vuln reference ---- */
    .vuln-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 14px;
        margin-top: 4px;
    }}
    .vuln-ref-card {{
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 16px 18px;
        transition: border-color 0.2s, transform 0.2s;
    }}
    .vuln-ref-card:hover {{ border-color: var(--border2); transform: translateY(-1px); }}
    .vuln-ref-title {{ font-size: 0.92rem; font-weight: 700; margin-bottom: 6px; display: flex; align-items: center; gap: 8px; }}
    .vuln-ref-desc {{ font-size: 0.82em; color: var(--muted); line-height: 1.55; }}

    /* ---- Meta info bar ---- */
    .meta-bar {{
        display: flex; flex-wrap: wrap; gap: 8px;
        margin-bottom: 28px; margin-top: 8px;
    }}
    .meta-pill {{
        background: var(--panel); border: 1px solid var(--border);
        border-radius: 8px; padding: 6px 12px;
        font-size: 0.78em; color: var(--muted);
        display: flex; align-items: center; gap: 6px;
    }}
    .meta-pill strong {{ color: var(--text); }}

    /* ---- Section divider ---- */
    .section-note {{
        font-size: 0.79em; color: var(--muted); margin-bottom: 16px;
        padding: 8px 12px; background: var(--panel); border-radius: 6px;
        border-left: 3px solid var(--border2);
    }}

    /* ---- Footer ---- */
    footer {{
        margin-top: 64px; padding-top: 18px;
        border-top: 1px solid var(--border);
        font-size: 0.75em; color: var(--muted); text-align: center;
    }}
    footer a {{ color: var(--accent); text-decoration: none; }}

    /* ---- Animations ---- */
    @keyframes fadeInUp {{
        from {{ opacity: 0; transform: translateY(10px); }}
        to   {{ opacity: 1; transform: translateY(0); }}
    }}
    .finding-card {{ animation: fadeInUp 0.3s ease both; }}
    .finding-card:nth-child(1) {{ animation-delay: 0.05s; }}
    .finding-card:nth-child(2) {{ animation-delay: 0.10s; }}
    .finding-card:nth-child(3) {{ animation-delay: 0.15s; }}
    .finding-card:nth-child(4) {{ animation-delay: 0.20s; }}
    .finding-card:nth-child(5) {{ animation-delay: 0.25s; }}

    /* ---- Scrollbar ---- */
    ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
    ::-webkit-scrollbar-track {{ background: var(--bg); }}
    ::-webkit-scrollbar-thumb {{ background: var(--border2); border-radius: 3px; }}
    """


# ---------------------------------------------------------------------------
# JS
# ---------------------------------------------------------------------------

_JS = """
function switchTab(btn, paneId) {
    const card = btn.closest('.finding-card');
    card.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    card.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(paneId).classList.add('active');
}
"""


# ---------------------------------------------------------------------------
# Renderer helpers
# ---------------------------------------------------------------------------

def _badge_html(label: str, color: str, dot: bool = True) -> str:
    dot_html = f'<span class="badge-dot" style="background:{color};"></span>' if dot else ""
    return (
        f'<span class="badge" '
        f'style="background:{color}18;color:{color};border:1px solid {color}50;">'
        f'{dot_html}{html.escape(label)}</span>'
    )


def _stat_card(num: int, label: str, color: str) -> str:
    return (
        f'<div class="stat-card" style="border-top:3px solid {color};">'
        f'<div class="stat-num" style="color:{color};">{num}</div>'
        f'<div class="stat-label">{html.escape(label)}</div>'
        f'</div>'
    )


def _pill(icon: str, key: str, value: str) -> str:
    return (
        f'<span class="pill">{icon} <span style="color:var(--muted);">{html.escape(key)}:</span> '
        f'<strong>{value}</strong></span>'
    )


def _code_compare(bad: str | None, good: str | None) -> str:
    if not bad and not good:
        return ""
    parts = ['<div class="code-compare">']
    if bad:
        parts.append(
            '<div>'
            '<div class="code-block-label" style="color:var(--critical);">❌ Vulnerable pattern</div>'
            f'<pre>{html.escape(bad)}</pre>'
            '</div>'
        )
    if good:
        parts.append(
            '<div>'
            '<div class="code-block-label" style="color:var(--clean);">✅ Safe pattern</div>'
            f'<pre>{html.escape(good)}</pre>'
            '</div>'
        )
    parts.append('</div>')
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Main renderer
# ---------------------------------------------------------------------------

def _render(result: ScanResult) -> str:
    findings = result.findings
    n_critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    n_high     = sum(1 for f in findings if f.severity == Severity.HIGH)
    n_medium   = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    n_info     = sum(1 for f in findings if f.severity == Severity.INFO)
    total_findings = len(findings)

    binary_h    = html.escape(result.binary)
    run_id_h    = html.escape(result.run_id)
    ts_start_h  = html.escape(result.timestamp_start or "–")
    ts_end_h    = html.escape(result.timestamp_end   or "–")

    timeline = build_allocation_timeline(result.events)

    # ---- Topbar ----
    topbar = f"""
    <div class="topbar">
        <div class="topbar-logo">🔍 Heap<span>Sentry</span></div>
        <div class="topbar-meta">
            Binary: <code>{binary_h}</code>
            &nbsp;|&nbsp; Run: <code>{run_id_h}</code>
        </div>
    </div>
    """

    # ---- Hero header ----
    risk_label = "CRITICAL" if n_critical else ("HIGH" if n_high else ("MEDIUM" if n_medium else "CLEAN"))
    risk_color = (_COLORS["critical"] if n_critical else
                  _COLORS["high"]     if n_high     else
                  _COLORS["medium"]   if n_medium   else _COLORS["clean"])

    header_html = f"""
    <h1>Security Scan <span style="color:{risk_color};">{html.escape(risk_label)}</span></h1>
    <div class="meta-bar">
        <div class="meta-pill">📁 <strong>{binary_h}</strong></div>
        <div class="meta-pill">🆔 Run <strong>{run_id_h}</strong></div>
        <div class="meta-pill">⏱ Started <strong>{ts_start_h}</strong></div>
        <div class="meta-pill">⏱ Finished <strong>{ts_end_h}</strong></div>
        <div class="meta-pill">🔎 Findings <strong style="color:{risk_color};">{total_findings}</strong></div>
    </div>
    """

    # ---- Summary grid ----
    summary_html = '<div class="summary-grid">'
    if n_critical:
        summary_html += _stat_card(n_critical, "Critical", _COLORS["critical"])
    if n_high:
        summary_html += _stat_card(n_high, "High", _COLORS["high"])
    if n_medium:
        summary_html += _stat_card(n_medium, "Medium", _COLORS["medium"])
    if n_info:
        summary_html += _stat_card(n_info, "Info / Clean", _COLORS["info"])
    total_allocs = len([e for e in result.events if e.event == "allocation"])
    total_events = len(result.events)
    summary_html += _stat_card(total_allocs, "Allocations", _COLORS["accent"])
    summary_html += _stat_card(total_events, "Events", _COLORS["muted"])
    summary_html += '</div>'

    # ---- Finding cards ----
    cards_html = '<h2>Findings</h2>\n'
    cards_html += '<div class="section-note">Each finding below includes exploit impact assessment, remediation steps, and code patterns.</div>'

    for idx, f in enumerate(findings):
        color = _sev_color(f.severity.value)
        bug_key = f.bug_class.value
        bug_label = bug_key.replace("_", " ").title()
        meta = _BUG_META.get(bug_key, {})
        icon = meta.get("icon", "🔍")
        card_id = f"card-{idx}"

        sev_badge = _badge_html(f.severity.value.upper(), color)
        bug_badge = _badge_html(bug_label, _COLORS["muted"], dot=False)

        # Sub-pills for address, alloc id, size, overflow side
        pills = []
        if f.address:
            pills.append(_pill("📍", "address", f"<code>{html.escape(f.address)}</code>"))
        if f.allocation_id is not None:
            pills.append(_pill("🔢", "alloc #", str(f.allocation_id)))
        if f.size is not None:
            pills.append(_pill("📏", "size", f"{f.size:,} bytes"))
        if f.overflow_side:
            pills.append(_pill("↔", "side", html.escape(f.overflow_side)))
        if f.event_id is not None:
            pills.append(_pill("🎯", "event id", str(f.event_id)))
        subtitle_html = "".join(pills)

        # Tab pane IDs
        tab_impact_id = f"tab-{idx}-impact"
        tab_fix_id    = f"tab-{idx}-fix"
        tab_code_id   = f"tab-{idx}-code"
        tab_raw_id    = f"tab-{idx}-raw"

        # Impact
        impact_text = meta.get("impact", f.description)
        impact_class = "impact-block clean" if bug_key == "clean" else "impact-block"
        impact_pane = f'<div class="{impact_class}">{html.escape(impact_text)}</div>'

        # Description
        impact_pane += f'<p style="margin-top:8px;"><strong>Scanner description:</strong> {html.escape(f.description)}</p>'

        # Remediation
        remediations = meta.get("remediation", [])
        rem_items = "".join(f'<li>{r}</li>' for r in remediations)
        fix_pane = f'<ul class="remediation-list">{rem_items}</ul>' if rem_items else '<p>No remediation steps available.</p>'

        # Code compare
        code_bad  = meta.get("code_bad")
        code_good = meta.get("code_good")
        code_pane = _code_compare(code_bad, code_good) or '<p style="color:var(--muted);font-size:0.85em;">No code pattern example for this finding type.</p>'

        # Raw evidence
        evidence_json = html.escape(json.dumps(f.evidence, indent=2)) if f.evidence else "No evidence recorded."
        raw_pane = f'<pre>{evidence_json}</pre>'

        # Has code tab?
        has_code = bool(code_bad or code_good)
        code_tab = f'<button class="tab-btn" onclick="switchTab(this,\'{tab_code_id}\')">Code Pattern</button>' if has_code else ''

        cards_html += f"""
        <div class="finding-card" style="border-left-color:{color};" id="{card_id}">
            <div class="card-header">
                <div class="card-icon">{icon}</div>
                <div class="card-title-block">
                    <div class="card-title">{sev_badge} {bug_badge}</div>
                    <div class="card-subtitle">{subtitle_html}</div>
                </div>
            </div>
            <div class="card-tabs">
                <button class="tab-btn active" onclick="switchTab(this,'{tab_impact_id}')">Impact</button>
                <button class="tab-btn" onclick="switchTab(this,'{tab_fix_id}')">Remediation</button>
                {code_tab}
                <button class="tab-btn" onclick="switchTab(this,'{tab_raw_id}')">Raw Evidence</button>
            </div>
            <div class="tab-pane active" id="{tab_impact_id}">{impact_pane}</div>
            <div class="tab-pane" id="{tab_fix_id}">{fix_pane}</div>
            {'<div class="tab-pane" id="' + tab_code_id + '">' + code_pane + '</div>' if has_code else ''}
            <div class="tab-pane" id="{tab_raw_id}">{raw_pane}</div>
        </div>
        """

    # ---- Crash details ----
    crash_html = ""
    if result.crashed and result.crash_info is not None:
        ci = result.crash_info
        sig_label = html.escape(ci.signal_name or str(ci.signal_number or "unknown"))
        crash_html = f"""
        <h2>Crash Details</h2>
        <div class="crash-box">
            <h3>💀 Process Terminated Abnormally</h3>
            <div class="meta-bar" style="margin-bottom:12px;">
                <div class="meta-pill">Exit code <strong style="color:var(--critical);">{ci.exit_code}</strong></div>
                <div class="meta-pill">Signal <strong style="color:var(--critical);">{sig_label}</strong></div>
            </div>
        """
        if ci.backtrace:
            crash_html += f'<h3 style="margin-top:12px;margin-bottom:6px;">🗂 LLDB Backtrace</h3><pre>{html.escape(ci.backtrace)}</pre>'
        if ci.asan_output:
            crash_html += f'<h3 style="margin-top:12px;margin-bottom:6px;">🧪 AddressSanitizer Output</h3><pre>{html.escape(ci.asan_output)}</pre>'
        if ci.stderr_text:
            crash_html += (
                '<details style="margin-top:10px;">'
                '<summary>stderr output</summary>'
                f'<pre>{html.escape(ci.stderr_text[:4000])}</pre>'
                '</details>'
            )
        crash_html += '</div>'

    # ---- Allocation timeline ----
    timeline_html = '<h2>Allocation Timeline</h2>\n'
    if timeline:
        timeline_html += """
        <div class="timeline-wrap">
        <table>
          <thead><tr>
            <th>Alloc #</th>
            <th>Address</th>
            <th>Size</th>
            <th>Thread</th>
            <th>Fate</th>
          </tr></thead>
          <tbody>
        """
        for row in timeline:
            fate = row.get("fate", "unknown")
            fc = _fate_color(fate)
            fate_dot = f'<span class="badge-dot" style="background:{fc};"></span>'
            fate_tag = (
                f'<span class="fate-tag" '
                f'style="background:{fc}18;color:{fc};border:1px solid {fc}50;">'
                f'{fate_dot}{html.escape(fate)}</span>'
            )
            size_val = row.get("size")
            size_str = f"{size_val:,}" if size_val is not None else "–"
            timeline_html += f"""
            <tr>
              <td><strong>#{row.get("alloc_id", "")}</strong></td>
              <td><code>{html.escape(str(row.get("address") or "–"))}</code></td>
              <td>{size_str} B</td>
              <td>{row.get("thread_id", "–")}</td>
              <td>{fate_tag}</td>
            </tr>
            """
        timeline_html += '</tbody></table></div>'
    else:
        timeline_html += '<p>No allocation events recorded.</p>'

    # ---- Full event log ----
    event_log_html = ""
    if result.events:
        event_log_html = '<h2>Full Event Log</h2>\n'
        event_log_html += '<div class="section-note">Complete sequence of instrumentation events, ordered by event ID. Error-status events are highlighted.</div>'
        event_log_html += '<div class="timeline-wrap"><table><thead><tr>'
        event_log_html += '<th>#</th><th>Event</th><th>Alloc ID</th><th>Address</th><th>Size</th><th>Thread</th><th>Extra</th><th>Status</th>'
        event_log_html += '</tr></thead><tbody>'

        base_ts = result.events[0].timestamp_ns if result.events else 0
        for ev in result.events:
            is_err = ev.status != "ok"
            row_style = ' style="background:rgba(255,71,87,0.05);"' if is_err else ''
            status_cls = "event-error" if is_err else "event-ok"
            type_cls   = "event-error" if is_err else "event-type"

            extras = []
            if ev.overflow_side:
                extras.append(f'side=<span class="canary">{html.escape(ev.overflow_side)}</span>')
            if ev.user_size is not None:
                extras.append(f'user_size={ev.user_size}')
            if ev.original_alloc_id is not None:
                extras.append(f'orig_alloc=#{ev.original_alloc_id}')
            if ev.extra:
                for k, v in ev.extra.items():
                    vs = str(v)
                    if k == "corrupted_canary":
                        extras.append(f'canary=<span class="canary">{html.escape(vs)}</span>')
                    else:
                        extras.append(f'{html.escape(k)}={html.escape(vs)}')
            extras_html = ' &nbsp; '.join(extras) if extras else '–'

            size_str = f"{ev.size:,}" if ev.size is not None else "–"

            event_log_html += f"""
            <tr{row_style}>
              <td style="color:var(--muted);font-size:0.8em;">{ev.event_id}</td>
              <td><span class="{type_cls}">{html.escape(ev.event)}</span></td>
              <td>{f'<strong>#{ev.allocation_id}</strong>' if ev.allocation_id is not None else '–'}</td>
              <td><code style="font-size:0.78em;">{html.escape(ev.address or '–')}</code></td>
              <td>{size_str}</td>
              <td>{ev.thread_id}</td>
              <td style="font-size:0.8em;">{extras_html}</td>
              <td><span class="{status_cls}">{html.escape(ev.status)}</span></td>
            </tr>
            """
        event_log_html += '</tbody></table></div>'

    # ---- Vulnerability reference ----
    vuln_ref_html = '<h2>Vulnerability Reference</h2>\n'
    vuln_ref_html += '<div class="section-note">Quick reference for all heap memory-safety vulnerability classes detected by HeapSentry.</div>'
    vuln_ref_html += '<div class="vuln-grid">'

    _vuln_display = [
        ("heap_buffer_overflow", "Heap Buffer Overflow", _COLORS["critical"]),
        ("double_free",          "Double Free",           _COLORS["critical"]),
        ("use_after_free_write", "Use-After-Free Write",  _COLORS["high"]),
        ("memory_leak",          "Memory Leak",           _COLORS["medium"]),
    ]
    for key, title, color in _vuln_display:
        meta = _BUG_META.get(key, {})
        icon = meta.get("icon", "🔍")
        desc = (meta.get("impact") or "")[:160] + "…"
        active = any(f.bug_class.value == key for f in findings)
        active_badge = f'&nbsp;<span class="badge" style="background:{color}18;color:{color};border:1px solid {color}50;font-size:0.65em;">DETECTED</span>' if active else ''
        vuln_ref_html += f"""
        <div class="vuln-ref-card" style="{'border-color:' + color + '55;' if active else ''}">
            <div class="vuln-ref-title">{icon} {html.escape(title)}{active_badge}</div>
            <div class="vuln-ref-desc">{html.escape(desc)}</div>
        </div>
        """
    vuln_ref_html += '</div>'

    # ---- Footer ----
    footer_html = """
    <footer>HeapSentry v1.0.0 — for authorized research use only &nbsp;|&nbsp; Generated by the HeapSentry HTML report engine</footer>
    """

    css = _build_css()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HeapSentry Report — {binary_h}</title>
  <meta name="description" content="HeapSentry memory-safety scan report for {binary_h}. Run {run_id_h}.">
  <style>{css}</style>
</head>
<body>
  {topbar}
  <div class="container">
    {header_html}
    {summary_html}
    {cards_html}
    {crash_html}
    {timeline_html}
    {event_log_html}
    {vuln_ref_html}
    {footer_html}
  </div>
  <script>{_JS}</script>
</body>
</html>
"""
