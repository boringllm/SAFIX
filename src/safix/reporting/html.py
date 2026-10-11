"""Self-contained HTML report of a scan result (no external assets)."""

from __future__ import annotations

import html
from ..engine.runner import ScanResult
from ..model.finding import Finding, Severity

_SEV_COLORS = {
    "critical": "#b00020", "high": "#d93025", "medium": "#e8710a",
    "low": "#1a73e8", "info": "#5f6368",
}


def _esc(s) -> str:
    return html.escape(str(s)) if s is not None else ""


def _chip(text: str, color: str) -> str:
    return (f'<span style="background:{color};color:#fff;border-radius:10px;'
            f'padding:1px 8px;font-size:12px;white-space:nowrap">{_esc(text)}</span>')


def _finding_row(f: Finding) -> str:
    color = _SEV_COLORS.get(f.severity.value, "#5f6368")
    vectors = ", ".join(f.vector_ids)
    benign = "".join(f"<li>{_esc(b)}</li>" for b in f.benign_notes)
    regs = ", ".join(f.regulatory_refs)
    loc = _esc(f.session or "")
    if f.msg_seq is not None:
        loc += f" · seq {f.msg_seq}"
    if f.source_line is not None:
        loc += f" · line {f.source_line}"
    occ = f" ×{f.occurrence_count}" if f.occurrence_count > 1 else ""
    return f"""
    <details class="finding">
      <summary>
        {_chip(f.severity.value.upper(), color)}
        {_chip('conf ' + f.confidence.value, '#5f6368')}
        <b>{_esc(f.rule_id)}</b> — {_esc(f.title)}{occ}
        <span class="pri">P{f.priority}</span>
      </summary>
      <div class="body">
        <p class="msg">{_esc(f.message)}</p>
        <table class="meta">
          <tr><th>Category</th><td>{_esc(f.category)}</td>
              <th>MsgType</th><td>{_esc(f.msg_type)}</td></tr>
          <tr><th>Location</th><td>{loc}</td>
              <th>Tag</th><td>{_esc(f.tag)}</td></tr>
          <tr><th>Vectors</th><td colspan="3">{_esc(vectors)}</td></tr>
          {f'<tr><th>Regulatory</th><td colspan="3">{_esc(regs)}</td></tr>' if regs else ''}
        </table>
        {f'<pre class="evidence">{_esc(f.evidence)}</pre>' if f.evidence else ''}
        {f'<div class="remed"><b>Remediation:</b> {_esc(f.remediation)}</div>' if f.remediation else ''}
        {f'<div class="benign"><b>Benign explanations:</b><ul>{benign}</ul></div>' if benign else ''}
      </div>
    </details>"""


def render(result: ScanResult) -> str:
    counts = result.counts_by_severity()
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    summary_chips = "".join(
        _chip(f"{counts[s.value]} {s.value}", _SEV_COLORS[s.value])
        for s in order if counts.get(s.value))
    fmt = result.detected_format or {}
    rows = "".join(_finding_row(f) for f in result.active_findings)
    if not rows:
        rows = '<p class="none">No findings.</p>'
    sources = _esc(", ".join(result.sources))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SAFIX scan report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background: Canvas;
          color: CanvasText; }}
  header {{ padding: 20px 24px; border-bottom: 1px solid #8884; }}
  h1 {{ margin: 0 0 6px; font-size: 20px; }}
  .sub {{ color: #8a8a8a; font-size: 13px; }}
  .chips {{ margin-top: 10px; display: flex; gap: 8px; flex-wrap: wrap; }}
  main {{ padding: 16px 24px; max-width: 1100px; }}
  .finding {{ border: 1px solid #8884; border-radius: 8px; margin: 8px 0; padding: 6px 12px; }}
  .finding summary {{ cursor: pointer; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
  .finding .pri {{ margin-left: auto; color: #8a8a8a; font-variant-numeric: tabular-nums; }}
  .body {{ padding: 8px 2px 4px; }}
  .msg {{ margin: 6px 0; }}
  table.meta {{ border-collapse: collapse; font-size: 13px; margin: 6px 0; }}
  table.meta th {{ text-align: left; color: #8a8a8a; padding: 2px 10px 2px 0; font-weight: 600; }}
  table.meta td {{ padding: 2px 24px 2px 0; }}
  pre.evidence {{ background: #8881; padding: 8px; border-radius: 6px; overflow-x: auto; font-size: 12px; }}
  .remed {{ font-size: 13px; margin: 6px 0; }}
  .benign {{ font-size: 13px; color: #8a8a8a; }}
  .benign ul {{ margin: 4px 0; }}
  .none {{ color: #1a7f37; font-weight: 600; }}
</style></head>
<body>
  <header>
    <h1>SAFIX — FIX security scan report</h1>
    <div class="sub">{result.message_count} messages · {result.session_count} sessions ·
      format: {_esc(fmt.get('input_kind', '?'))} · sources: {sources}</div>
    <div class="chips">{summary_chips or '<span class="none">No findings</span>'}</div>
  </header>
  <main>{rows}</main>
</body></html>"""
