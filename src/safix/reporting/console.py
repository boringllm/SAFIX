"""Rich console report of a scan result."""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from ..engine.runner import ScanResult
from ..model.finding import Finding, Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render(result: ScanResult, *, console: Console | None = None, show_suppressed: bool = False,
           max_rows: int = 200) -> None:
    console = console or Console()

    fmt = result.detected_format or {}
    console.print()
    console.rule("[bold]SAFIX scan[/bold]")
    console.print(
        f"messages: [bold]{result.message_count}[/bold]   "
        f"sessions: [bold]{result.session_count}[/bold]   "
        f"format: [bold]{fmt.get('input_kind', '?')}[/bold] "
        f"(delim={fmt.get('field_delimiter', '?')!r})"
    )

    counts = result.counts_by_severity()
    if counts:
        parts = []
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            if counts.get(sev.value):
                parts.append(Text(f"{counts[sev.value]} {sev.value}", style=_SEV_STYLE[sev]))
        line = Text("  ").join(parts)
        console.print(Text("findings: ", style="bold") + line)
    else:
        console.print("[green]no findings[/green]")

    findings = result.findings if show_suppressed else result.active_findings
    if not findings:
        console.print()
        return

    table = Table(show_lines=False, expand=True, header_style="bold")
    table.add_column("Pri", justify="right", width=4)
    table.add_column("Severity", width=9)
    table.add_column("Conf", width=4)
    table.add_column("Rule", width=18, no_wrap=True)
    table.add_column("Cat", width=6)
    table.add_column("Title")
    table.add_column("Session / loc", width=28, no_wrap=True)

    for f in findings[:max_rows]:
        table.add_row(
            str(f.priority),
            Text(f.severity.value, style=_SEV_STYLE[f.severity]),
            f.confidence.value[0].upper(),
            f.rule_id,
            f.category,
            _title_cell(f),
            _loc_cell(f),
        )
    console.print(table)
    if len(findings) > max_rows:
        console.print(f"[dim]... {len(findings) - max_rows} more findings (use --report json)[/dim]")
    console.print()


def _title_cell(f: Finding) -> Text:
    t = Text(f.title)
    if f.vector_ids:
        t.append(f"  [{', '.join(f.vector_ids[:3])}]", style="dim")
    if f.occurrence_count > 1:
        t.append(f"  x{f.occurrence_count}", style="bold")
    return t


def _loc_cell(f: Finding) -> str:
    loc = f.session or "?"            # session carries CompIDs (untrusted)
    if f.msg_seq is not None:
        loc += f" #{f.msg_seq}"
    if f.source_line is not None:
        loc += f" L{f.source_line}"
    return escape(loc)               # prevent rich-markup injection via crafted CompIDs
