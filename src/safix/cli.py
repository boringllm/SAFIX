"""SAFIX command-line interface."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape as _rescape

from . import __version__
from .config import Config
from .model.finding import Severity, severity_at_least

app = typer.Typer(
    name="safix",
    help="SAFIX — Static Analyzer for FIX: a security scanner for FIX protocol logs.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


def _build_config(
    config_path: Optional[Path],
    fix_version: Optional[str],
    delimiter: Optional[str],
    severity_min: Optional[str],
    no_dedup: bool,
) -> Config:
    cfg = Config.load(config_path) if config_path else Config.default()
    if fix_version:
        cfg.fix_version = fix_version
    if delimiter:
        cfg.field_delimiter = delimiter
    if severity_min:
        cfg.severity_min = Severity(severity_min)
    if no_dedup:
        cfg.dedup = False
    return cfg


@app.command()
def scan(
    paths: list[Path] = typer.Argument(..., help="Log file(s) or directory(ies) to scan."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
    fix_version: Optional[str] = typer.Option(
        None, "--fix-version", help="Force a dictionary version, e.g. FIX.4.4 or FIXT.1.1."),
    delimiter: Optional[str] = typer.Option(
        None, "--delimiter", help="Override the field delimiter (e.g. '|' or 'soh')."),
    report: str = typer.Option("console", "--report", "-r",
                               help="console | json | sarif | html | junit."),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Write the report to a file."),
    severity_min: Optional[str] = typer.Option(
        None, "--severity-min", help="Drop findings below this severity."),
    fail_on: Optional[str] = typer.Option(
        None, "--fail-on", help="Exit non-zero if any finding is at/above this severity (CI)."),
    no_dedup: bool = typer.Option(False, "--no-dedup", help="Do not collapse duplicate findings."),
    baseline: Optional[Path] = typer.Option(None, "--baseline", "-b",
                                            help="Learned price baseline JSON (seeds APP band checks)."),
    rules: Optional[Path] = typer.Option(None, "--rules", help="Directory of custom YAML rule packs."),
    show_suppressed: bool = typer.Option(False, "--show-suppressed",
                                         help="Include suppressed findings in the console report."),
) -> None:
    """Scan FIX log(s) for security issues."""
    from .engine.runner import scan_paths
    from .reporting import render_console, render_text

    cfg = _build_config(config, fix_version, delimiter, severity_min, no_dedup)
    if baseline:
        cfg.baseline_path = str(baseline)
    if rules:
        cfg.rules_path = str(rules)
    missing = [p for p in paths if not p.exists()]
    if missing:
        console.print(f"[red]path(s) not found:[/red] {', '.join(str(m) for m in missing)}")
        raise typer.Exit(2)

    result = scan_paths(paths, cfg)

    if report == "console":
        render_console(result, console=console, show_suppressed=show_suppressed)
    else:
        text = render_text(result, report)
        if out:
            out.write_text(text, encoding="utf-8")
            console.print(f"[green]wrote[/green] {report} report -> {out} "
                          f"({len(result.active_findings)} findings)")
        else:
            print(text)

    if fail_on:
        threshold = Severity(fail_on)
        if any(severity_at_least(f.severity, threshold) for f in result.active_findings):
            raise typer.Exit(1)


_LIVE_STYLE = {"critical": "bold white on red", "high": "bold red", "medium": "yellow",
               "low": "cyan", "info": "dim"}


@app.command()
def watch(
    path: str = typer.Argument(..., help="Log file to tail live, or '-' to read from stdin."),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="YAML config file."),
    fix_version: Optional[str] = typer.Option(None, "--fix-version"),
    delimiter: Optional[str] = typer.Option(None, "--delimiter"),
    severity_min: Optional[str] = typer.Option(None, "--severity-min"),
    rules: Optional[Path] = typer.Option(None, "--rules", help="Directory of custom YAML rules."),
    baseline: Optional[Path] = typer.Option(None, "--baseline", "-b"),
    report: str = typer.Option("console", "--report", "-r", help="console | jsonl."),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="Append findings to this file."),
    from_start: bool = typer.Option(False, "--from-start", help="Scan existing content first, then follow."),
    poll: float = typer.Option(0.5, "--poll", help="Seconds between file polls."),
) -> None:
    """Passively tail a live FIX log and alert in real time (read-only, zero engine latency)."""
    import json as _json

    from .engine.live import LiveScanner
    from .parsing import tail
    from .parsing.logreader import ReadOptions

    cfg = _build_config(config, fix_version, delimiter, severity_min, False)
    if rules:
        cfg.rules_path = str(rules)
    if baseline:
        cfg.baseline_path = str(baseline)

    opts = ReadOptions()
    d = cfg.delimiter_bytes()
    if d is not None:
        opts.field_delimiter = d

    scanner = LiveScanner(cfg)
    out_fh = out.open("a", encoding="utf-8") if out else None
    stdin_mode = path == "-"
    console.print(f"[dim]SAFIX watching {'stdin' if stdin_mode else path} "
                  f"(read-only, out-of-band). Ctrl-C to stop.[/dim]")

    def emit(finding) -> None:
        if report == "jsonl":
            line = _json.dumps(finding.to_dict(), ensure_ascii=False)
            (out_fh or sys.stdout).write(line + "\n")
            if out_fh:
                out_fh.flush()
        else:
            style = _LIVE_STYLE.get(finding.severity.value, "")
            loc = finding.session or "?"
            if finding.msg_seq is not None:
                loc += f" #{finding.msg_seq}"
            ts = finding.timestamp or ""
            # escape untrusted values (CompIDs, timestamps from the log) so a crafted field
            # like a CompID of "[/]" cannot inject rich markup and crash the monitor.
            console.print(f"[dim]{_rescape(ts)}[/dim] [{style}]{finding.severity.value.upper():8}[/] "
                          f"{finding.rule_id:18} {_rescape(finding.title)}  [dim]{_rescape(loc)} "
                          f"[{_rescape(', '.join(finding.vector_ids[:2]))}][/dim]")
            if out_fh:
                out_fh.write(_json.dumps(finding.to_dict(), ensure_ascii=False) + "\n")
                out_fh.flush()

    source = tail.follow_stream(options=opts) if stdin_mode else \
        tail.follow_file(path, options=opts, from_start=from_start, poll_interval=poll)
    try:
        for msg in source:
            for finding in scanner.feed(msg):
                try:
                    emit(finding)
                except Exception as exc:  # a monitor must never die on a render error
                    console.print(f"[dim](emit error: {_rescape(str(exc))})[/dim] {finding.rule_id}")
    except KeyboardInterrupt:
        pass
    finally:
        if out_fh:
            out_fh.close()
    s = scanner.summary()
    console.print(f"\n[bold]stopped[/bold] — {s['messages']} messages, {s['sessions']} sessions, "
                  f"{s['findings']} findings {dict(s['counts_by_severity'])}")


@app.command()
def validate(
    paths: list[Path] = typer.Argument(..., help="Log file(s) to check for FIX conformance."),
    fix_version: Optional[str] = typer.Option(None, "--fix-version"),
) -> None:
    """Parse messages and report structural/datatype conformance only (TYPE+STRUCT+FRAMING)."""
    from .engine.runner import scan_paths
    from .reporting import render_console

    cfg = Config.default()
    if fix_version:
        cfg.fix_version = fix_version
    cfg.enabled_categories = ["TYPE", "STRUCT", "FRAMING", "SESS"]
    result = scan_paths(paths, cfg)
    render_console(result, console=console)


@app.command("baseline")
def baseline_cmd(
    good_log: list[Path] = typer.Argument(..., help="Known-good log(s) to learn a baseline from."),
    out: Path = typer.Option(Path("safix-baseline.json"), "--out", "-o", help="Baseline JSON path."),
) -> None:
    """Learn a per-instrument price baseline from known-good traffic."""
    from .engine import baseline as bl
    from .parsing.logreader import read_paths

    data = bl.build(read_paths(list(good_log)))
    bl.save(data, out)
    n = len(data.get("instruments", {}))
    console.print(f"[green]learned[/green] baseline for {n} instrument(s) -> {out}")


@app.command("rules")
def rules_cmd() -> None:
    """List the built-in detectors."""
    import safix.detectors  # noqa: F401
    from rich.table import Table

    from .detectors.base import all_detectors

    table = Table(title="SAFIX detectors", header_style="bold")
    table.add_column("Detector id")
    table.add_column("Category")
    table.add_column("Title")
    for d in all_detectors():
        table.add_row(d.id, d.category, d.title or "")
    console.print(table)

    from .rules import loader as rule_loader
    builtin = rule_loader.load_builtin()
    if builtin:
        yt = Table(title="Built-in YAML rules", header_style="bold")
        yt.add_column("Rule id")
        yt.add_column("Sev")
        yt.add_column("Title")
        for r in builtin:
            yt.add_row(r.id, r.severity.value, r.title)
        console.print(yt)


@app.command("dict")
def dict_cmd(
    version: Optional[str] = typer.Argument(None, help="Version to describe, e.g. FIX.4.4."),
) -> None:
    """List bundled dictionaries, or describe one."""
    from .dictionary import loader

    if version is None:
        console.print("Bundled dictionary versions:")
        for v in loader.available_versions():
            console.print(f"  • {v}")
        return
    spec = loader.load(version)
    console.print_json(data=spec.describe())


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8375, "--port"),
) -> None:
    """Launch the SAFIX web UI."""
    try:
        from .web.app import run
    except ModuleNotFoundError:
        console.print("[red]web extras not installed.[/red] Run: pip install 'safix[web]'")
        raise typer.Exit(2)
    run(host=host, port=port)


@app.command()
def version() -> None:
    """Print the SAFIX version."""
    console.print(f"SAFIX {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
