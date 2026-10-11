"""Report renderers for scan results."""

from __future__ import annotations

from ..engine.runner import ScanResult

TEXT_FORMATS = {"json", "sarif", "html", "junit"}


def render_text(result: ScanResult, fmt: str) -> str:
    """Render a scan result to a string in the given format (not 'console')."""
    if fmt == "json":
        from . import jsonreport
        return jsonreport.render(result)
    if fmt == "sarif":
        from . import sarif
        return sarif.render(result)
    if fmt == "html":
        from . import html
        return html.render(result)
    if fmt == "junit":
        from . import junit
        return junit.render(result)
    raise ValueError(f"unknown report format: {fmt!r}")


def render_console(result: ScanResult, **kwargs) -> None:
    from . import console
    console.render(result, **kwargs)
