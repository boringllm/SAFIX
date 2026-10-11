"""The scan orchestrator: parse -> per-message detectors -> finalize -> triage."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from ..config import Config
from ..model.finding import Finding
from ..model.message import FixMessage
from ..parsing import logreader
from ..parsing.logreader import ReadOptions
from ..suppress.suppressions import postprocess
from .context import ScanContext


@dataclass(slots=True)
class ScanResult:
    findings: list[Finding]
    message_count: int = 0
    session_count: int = 0
    stats: dict = field(default_factory=dict)
    detected_format: Optional[dict] = None
    sources: list[str] = field(default_factory=list)

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    def counts_by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.active_findings:
            out[f.severity.value] = out.get(f.severity.value, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "message_count": self.message_count,
            "session_count": self.session_count,
            "finding_count": len(self.active_findings),
            "counts_by_severity": self.counts_by_severity(),
            "detected_format": self.detected_format,
            "sources": self.sources,
            "findings": [f.to_dict() for f in self.findings],
        }


def _get_detectors(config: Config):
    import safix.detectors  # noqa: F401  (import triggers registration)
    from ..detectors.base import all_detectors
    return [d for d in all_detectors() if config.rule_enabled(d.id, d.category)]


def scan_messages(
    messages: Iterable[FixMessage],
    config: Optional[Config] = None,
    *,
    detectors=None,
) -> ScanResult:
    """Run the detector pipeline over an iterable of parsed messages."""
    config = config or Config.default()
    ctx = ScanContext(config)
    active = detectors if detectors is not None else _get_detectors(config)

    for msg in messages:
        ctx.stats["messages"] += 1
        ctx.resolve_direction(msg)
        ctx.set_current(msg)
        ctx.session_state(msg).message_count += 1
        for det in active:
            det.analyze(msg, ctx)
    ctx.set_current(None)

    for det in active:
        det.finalize(ctx)

    findings = postprocess(ctx.findings, config)
    return ScanResult(
        findings=findings,
        message_count=ctx.stats.get("messages", 0),
        session_count=len(ctx.sessions),
        stats=dict(ctx.stats),
    )


def scan_paths(
    paths: list[str | Path],
    config: Optional[Config] = None,
) -> ScanResult:
    """Read and scan one or more log files/directories."""
    config = config or Config.default()
    opts = ReadOptions()
    delim = config.delimiter_bytes()
    if delim is not None:
        opts.field_delimiter = delim
    if config.line_oriented is not None:
        opts.line_oriented = config.line_oriented

    detected = None
    # sniff the first readable file for a format summary
    srcs: list[str] = []
    for p in (Path(x) for x in paths):
        target = p
        if p.is_dir():
            cands = [c for c in sorted(p.rglob("*")) if c.is_file()]
            target = cands[0] if cands else None
        if target and target.is_file():
            try:
                detected = logreader.sniff(target.read_bytes()[:65536], opts).describe()
            except OSError:
                detected = None
            break

    messages = list(logreader.read_paths(list(paths), opts))
    for m in messages:
        if m.source and m.source not in srcs:
            srcs.append(m.source)
    result = scan_messages(messages, config)
    result.detected_format = detected
    result.sources = srcs
    return result


def scan_bytes(data: bytes, config: Optional[Config] = None, *, source: str = "<bytes>") -> ScanResult:
    config = config or Config.default()
    opts = ReadOptions()
    delim = config.delimiter_bytes()
    if delim is not None:
        opts.field_delimiter = delim
    messages = list(logreader.iter_messages(data, source=source, options=opts))
    result = scan_messages(messages, config)
    result.detected_format = logreader.sniff(data, opts).describe()
    result.sources = [source]
    return result
