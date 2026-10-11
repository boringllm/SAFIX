"""Live/streaming scanner — process messages one at a time as they are tailed.

Holds one persistent :class:`ScanContext` (so stateful SESS/APP detectors work across the live
stream) and emits findings as each message is seen. Memory is bounded: emitted findings are not
retained, and per-session/order state is trimmed periodically so a long-running monitor does not
grow without bound.
"""

from __future__ import annotations

from collections import Counter
from typing import Optional

from ..config import Config
from ..model.finding import Finding, Severity, severity_at_least
from ..model.message import FixMessage
from ..suppress.suppressions import apply_suppressions
from .context import ScanContext
from .runner import _get_detectors


class LiveScanner:
    """Feed messages in; get new findings out. One instance per live session."""

    def __init__(self, config: Optional[Config] = None, *, state_trim_at: int = 200_000):
        self.config = config or Config.default()
        self.ctx = ScanContext(self.config)
        self.detectors = _get_detectors(self.config)
        self._seen_fp: dict[str, int] = {}
        self.state_trim_at = state_trim_at
        self.message_count = 0
        self.finding_count = 0
        self.counts: Counter = Counter()
        self._minimum = Severity(self.config.severity_min)

    def feed(self, msg: FixMessage) -> list[Finding]:
        """Process one message; return the newly-emitted (filtered, de-duplicated) findings."""
        self.ctx.stats["messages"] += 1
        self.message_count += 1
        self.ctx.resolve_direction(msg)
        self.ctx.set_current(msg)
        self.ctx.session_state(msg).message_count += 1

        base = len(self.ctx.findings)
        for det in self.detectors:
            det.analyze(msg, self.ctx)
        new = self.ctx.findings[base:]
        del self.ctx.findings[base:]  # don't retain — keeps memory flat

        apply_suppressions(new, self.config)
        out: list[Finding] = []
        for f in new:
            if f.suppressed or not severity_at_least(f.severity, self._minimum):
                continue
            fp = f.fingerprint
            n = self._seen_fp.get(fp, 0) + 1
            self._seen_fp[fp] = n
            if self.config.dedup and n > 1:
                continue  # already reported this exact finding on the stream
            out.append(f)
            self.finding_count += 1
            self.counts[f.severity.value] += 1

        if self.message_count % 10_000 == 0:
            self._trim_state()
        return out

    def _trim_state(self) -> None:
        """Bound memory for long runs: cap the order book and the seen-fingerprint set."""
        ob = self.ctx.orderbook
        if len(ob) > self.state_trim_at:
            keep = list(ob.items())[-(self.state_trim_at // 2):]
            self.ctx.orderbook = dict(keep)
        if len(self._seen_fp) > self.state_trim_at:
            self._seen_fp.clear()

    def summary(self) -> dict:
        return {
            "messages": self.message_count,
            "sessions": len(self.ctx.sessions),
            "findings": self.finding_count,
            "counts_by_severity": dict(self.counts),
        }
