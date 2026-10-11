"""Baseline learning: per-instrument price statistics from a known-good log.

A baseline seeds the APP price-band check (D02) so it works from the first message of a scan
instead of waiting for the in-scan baseline to warm up. The baseline is a plain JSON file:

    {"instruments": {"AAPL": {"n": 120, "sum": 18000.0, "min": 148.1, "max": 151.9}}}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..model.message import FixMessage

_PRICE_TAGS = (31, 270, 44, 6)  # LastPx, MDEntryPx, Price, AvgPx
_SYMBOL = 55


def build(messages: Iterable[FixMessage]) -> dict:
    """Accumulate per-symbol price stats from market/order prices in the messages."""
    instruments: dict[str, dict] = {}
    for msg in messages:
        sym = msg.get_str(_SYMBOL)
        if not sym:
            continue
        for tag in _PRICE_TAGS:
            raw = msg.get(tag)
            if raw is None:
                continue
            try:
                px = float(raw)
            except ValueError:
                continue
            if px <= 0:
                continue
            b = instruments.setdefault(sym, {"n": 0, "sum": 0.0, "min": px, "max": px})
            b["n"] += 1
            b["sum"] += px
            b["min"] = min(b["min"], px)
            b["max"] = max(b["max"], px)
    return {"instruments": instruments}


def save(baseline: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(baseline, indent=2), encoding="utf-8")


def load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def to_context_baseline(baseline: dict) -> dict:
    """Convert a saved baseline to the {symbol: {n, sum}} shape the APP detector reads."""
    out: dict[str, dict] = {}
    for sym, stats in baseline.get("instruments", {}).items():
        out[sym] = {"n": int(stats.get("n", 0)), "sum": float(stats.get("sum", 0.0))}
    return out
