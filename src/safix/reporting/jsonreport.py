"""JSON report of a scan result."""

from __future__ import annotations

import json

from ..engine.runner import ScanResult


def render(result: ScanResult, *, include_suppressed: bool = True, indent: int = 2) -> str:
    data = result.to_dict()
    if not include_suppressed:
        data["findings"] = [f for f in data["findings"] if not f["suppressed"]]
    return json.dumps(data, indent=indent, ensure_ascii=False)
