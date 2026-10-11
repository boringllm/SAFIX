"""Detection-rate (recall) and false-positive (precision) measurement.

Cross-validates SAFIX against the independent ``fixfuzz-plus`` fuzzer's labeled attack corpus,
and checks SAFIX stays quiet on a benign corpus. Prints a per-category report and gates on
calibrated thresholds so a regression that silences a detector family fails CI.
"""

from __future__ import annotations

from collections import defaultdict

import pytest

from safix.engine.runner import scan_bytes
from tests.corpus import benign_messages, load_fixfuzz_corpus

# single-message recall floors per area (SESS/APP have stateful/multi-message vectors a single
# message cannot exercise, so their floors are lower by design)
_RECALL_FLOOR = {"TYPE": 0.95, "STRUCT": 0.95, "ENC": 0.95, "APP": 0.90, "SESS": 0.80}
_OVERALL_FLOOR = 0.92


def test_fixfuzz_detection_rate(capsys):
    rows = load_fixfuzz_corpus()
    if not rows:
        pytest.skip("fixfuzz corpus fixture not present")

    total = defaultdict(int)
    detected = defaultdict(int)
    missed: list[str] = []
    for r in rows:
        raw = r["raw"].encode("latin-1")
        res = scan_bytes(raw, source="corpus")
        area = r["area"]
        total[area] += 1
        if res.active_findings:
            detected[area] += 1
        else:
            missed.append(f"{area}/{r['label']}")

    lines = ["", "SAFIX recall vs fixfuzz-plus corpus:"]
    for area in sorted(total):
        rec = detected[area] / total[area]
        lines.append(f"  {area:6} {detected[area]:3}/{total[area]:<3} recall={rec:.2f}")
    T = sum(total.values())
    D = sum(detected.values())
    lines.append(f"  OVERALL {D}/{T} recall={D / T:.3f}")
    lines.append(f"  misses: {missed}")
    with capsys.disabled():
        print("\n".join(lines))

    for area, floor in _RECALL_FLOOR.items():
        if total.get(area):
            rec = detected[area] / total[area]
            assert rec >= floor, f"{area} recall {rec:.2f} below floor {floor}"
    assert D / T >= _OVERALL_FLOOR, f"overall recall {D / T:.3f} below {_OVERALL_FLOOR}"


def test_benign_corpus_low_false_positives(capsys):
    """Benign, well-formed traffic must raise no HIGH/CRITICAL findings and few overall."""
    msgs = benign_messages()
    total_active = 0
    offenders: list[str] = []
    for label, raw in msgs:
        res = scan_bytes(raw, source="benign")
        active = res.active_findings
        total_active += len(active)
        for f in active:
            if f.severity.value in ("high", "critical"):
                offenders.append(f"{label}: {f.rule_id} {f.title}")
    with capsys.disabled():
        print(f"\nbenign corpus: {len(msgs)} messages, {total_active} total active findings, "
              f"{len(offenders)} high/critical")
        for o in offenders:
            print("  FP:", o)
    assert not offenders, f"benign traffic produced high/critical findings: {offenders}"


def test_benign_corpus_scanned_together_quiet():
    """A whole benign session scanned together should produce no high/critical findings."""
    blob = b"".join(raw for _, raw in benign_messages())
    res = scan_bytes(blob, source="benign-session")
    bad = [f for f in res.active_findings if f.severity.value in ("high", "critical")]
    assert not bad, [f"{f.rule_id}:{f.title}" for f in bad]
