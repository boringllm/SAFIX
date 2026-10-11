"""Tests for the engine: findings, suppression, dedup, severity filtering, reporters."""

from __future__ import annotations

import json

from safix.config import Config, Suppression
from safix.engine.runner import scan_bytes
from safix.model.finding import Confidence, Finding, Severity, severity_at_least
from safix.parsing.encode import encode
from safix.parsing.rawdata import SOH
from safix.reporting import render_text
from safix.suppress.suppressions import dedup, postprocess
from tests.conftest import make_logon


def _bad_checksum() -> bytes:
    raw = bytearray(make_logon(begin_string="FIX.4.4"))
    raw[-4:-1] = b"123"
    return bytes(raw)


def test_finding_priority_and_fingerprint():
    f = Finding("R1", "t", "m", Severity.HIGH, Confidence.HIGH, category="SESS")
    assert f.priority == 80            # 8.0 * 1.0 * 10
    assert len(f.fingerprint) == 16
    f2 = Finding("R1", "t", "m", Severity.HIGH, Confidence.LOW, category="SESS")
    assert f2.priority == 24           # 8.0 * 0.3 * 10


def test_severity_ordering():
    assert severity_at_least(Severity.CRITICAL, Severity.HIGH)
    assert not severity_at_least(Severity.LOW, Severity.HIGH)


def test_scan_detects_bad_checksum():
    res = scan_bytes(_bad_checksum(), source="t.log")
    rules = {f.rule_id for f in res.active_findings}
    assert "SAFIX-SESS-FRM-003" in rules


def test_scan_clean_message_quiet():
    res = scan_bytes(make_logon(begin_string="FIX.4.4"), source="t.log")
    assert res.active_findings == []


def test_suppression_marks_not_deletes():
    cfg = Config.default()
    cfg.suppressions = [Suppression(rule_id="SAFIX-SESS-FRM-003", reason="known test venue")]
    res = scan_bytes(_bad_checksum(), config=cfg, source="t.log")
    # suppressed findings are retained but excluded from active
    assert any(f.suppressed for f in res.findings)
    assert all(f.rule_id != "SAFIX-SESS-FRM-003" for f in res.active_findings)


def test_dedup_counts_occurrences():
    f1 = Finding("R", "t", "m", Severity.LOW, Confidence.HIGH, session="S", dedup_key="k")
    f2 = Finding("R", "t", "m", Severity.LOW, Confidence.HIGH, session="S", dedup_key="k")
    out = dedup([f1, f2])
    assert len(out) == 1 and out[0].occurrence_count == 2


def test_severity_min_filters():
    cfg = Config.default()
    cfg.severity_min = Severity.CRITICAL
    res = scan_bytes(_bad_checksum(), config=cfg, source="t.log")
    assert res.active_findings == []   # the high finding is below CRITICAL


def test_sarif_render_valid_structure():
    res = scan_bytes(_bad_checksum(), source="t.log")
    doc = json.loads(render_text(res, "sarif"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "SAFIX"
    assert run["results"], "expected at least one result"
    r0 = run["results"][0]
    assert r0["ruleId"].startswith("SAFIX-")
    assert "partialFingerprints" in r0
    assert r0["level"] in ("error", "warning", "note")


def test_json_render_roundtrips():
    res = scan_bytes(_bad_checksum(), source="t.log")
    doc = json.loads(render_text(res, "json"))
    assert doc["finding_count"] >= 1
    assert "counts_by_severity" in doc


def test_category_gating():
    cfg = Config.default()
    cfg.enabled_categories = ["TYPE"]   # disable SESS framing
    res = scan_bytes(_bad_checksum(), config=cfg, source="t.log")
    assert all(f.category == "TYPE" for f in res.active_findings)
