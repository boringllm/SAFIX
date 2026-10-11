"""Tests for the HTML/JUnit reporters and baseline learn-mode."""

from __future__ import annotations

from xml.etree import ElementTree as ET

from safix.config import Config
from safix.engine import baseline as bl
from safix.engine.runner import scan_bytes
from safix.parsing.encode import encode
from safix.parsing.logreader import iter_messages
from safix.reporting import render_text
from tests.conftest import make_logon


def _bad_checksum() -> bytes:
    raw = bytearray(make_logon(begin_string="FIX.4.4"))
    raw[-4:-1] = b"123"
    return bytes(raw)


def test_html_report_contains_finding():
    res = scan_bytes(_bad_checksum(), source="t.log")
    html = render_text(res, "html")
    assert "<html" in html.lower()
    assert "SAFIX-SESS-FRM-003" in html
    assert "FIX security scan report" in html


def test_junit_report_valid_xml():
    res = scan_bytes(_bad_checksum(), source="t.log")
    xml = render_text(res, "junit")
    root = ET.fromstring(xml)
    assert root.tag == "testsuites"
    # at least one failure testcase
    failures = root.findall(".//failure")
    assert failures, "expected a <failure> element"


def test_baseline_build_and_use():
    # a clean log of fills establishing AAPL ~150
    msgs = []
    for i in range(6):
        msgs.append(encode([(35, "8"), (34, i + 1), (49, "VENUE"), (52, "20231015-10:00:00"),
                            (56, "CLIENT"), (55, "AAPL"), (31, "150.0"), (54, "1"),
                            (38, "100"), (150, "F"), (39, "2")], begin_string="FIX.4.4"))
    data = bl.build(iter_messages(b"".join(msgs)))
    assert data["instruments"]["AAPL"]["n"] == 6
    ctx_bl = bl.to_context_baseline(data)
    assert ctx_bl["AAPL"]["n"] == 6

    # an order at 10x the baseline should now trip the absurd-price band from message 1
    cfg = Config.default()
    order = encode([(35, "D"), (34, 2), (49, "CLIENT"), (52, "20231015-10:01:00"),
                    (56, "VENUE"), (11, "O1"), (55, "AAPL"), (54, "1"), (38, "100"),
                    (40, "2"), (44, "2000.0"), (60, "20231015-10:01:00")], begin_string="FIX.4.4")
    # seed the baseline via a temp file through config
    import json
    import tempfile
    import os
    fd, p = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        with open(p, "w") as fh:
            json.dump(data, fh)
        cfg.baseline_path = p
        res = scan_bytes(order, config=cfg, source="t.log")
        assert "SAFIX-APP-006" in {f.rule_id for f in res.active_findings}
    finally:
        os.unlink(p)
