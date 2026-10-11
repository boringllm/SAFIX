"""Tests for the declarative YAML rule layer."""

from __future__ import annotations

from pathlib import Path

from safix.config import Config
from safix.engine.runner import scan_bytes
from safix.parsing.encode import encode
from safix.rules import loader as rule_loader


def _rules(blob: bytes, config: Config | None = None) -> set[str]:
    res = scan_bytes(blob, config=config, source="t.log")
    return {f.rule_id for f in res.active_findings}


def _order(fields_over) -> bytes:
    base = {35: "D", 34: 2, 49: "C", 52: "20231015-10:00:00", 56: "S", 11: "O1",
            55: "AAPL", 54: "1", 38: "100", 60: "20231015-10:00:00"}
    base.update(fields_over)
    return encode(list(base.items()), begin_string="FIX.4.4")


def test_builtin_rules_load():
    rules = rule_loader.load_builtin()
    ids = {r.id for r in rules}
    assert "SAFIX-APP-030" in ids and "SAFIX-APP-031" in ids


def test_stop_order_without_stoppx():
    # OrdType 3 (Stop), no StopPx(99)
    assert "SAFIX-APP-030" in _rules(_order({40: "3"}))


def test_stop_order_with_stoppx_ok():
    assert "SAFIX-APP-030" not in _rules(_order({40: "3", 99: "149.00"}))


def test_limit_order_without_price():
    assert "SAFIX-APP-031" in _rules(_order({40: "2"}))


def test_market_order_with_price_advisory():
    assert "SAFIX-APP-032" in _rules(_order({40: "1", 44: "150.00"}))


def test_user_rule_pack(tmp_path: Path):
    rule = tmp_path / "custom.yml"
    rule.write_text(
        "rules:\n"
        "  - id: MY-RULE-1\n"
        "    title: Account 999 is forbidden\n"
        "    category: CUSTOM\n"
        "    severity: high\n"
        "    msg_types: ['D']\n"
        "    when:\n"
        "      - {tag: 1, equals: '999'}\n",
        encoding="utf-8")
    cfg = Config.default()
    cfg.rules_path = str(tmp_path)
    assert "MY-RULE-1" in _rules(_order({1: "999"}), cfg)
    assert "MY-RULE-1" not in _rules(_order({1: "111"}), cfg)


def test_regex_and_datatype_conditions(tmp_path: Path):
    rule = tmp_path / "r.yml"
    rule.write_text(
        "rules:\n"
        "  - id: MY-REGEX\n"
        "    title: ClOrdID looks sequential\n"
        "    severity: low\n"
        "    when:\n"
        "      - {tag: 11, regex: '^SEQ[0-9]+$'}\n",
        encoding="utf-8")
    cfg = Config.default()
    cfg.rules_path = str(tmp_path)
    assert "MY-REGEX" in _rules(_order({11: "SEQ123"}), cfg)
    assert "MY-REGEX" not in _rules(_order({11: "ABC"}), cfg)
