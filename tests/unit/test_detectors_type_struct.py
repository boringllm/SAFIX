"""Tests for the TYPE (datatype) and STRUCT (structure) detectors."""

from __future__ import annotations

from safix.config import Config
from safix.engine.runner import scan_bytes
from safix.parsing.encode import encode
from tests.conftest import make_order


def _rules(data: bytes, **cfg_over) -> set[str]:
    cfg = Config.default()
    for k, v in cfg_over.items():
        setattr(cfg, k, v)
    res = scan_bytes(data, config=cfg, source="t.log")
    return {f.rule_id for f in res.active_findings}


def _order(**over) -> bytes:
    return make_order(begin_string="FIX.4.4", **over)


def test_clean_order_no_type_struct_findings():
    rules = _rules(_order())
    assert "SAFIX-TYPE-010" not in rules
    assert not any(r.startswith("SAFIX-STRUCT-1") for r in rules)


def test_bad_price_grammar():
    rules = _rules(_order(price="1e5"))
    assert "SAFIX-TYPE-010" in rules


def test_nan_price_high():
    res = scan_bytes(_order(price="NaN"), source="t.log")
    f = next(f for f in res.active_findings if f.rule_id == "SAFIX-TYPE-014")
    assert f.severity.value == "high"


def test_bad_side_enum():
    # Side(54)=I is not a valid enum (valid: 1..H)
    rules = _rules(_order(side="I"))
    assert "SAFIX-TYPE-020" in rules


def test_impossible_calendar_date():
    # TransactTime(60) Feb 31
    rules = _rules(_order().replace(b"60=20231015-14:30:01", b"60=20230231-14:30:01"))
    assert "SAFIX-TYPE-011" in rules


def test_control_char_in_text_field():
    data = encode([(35, "D"), (34, 2), (49, "C"), (56, "S"), (11, "O1"), (55, "AAPL"),
                   (54, "1"), (38, "100"), (40, "2"), (44, "1.0"), (58, "x\x00y")],
                  begin_string="FIX.4.4")
    rules = _rules(data)
    assert "SAFIX-TYPE-021" in rules


def test_unknown_tag():
    data = encode([(35, "D"), (34, 2), (49, "C"), (56, "S"), (11, "O1"), (55, "AAPL"),
                   (54, "1"), (38, "100"), (40, "2"), (44, "1.0"), (9999, "x")],
                  begin_string="FIX.4.4")
    rules = _rules(data)
    assert "SAFIX-STRUCT-110" in rules  # unknown tag (UDF range -> low)


def test_missing_required_field():
    # NewOrderSingle without ClOrdID(11)
    data = encode([(35, "D"), (34, 2), (49, "C"), (52, "20231015-14:30:01"), (56, "S"),
                   (55, "AAPL"), (54, "1"), (38, "100"), (40, "2"), (44, "1.0"),
                   (60, "20231015-14:30:01")], begin_string="FIX.4.4")
    rules = _rules(data)
    assert "SAFIX-STRUCT-101" in rules


def test_group_count_desync():
    # NoPartyIDs(453)=3 but only one PartyID(448) present
    data = encode([(35, "D"), (34, 2), (49, "C"), (52, "20231015-14:30:01"), (56, "S"),
                   (11, "O1"), (453, "3"), (448, "ME"), (447, "D"), (452, "1"),
                   (55, "AAPL"), (54, "1"), (38, "100"), (40, "2"), (44, "1.0"),
                   (60, "20231015-14:30:01")], begin_string="FIX.4.4")
    rules = _rules(data)
    assert "SAFIX-STRUCT-130" in rules


def test_unknown_msgtype():
    data = encode([(35, "ZZ"), (34, 2), (49, "C"), (56, "S")], begin_string="FIX.4.4")
    rules = _rules(data)
    assert "SAFIX-STRUCT-120" in rules


def test_duplicate_scalar_tag():
    # duplicate ClOrdID(11) — a scalar field, not a group member
    data = encode([(35, "D"), (34, 2), (49, "C"), (52, "20231015-14:30:01"), (56, "S"),
                   (11, "O1"), (11, "O2"), (55, "AAPL"), (54, "1"), (38, "100"),
                   (40, "2"), (44, "1.0"), (60, "20231015-14:30:01")], begin_string="FIX.4.4")
    rules = _rules(data)
    assert "SAFIX-STRUCT-140" in rules
