"""Tests for the dictionary loader and datatype validators against the bundled dictionaries."""

from __future__ import annotations

import pytest

from safix.dictionary import datatypes as dt
from safix.dictionary import loader


def test_load_fix44():
    spec = loader.load("FIX.4.4")
    assert spec.begin_string == "FIX.4.4"
    assert spec.field_number("MsgType") == 35
    assert spec.field_name(55) == "Symbol"
    assert spec.field_type(44) == "PRICE"
    # NewOrderSingle
    assert spec.message("D").name == "NewOrderSingle"
    # enums present on Side(54)
    assert spec.enum_values(54).get("1") == "BUY"
    # group count tags include NoPartyIDs(453)
    assert 453 in spec.group_count_tags
    # data pairs derived
    assert spec.len_to_data.get(95) == 96  # RawDataLength -> RawData


def test_fix44_required_and_allowed():
    spec = loader.load("FIX.4.4")
    required = spec.required_top_level_tags("D")
    assert 11 in required   # ClOrdID required in NewOrderSingle
    assert 8 in required and 35 in required  # header requireds
    allowed = spec.allowed_tags("D")
    assert 44 in allowed and 38 in allowed and 55 in allowed


def test_load_fixt_merged():
    spec = loader.load("FIXT.1.1")
    # admin messages from FIXT
    assert spec.message("A").name == "Logon"
    # app messages from FIX50SP2
    assert "D" in spec.messages_by_msgtype
    assert spec.field_number("Symbol") == 55
    assert spec.begin_string == "FIXT.1.1"


def test_all_bundled_versions_load():
    for v in loader.available_versions():
        spec = loader.load(v) if v != "FIXT.1.1" else loader.load("FIXT.1.1")
        assert spec.fields_by_number, f"{v} has no fields"


# --- datatype validators -------------------------------------------------------------------

@pytest.mark.parametrize("value,ok", [
    (b"34", True), (b"-1", True), (b"007", True),
    (b"+5", False), (b"3.0", False), (b"1e5", False), (b"", False), (b"3 4", False),
])
def test_int_grammar(value, ok):
    assert dt.validate("INT", value).lexical_ok is ok


@pytest.mark.parametrize("value,ok", [
    (b"12.5", True), (b"-3", True), (b"23.", True), (b".5", True), (b"0.00", True),
    (b"1e5", False), (b"+3.14", False), (b"1,000.5", False), (b"NaN", False),
    (b"1.2.3", False), (b".", False), (b"-", False), (b"", False),
])
def test_decimal_grammar(value, ok):
    assert dt.validate("PRICE", value).lexical_ok is ok


@pytest.mark.parametrize("value,ok", [(b"Y", True), (b"N", True),
                                      (b"y", False), (b"1", False), (b"true", False)])
def test_boolean_grammar(value, ok):
    assert dt.validate("BOOLEAN", value).lexical_ok is ok


def test_char_single_byte():
    assert dt.validate("CHAR", b"A").lexical_ok is True
    assert dt.validate("CHAR", b"").lexical_ok is False
    assert dt.validate("CHAR", b"12").lexical_ok is False


def test_utctimestamp_and_calendar():
    good = dt.validate("UTCTIMESTAMP", b"20231130-09:30:00.123")
    assert good.lexical_ok and good.calendar_ok
    # lexical pass but impossible calendar date (Feb 31)
    cal = dt.validate("UTCTIMESTAMP", b"20230231-09:30:00")
    assert cal.lexical_ok is True and cal.calendar_ok is False
    # hour 25 fails lexically
    assert dt.validate("UTCTIMESTAMP", b"20231130-25:00:00").lexical_ok is False
    # leap second allowed
    assert dt.validate("UTCTIMEONLY", b"23:59:60").lexical_ok is True


def test_string_control_chars():
    assert dt.validate("STRING", b"ACME Order #5").lexical_ok is True
    assert dt.validate("STRING", b"A\x00B").lexical_ok is False
    assert dt.validate("STRING", b"clear\x1b[2J").lexical_ok is False


def test_enforced_free_types_flagged():
    r = dt.validate("CURRENCY", b"usd")
    assert r.enforced_free is True and r.lexical_ok is False
    assert dt.validate("CURRENCY", b"USD").lexical_ok is True
    assert dt.validate("EXCHANGE", b"' OR 1=1").lexical_ok is False


def test_monthyear_xsd_defect():
    # month 13 matches defective XSD but not prose-strict
    assert dt.monthyear_regex_defect(b"202313") is True
    assert dt.monthyear_regex_defect(b"202312") is False


def test_int_magnitude_class():
    assert dt.validate("SEQNUM", b"2200000000").magnitude_class == "int32_overflow"
    assert dt.validate("SEQNUM", b"34").magnitude_class is None


def test_unknown_type_no_violation():
    r = dt.validate("SOMEWEIRDTYPE", b"anything")
    assert r.lexical_ok is None and r.is_violation is False
