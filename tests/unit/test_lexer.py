"""Unit tests for the lenient FIX lexer."""

from __future__ import annotations

from safix.parsing.encode import encode
from safix.parsing.lexer import parse_message
from safix.parsing.rawdata import SOH
from tests.conftest import make_logon, make_order


def _codes(msg) -> set[str]:
    return {a.code for a in msg.all_anomalies}


def test_wellformed_logon_parses_clean():
    raw = make_logon()
    msg = parse_message(raw)
    assert msg.begin_string == "FIX.4.2"
    assert msg.msg_type == "A"
    assert msg.seq_num == 1
    assert msg.sender_comp_id == "CLIENT"
    assert msg.target_comp_id == "SERVER"
    assert msg.body_length_ok is True
    assert msg.checksum_ok is True
    assert msg.all_anomalies == []


def test_order_fields_and_accessors():
    msg = parse_message(make_order())
    assert msg.msg_type == "D"
    assert msg.get_str(55) == "AAPL"
    assert msg.get_int(38) == 100
    assert msg.get_str(44) == "150.00"
    assert msg.has(40)
    assert not msg.has(99)


def test_pipe_delimiter():
    raw = encode([(35, "0"), (34, 5), (49, "A"), (56, "B")],
                 begin_string="FIX.4.4", delimiter=b"|")
    msg = parse_message(raw, field_delimiter=b"|")
    assert msg.msg_type == "0"
    assert msg.body_length_ok is True
    assert msg.checksum_ok is True


def test_bad_bodylength_detected():
    raw = make_logon()
    # corrupt the declared BodyLength: find "9=NN" and bump it
    msg = parse_message(raw)
    bl = msg.body_length_declared
    bad = raw.replace(b"9=" + str(bl).encode(), b"9=" + str(bl + 7).encode(), 1)
    m2 = parse_message(bad)
    assert m2.body_length_ok is False
    assert "BODYLENGTH_MISMATCH" in _codes(m2)


def test_bad_checksum_detected():
    raw = bytearray(make_logon())
    # corrupt the 3-digit checksum (last field before final SOH)
    raw[-4:-1] = b"000"
    m = parse_message(bytes(raw))
    # either it now mismatches the recomputed sum, or stays—force a guaranteed mismatch:
    assert m.checksum_declared == b"000"
    if m.checksum_computed != 0:
        assert m.checksum_ok is False
        assert "CHECKSUM_MISMATCH" in _codes(m)


def test_non_numeric_tag_recorded_not_raised():
    raw = b"8=FIX.4.2\x019=10\x0135=D\x01XY=foo\x0110=000\x01"
    m = parse_message(raw)
    codes = _codes(m)
    assert "NON_NUMERIC_TAG" in codes
    # the bad field is still captured
    assert any(f.tag_bytes == b"XY" for f in m.fields)


def test_leading_zero_tag_aliasing():
    raw = b"8=FIX.4.2\x019=5\x01007=X\x0110=000\x01"
    m = parse_message(raw)
    codes = _codes(m)
    assert "LEADING_ZERO_TAG" in codes
    f = m.get_field(7)
    assert f is not None and f.tag_bytes == b"007"


def test_data_field_with_embedded_soh():
    # RawData 95->96: value "ab\x01cd" has length 5 and contains an SOH
    inner = b"ab" + SOH + b"cd"
    body = b"35=D" + SOH + b"95=5" + SOH + b"96=" + inner + SOH
    raw = b"8=FIX.4.4" + SOH + b"9=" + str(len(body)).encode() + SOH + body
    raw += b"10=000" + SOH
    m = parse_message(raw)
    f96 = m.get_field(96)
    assert f96 is not None
    assert f96.value == inner
    assert f96.is_data_value is True
    # the embedded SOH did NOT create bogus fields
    assert "MALFORMED_FIELD_NO_EQUALS" not in _codes(m)


def test_data_length_mismatch_smuggling():
    # declare length 2 but the real field is longer -> desync + unframed bytes
    body = b"35=D" + SOH + b"95=2" + SOH + b"96=abcdef" + SOH
    raw = b"8=FIX.4.4" + SOH + b"9=" + str(len(body)).encode() + SOH + body + b"10=000" + SOH
    m = parse_message(raw)
    assert "DATA_LEN_MISMATCH" in _codes(m)


def test_data_length_overrun():
    body = b"35=D" + SOH + b"95=999" + SOH + b"96=ab" + SOH
    raw = b"8=FIX.4.4" + SOH + b"9=" + str(len(body)).encode() + SOH + body + b"10=000" + SOH
    m = parse_message(raw)
    assert "DATA_LEN_OVERRUN" in _codes(m)


def test_duplicate_structural_tag():
    raw = make_logon()
    # inject a second MsgType
    raw2 = raw.replace(b"35=A\x01", b"35=A\x0135=D\x01", 1)
    m = parse_message(raw2)
    assert "DUPLICATE_STRUCTURAL_TAG" in _codes(m)


def test_missing_begin_string():
    raw = b"35=A\x0149=X\x0156=Y\x0110=000\x01"
    m = parse_message(raw)
    assert "MISSING_OR_MISPLACED_BEGINSTRING" in _codes(m)


def test_truncated_no_checksum():
    raw = b"8=FIX.4.2\x019=10\x0135=A\x0149=X\x01"
    m = parse_message(raw)
    assert "TRUNCATED_NO_CHECKSUM" in _codes(m)


def test_order_and_duplicates_preserved():
    raw = b"8=FIX.4.2\x019=10\x0135=D\x0158=one\x0158=two\x0110=000\x01"
    m = parse_message(raw)
    assert m.get_all(58) == [b"one", b"two"]
    assert m.count(58) == 2
    # order preserved
    tags = [f.tag for f in m.fields]
    assert tags == [8, 9, 35, 58, 58, 10]
