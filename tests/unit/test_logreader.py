"""Tests for format detection, segmentation and the log reader."""

from __future__ import annotations

from safix.parsing import formats
from safix.parsing.logreader import ReadOptions, iter_messages, sniff
from safix.parsing.rawdata import SOH
from tests.conftest import make_logon, make_order


def test_pick_delimiter_soh():
    assert formats.pick_delimiter(b"8=FIX.4.2\x0135=A\x0110=000\x01") == SOH


def test_pick_delimiter_pipe():
    assert formats.pick_delimiter(b"8=FIX.4.2|9=10|35=A|10=000|") == b"|"


def test_split_prefix_quickfix_cpp():
    line = b"20231015-14:30:00.123456789 : 8=FIX.4.4\x0135=A\x0110=000\x01"
    ts, direction, start = formats.split_prefix(line)
    assert ts == "20231015-14:30:00.123456789"
    assert line[start:start + 2] == b"8="


def test_split_prefix_with_direction_arrow():
    line = b"20231015-14:30:00 --> 8=FIX.4.4\x0135=D\x0110=000\x01"
    ts, direction, start = formats.split_prefix(line)
    assert direction == "out"
    assert ts == "20231015-14:30:00"


def test_split_prefix_no_timestamp_qfj():
    line = b"8=FIX.4.4\x0135=A\x0110=000\x01"
    ts, direction, start = formats.split_prefix(line)
    assert ts is None
    assert start == 0


def test_blob_segmentation_two_messages():
    blob = make_logon(seq=1) + make_order(seq=2)
    segs = list(formats.iter_blob_segments(blob, SOH))
    assert len(segs) == 2
    assert segs[0][0].startswith(b"8=FIX.4.2")
    assert segs[1][1] == len(make_logon(seq=1))  # offset of 2nd message


def test_iter_messages_quickfix_log():
    lines = [
        b"20231015-14:30:00.000 : " + make_logon(seq=1),
        b"20231015-14:30:01.000 : " + make_order(seq=2),
    ]
    data = b"\n".join(lines) + b"\n"
    msgs = list(iter_messages(data, source="messages.log"))
    assert len(msgs) == 2
    assert msgs[0].msg_type == "A" and msgs[0].seq_num == 1
    assert msgs[1].msg_type == "D" and msgs[1].seq_num == 2
    assert msgs[0].timestamp == "20231015-14:30:00.000"
    assert msgs[0].source_line == 1 and msgs[1].source_line == 2
    assert all(m.checksum_ok for m in msgs)


def test_iter_messages_pipe_log():
    from safix.parsing.encode import encode
    raw = encode([(35, "A"), (34, 1), (49, "C"), (56, "S")],
                 begin_string="FIX.4.4", delimiter=b"|")
    data = raw + b"\n"
    fmt = sniff(data)
    assert fmt.field_delimiter == b"|"
    msgs = list(iter_messages(data))
    assert len(msgs) == 1 and msgs[0].msg_type == "A"


def test_iter_messages_blob():
    blob = make_logon(seq=1) + make_order(seq=2) + make_order(seq=3, clordid="ORD3")
    msgs = list(iter_messages(blob, source="store.body"))
    assert [m.seq_num for m in msgs] == [1, 2, 3]


def test_detect_reports_kind():
    log = b"20231015-14:30:00.000 : " + make_logon() + b"\n"
    assert sniff(log).input_kind == "quickfix-log"
    blob = make_logon() + make_order()
    assert sniff(blob).input_kind == "filestore-body"
