"""Tests for live/streaming scanning: the tailer and the LiveScanner."""

from __future__ import annotations

import io
from pathlib import Path

from safix.config import Config
from safix.engine.live import LiveScanner
from safix.parsing import tail
from safix.parsing.encode import encode
from tests.conftest import make_logon, make_order


def _logon(seq):
    return encode([(35, "A"), (34, seq), (49, "C"), (52, "20231015-10:00:00"), (56, "S"),
                   (98, 0), (108, 30)], begin_string="FIX.4.4")


def _order(seq, over=None):
    d = dict([(35, "D"), (34, seq), (49, "C"), (52, "20231015-10:00:00"), (56, "S"),
              (11, "O1"), (55, "AAPL"), (54, "1"), (38, "100"), (40, "2"), (44, "150"),
              (60, "20231015-10:00:00")])
    if over:
        d.update(over)
    return encode(list(d.items()), begin_string="FIX.4.4")


# --- LiveScanner ---------------------------------------------------------------------------

def test_live_feed_clean_then_attack():
    ls = LiveScanner()
    import safix.parsing.lexer as lex
    assert ls.feed(lex.parse_message(_logon(1))) == []            # clean logon
    assert ls.feed(lex.parse_message(_order(2))) == []            # clean order
    # duplicate seqnum 2 -> stateful replay finding on the live stream
    out = ls.feed(lex.parse_message(_order(2, {11: "O2"})))
    assert any(f.rule_id == "SAFIX-SESS-SEQ-012" for f in out)


def test_live_stream_dedup():
    ls = LiveScanner()
    import safix.parsing.lexer as lex
    first = ls.feed(lex.parse_message(_order(2, {44: "0"})))      # non-positive price
    assert any(f.rule_id == "SAFIX-APP-005" for f in first)
    # same rule + same ClOrdID -> same fingerprint -> deduped on the stream
    second = ls.feed(lex.parse_message(_order(3, {44: "0"})))
    assert not any(f.rule_id == "SAFIX-APP-005" for f in second)


def test_live_summary_counts():
    ls = LiveScanner()
    import safix.parsing.lexer as lex
    ls.feed(lex.parse_message(_order(2, {38: "-5"})))
    s = ls.summary()
    assert s["messages"] == 1 and s["findings"] >= 1


# --- tailer --------------------------------------------------------------------------------

def test_follow_file_quickfix_log(tmp_path: Path):
    p = tmp_path / "messages.log"
    lines = [b"20231015-10:00:00.000 : " + make_logon(begin_string="FIX.4.4"),
             b"20231015-10:00:01.000 : " + make_order(begin_string="FIX.4.4")]
    p.write_bytes(b"\n".join(lines) + b"\n")
    got = []
    for m in tail.follow_file(p, from_start=True, poll_interval=0.01):
        got.append(m)
        if len(got) == 2:
            break
    assert [m.msg_type for m in got] == ["A", "D"]
    assert got[0].timestamp == "20231015-10:00:00.000"


def test_follow_file_sees_appended(tmp_path: Path):
    p = tmp_path / "m.log"
    p.write_bytes(b"20231015-10:00:00.000 : " + make_logon(begin_string="FIX.4.4") + b"\n")
    gen = tail.follow_file(p, from_start=True, poll_interval=0.01)
    assert next(gen).msg_type == "A"   # primes the generator (now suspended at the yield)
    with p.open("ab") as fh:           # append after the follower is live
        fh.write(b"20231015-10:00:02.000 : " + make_order(begin_string="FIX.4.4") + b"\n")
    m = next(gen)
    gen.close()
    assert m.msg_type == "D"


def test_follow_stream_stdin_like():
    blob = (b"20231015-10:00:00.000 : " + make_logon(begin_string="FIX.4.4") + b"\n"
            + b"20231015-10:00:01.000 : " + make_order(begin_string="FIX.4.4") + b"\n")
    msgs = list(tail.follow_stream(fileobj=io.BytesIO(blob)))
    assert [m.msg_type for m in msgs] == ["A", "D"]


def test_follow_file_raw_soh_frames(tmp_path: Path):
    # no newlines — frame-boundary segmentation
    p = tmp_path / "store.body"
    p.write_bytes(make_logon(begin_string="FIX.4.4") + make_order(begin_string="FIX.4.4"))
    got = []
    for m in tail.follow_file(p, from_start=True, poll_interval=0.01):
        got.append(m)
        if len(got) == 2:
            break
    assert [m.msg_type for m in got] == ["A", "D"]


def test_follow_file_handles_rotation(tmp_path: Path):
    import os
    p = tmp_path / "r.log"
    p.write_bytes(b"20231015-10:00:00.000 : " + make_logon(begin_string="FIX.4.4") + b"\n")
    gen = tail.follow_file(p, from_start=True, poll_interval=0.01)
    assert next(gen).msg_type == "A"
    # rotate the way a log engine does: swap in a brand-new current file (new inode)
    newp = tmp_path / "new"
    newp.write_bytes(b"20231015-10:01:00.000 : " + make_order(begin_string="FIX.4.4") + b"\n")
    os.replace(newp, p)
    m = next(gen)
    gen.close()
    assert m.msg_type == "D"
