"""Tests for the stateful SESS (session/sequence) detector."""

from __future__ import annotations

from safix.engine.runner import scan_bytes
from safix.parsing.encode import encode


def _m(fields, bs="FIX.4.4"):
    return encode(fields, begin_string=bs)


def _rules(blob: bytes) -> set[str]:
    res = scan_bytes(blob, source="t.log")
    return {f.rule_id for f in res.active_findings}


def _logon(seq, reset=None, t="20231015-10:00:00", hb=30):
    f = [(35, "A"), (34, seq), (49, "CLIENT"), (52, t), (56, "SERVER"), (98, 0), (108, hb)]
    if reset:
        f.append((141, reset))
    return _m(f)


def _order(seq, t="20231015-10:00:05", possdup=None, orig=None, clordid="O1"):
    f = [(35, "D"), (34, seq), (49, "CLIENT"), (52, t), (56, "SERVER"),
         (11, clordid), (55, "AAPL"), (54, "1"), (38, "100"), (40, "2"), (44, "1.0"),
         (60, t)]
    if possdup:
        f.insert(5, (43, possdup))
    if orig:
        f.append((122, orig))
    return _m(f)


def test_reset_seqnum_midsession_high():
    blob = _order(1) + _logon(2, reset="Y")
    res = scan_bytes(blob, source="t.log")
    f = next(f for f in res.active_findings if f.rule_id == "SAFIX-SESS-STA-001")
    assert f.severity.value == "high"


def test_reset_seqnum_at_start_is_low():
    blob = _logon(1, reset="Y")
    res = scan_bytes(blob, source="t.log")
    f = next((f for f in res.active_findings if f.rule_id == "SAFIX-SESS-STA-001"), None)
    assert f is not None and f.severity.value in ("medium", "low")


def test_resend_endseqno_zero():
    blob = _logon(1) + _m([(35, "2"), (34, 2), (49, "CLIENT"), (52, "20231015-10:00:01"),
                           (56, "SERVER"), (7, 1), (16, 0)])
    assert "SAFIX-SESS-SEQ-005" in _rules(blob)


def test_resend_inverted_range():
    blob = _logon(1) + _m([(35, "2"), (34, 2), (49, "CLIENT"), (52, "20231015-10:00:01"),
                           (56, "SERVER"), (7, 10), (16, 5)])
    assert "SAFIX-SESS-SEQ-007" in _rules(blob)


def test_duplicate_seqnum_replay_no_possdup():
    blob = _logon(1) + _order(2) + _order(2, clordid="O2")
    assert "SAFIX-SESS-SEQ-012" in _rules(blob)


def test_possdup_missing_origsendingtime():
    blob = _logon(1) + _order(2) + _order(2, possdup="Y")  # dup seq 2 w/ PossDup, no 122
    assert "SAFIX-SESS-SEQ-011" in _rules(blob)


def test_possdup_altered_body_injection():
    # genuine order seq2, then PossDup replay of seq2 with a different ClOrdID + OrigSendingTime
    blob = _order(2, clordid="O1") + _order(2, possdup="Y", orig="20231015-10:00:05", clordid="HACK")
    assert "SAFIX-SESS-SEQ-014" in _rules(blob)


def test_gapfill_smuggling_chain():
    # logon seq1; app at too-high seq5 (queued); then GapFill NewSeqNo=5
    blob = _logon(1) + _order(5) + _m([(35, "4"), (34, 2), (49, "CLIENT"),
                                       (52, "20231015-10:00:06"), (56, "SERVER"),
                                       (123, "Y"), (36, 5)])
    assert "SAFIX-SESS-SEQ-013" in _rules(blob)


def test_sequencereset_to_lower():
    blob = _logon(1) + _order(2) + _m([(35, "4"), (34, 3), (49, "CLIENT"),
                                       (52, "20231015-10:00:06"), (56, "SERVER"),
                                       (123, "Y"), (36, 1)])
    assert "SAFIX-SESS-SEQ-010" in _rules(blob)


def test_double_logon():
    blob = _logon(1) + _logon(2)
    assert "SAFIX-SESS-STA-002" in _rules(blob)


def test_logon_flood():
    blob = b"".join(_logon(i, t="20231015-10:00:00") for i in range(1, 9))
    assert "SAFIX-SESS-STA-003" in _rules(blob)


def test_clean_session_quiet():
    blob = _logon(1) + _order(2) + _order(3, clordid="O3", t="20231015-10:00:06")
    rules = _rules(blob)
    assert not any(r.startswith("SAFIX-SESS-") for r in rules)
