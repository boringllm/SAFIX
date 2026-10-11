"""SESS detectors — stateful session & sequence analysis.

Tracks per-directional-stream state (``SessionKey`` = BeginString+Sender+Target) to detect the
headline session attacks with low false-positive rates:

* STA-01  Logon ResetSeqNumFlag(141)=Y mid-session (attacker-operable reset)
* double Logon / Logon flood / TestRequest flood / ResendRequest flood (rate, via SendingTime)
* SEQ-05  ResendRequest EndSeqNo(16)=0 amplification; inverted/zero ranges
* duplicate MsgSeqNum replay (with / without PossDup) and PossDup body-mismatch injection
* SEQ-13  gap -> SequenceReset-GapFill smuggling (NewSeqNo == a previously-queued high seqnum)
* SequenceReset to a lower/equal NewSeqNo (verify bypass / desync)

The sequence model is contiguity-based so a normal recovery gap does not generate noise.
"""

from __future__ import annotations

import hashlib
from collections import deque
from typing import TYPE_CHECKING, Optional

from ..model.finding import Confidence, Finding, Severity
from ..util.fixtime import parse_utc_timestamp
from .base import Detector, register

if TYPE_CHECKING:  # pragma: no cover
    from ..engine.context import ScanContext
    from ..model.message import FixMessage
    from ..model.session import SessionState

H, M, L, I = Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
CH, CM, CL = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW

# admin msg types
LOGON, LOGOUT, HEARTBEAT, TESTREQ, RESEND, SEQRESET, REJECT = "A", "5", "0", "1", "2", "4", "3"

# tags
T_SEQ, T_POSSDUP, T_ORIGSENDING, T_RESET_FLAG = 34, 43, 122, 141
T_BEGINSEQ, T_ENDSEQ, T_NEWSEQ, T_GAPFILL, T_HEARTBTINT = 7, 16, 36, 123, 108
_VOLATILE = {9, 10, 52, 34, 43, 122}  # excluded from the replay body hash


def _body_hash(msg: "FixMessage") -> str:
    parts = [f"{f.tag}={f.value_str}" for f in msg.fields if f.tag not in _VOLATILE]
    return hashlib.sha1("\x01".join(parts).encode("utf-8", "replace")).hexdigest()[:16]


def _rate_window(st: "SessionState", name: str) -> deque:
    w = st.rate_windows.get(name)
    if w is None:
        w = deque()
        st.rate_windows[name] = w
    return w


@register
class SessionSequenceDetector(Detector):
    id = "session-seq"
    category = "SESS"
    title = "Stateful session & sequence-number analysis"

    def analyze(self, msg: "FixMessage", ctx: "ScanContext") -> None:
        st = ctx.session_state(msg)
        mt = msg.msg_type
        now = parse_utc_timestamp(msg.sending_time)

        if mt == LOGON:
            self._logon(msg, ctx, st, now)
        elif mt == TESTREQ:
            self._flood(msg, ctx, st, now, "testreq", "SAFIX-SESS-STA-005",
                        ctx.config.thresholds.testrequest_flood_window_sec,
                        ctx.config.thresholds.testrequest_flood_count,
                        "TestRequest flood", ["AV-SESS-STA-05"])
        elif mt == RESEND:
            self._resend(msg, ctx, st, now)
        elif mt == SEQRESET:
            self._seqreset(msg, ctx, st)
        elif mt == LOGOUT:
            st.logged_on = False
            st.logout_count += 1

        self._sequence(msg, ctx, st)

    # --- logon ------------------------------------------------------------------------------
    def _logon(self, msg, ctx, st: "SessionState", now) -> None:
        st.logon_count += 1
        hb = msg.get_int(T_HEARTBTINT)
        if hb is not None:
            st.heartbeat_int = hb
        reset = msg.get_str(T_RESET_FLAG)
        if reset == "Y":
            st.reset_seq_requests += 1
            # a reset at the very first message of a stream is the normal session start
            first = st.message_count <= 1
            sev, conf = (M, CL) if first else (H, CM)
            note = ["A ResetSeqNumFlag=Y on the session-opening Logon is normal."] if first else [
                "Scheduled daily sequence resets are legitimate — correlate with session start."]
            self._emit(ctx, msg, "SAFIX-SESS-STA-001", sev, conf,
                       "Logon ResetSeqNumFlag(141)=Y (sequence reset)",
                       "Logon requests a sequence-number reset; this re-enables replay from seq 1 "
                       + ("(at session start)" if first else "mid-session"),
                       ["AV-SESS-STA-01", "SV-SESS-15"], tag=T_RESET_FLAG, benign=note,
                       remediation="Bind resets to authenticated session start; alert on mid-session resets.")
        if st.logged_on and not reset == "Y":
            self._emit(ctx, msg, "SAFIX-SESS-STA-002", M, CM, "Repeated Logon on an active session",
                       "a second Logon(35=A) arrived without an intervening Logout",
                       ["AV-SESS-STA-04"], benign=["Reconnect races can produce a duplicate Logon."],
                       remediation="Reject a Logon on an already-established session.")
        st.logged_on = True
        self._flood(msg, ctx, st, now, "logon", "SAFIX-SESS-STA-003",
                    ctx.config.thresholds.logon_flood_window_sec,
                    ctx.config.thresholds.logon_flood_count, "Logon flood", ["AV-SESS-STA-02"])

    # --- resend request ---------------------------------------------------------------------
    def _resend(self, msg, ctx, st: "SessionState", now) -> None:
        begin = msg.get_int(T_BEGINSEQ)
        end = msg.get_int(T_ENDSEQ)
        if end == 0:
            self._emit(ctx, msg, "SAFIX-SESS-SEQ-005", M, CM,
                       "ResendRequest EndSeqNo(16)=0 (resend all — amplification)",
                       "EndSeqNo=0 requests the entire message store (spec-legal 'infinity' but abusable)",
                       ["AV-SESS-SEQ-05"], tag=T_ENDSEQ,
                       benign=["EndSeqNo=0 is the standard way to request 'all since BeginSeqNo'."],
                       remediation="Rate-limit and bound resend ranges; watch for repeated full-store asks.")
        elif begin is not None and end is not None and begin > end:
            self._emit(ctx, msg, "SAFIX-SESS-SEQ-007", M, CH,
                       "ResendRequest inverted range (BeginSeqNo > EndSeqNo)",
                       f"BeginSeqNo({begin}) > EndSeqNo({end}) is a malformed/again-abusable range",
                       ["AV-SESS-SEQ-08"], tag=T_BEGINSEQ, benign=[],
                       remediation="Reject inverted resend ranges.")
        self._flood(msg, ctx, st, now, "resend", "SAFIX-SESS-SEQ-006",
                    ctx.config.thresholds.resend_flood_window_sec,
                    ctx.config.thresholds.resend_flood_count, "ResendRequest flood",
                    ["AV-SESS-SEQ-06"])

    # --- sequence reset ---------------------------------------------------------------------
    def _seqreset(self, msg, ctx, st: "SessionState") -> None:
        new_seq = msg.get_int(T_NEWSEQ)
        gapfill = msg.get_str(T_GAPFILL) == "Y"
        if new_seq is None:
            return
        # SEQ-13 smuggling: GapFill advancing to a previously-queued (too-high) seqnum
        if gapfill and new_seq in st.queued_high_seqnums:
            self._emit(ctx, msg, "SAFIX-SESS-SEQ-013", H, CM,
                       "GapFill targets a previously-queued high seqnum (smuggling chain)",
                       f"SequenceReset-GapFill NewSeqNo={new_seq} matches an earlier out-of-order "
                       "message — the queued forged message would be drained as genuine",
                       ["AV-SESS-SEQ-13"], tag=T_NEWSEQ, benign=[],
                       remediation="Validate GapFill against the real gap; never drain future-seq queue entries.")
        # reset to a lower/equal seqnum (verify bypass / desync)
        if st.expected_seq is not None and new_seq <= st.expected_seq:
            mode = "GapFill" if gapfill else "Reset"
            self._emit(ctx, msg, "SAFIX-SESS-SEQ-010", M, CM,
                       f"SequenceReset-{mode} to a non-advancing NewSeqNo",
                       f"NewSeqNo({new_seq}) <= expected({st.expected_seq}) rewinds/holds the sequence",
                       ["AV-SESS-SEQ-10", "AV-SESS-SEQ-11"], tag=T_NEWSEQ,
                       benign=["A benign GapFill never lowers the sequence."],
                       remediation="Reject non-advancing SequenceReset; in reset mode verify carefully.")
        elif new_seq is not None and st.expected_seq is not None and new_seq > st.expected_seq + 1:
            self._emit(ctx, msg, "SAFIX-SESS-SEQ-009", M, CL,
                       "SequenceReset leapfrogs the sequence forward",
                       f"NewSeqNo({new_seq}) jumps well beyond expected({st.expected_seq}) — "
                       "may void intervening messages",
                       ["AV-SESS-SEQ-09"], tag=T_NEWSEQ,
                       benign=["Large legitimate gaps after an outage can require a big GapFill."],
                       remediation="Correlate the jump with a real gap before accepting.")
        st.expected_seq = max(st.expected_seq or 0, new_seq)

    # --- sequence number tracking -----------------------------------------------------------
    def _sequence(self, msg, ctx, st: "SessionState") -> None:
        s = msg.seq_num
        if s is None:
            return
        possdup = msg.get_str(T_POSSDUP) == "Y"
        bh = _body_hash(msg)

        if s in st.seen_seqnums:
            orig = st.scratch.get(f"bh:{s}")
            if not possdup:
                self._emit(ctx, msg, "SAFIX-SESS-SEQ-012", H, CH,
                           "Duplicate MsgSeqNum without PossDup(43=Y) (replay/injection)",
                           f"MsgSeqNum {s} already seen in this stream and PossDup is not set",
                           ["AV-SESS-SEQ-12", "SV-SESS-3"], tag=T_SEQ, benign=[],
                           remediation="A non-PossDup duplicate is a replay or desync; disconnect.")
            else:
                if msg.get_str(T_ORIGSENDING) is None:
                    self._emit(ctx, msg, "SAFIX-SESS-SEQ-011", M, CM,
                               "PossDup resend missing OrigSendingTime(122)",
                               f"PossDup(43=Y) replay of seq {s} omits OrigSendingTime(122)",
                               ["AV-SESS-SEQ-12", "SV-SESS-10"], tag=T_ORIGSENDING,
                               benign=["Some engines tolerate a missing OrigSendingTime."],
                               remediation="Require OrigSendingTime on PossDup messages.")
                if orig is not None and orig != bh:
                    self._emit(ctx, msg, "SAFIX-SESS-SEQ-014", H, CM,
                               "PossDup replay with altered body (injection under resend)",
                               f"the PossDup resend of seq {s} differs from the original message body",
                               ["AV-SESS-SEQ-12"], tag=T_SEQ, benign=[],
                               remediation="A genuine resend is byte-identical except session fields; reject.")
            return

        # first message of the stream establishes the baseline
        if st.expected_seq is None:
            st.expected_seq = s + 1
        elif s == st.expected_seq:
            st.expected_seq += 1
            while st.expected_seq in st.queued_high_seqnums:
                del st.queued_high_seqnums[st.expected_seq]
                st.expected_seq += 1
        elif s > st.expected_seq:
            st.queued_high_seqnums[s] = msg.msg_offset
            if len(st.queued_high_seqnums) > ctx.config.thresholds.queued_high_seqnum_limit:
                self._emit(ctx, msg, "SAFIX-SESS-SEQ-002", H, CM,
                           "Excessive out-of-order (too-high) messages queued (resource exhaustion)",
                           f"{len(st.queued_high_seqnums)} future-seqnum messages queued without fill",
                           ["AV-SESS-SEQ-02"], tag=T_SEQ, benign=["A long genuine outage can queue many."],
                           remediation="Bound the out-of-order queue; this is the real queue-OOM surface.")
        elif s < st.expected_seq:
            self._emit(ctx, msg, "SAFIX-SESS-SEQ-003", M, CM,
                       "Too-low MsgSeqNum (sequence rewind / desync)",
                       f"MsgSeqNum {s} is below expected {st.expected_seq} and was not seen before",
                       ["AV-SESS-SEQ-03"], tag=T_SEQ,
                       benign=["A legitimate reset lowers the sequence (correlate with 141=Y/SeqReset)."],
                       remediation="A non-reset low seqnum forces a logout in a conformant engine.")

        st.seen_seqnums.add(s)
        st.scratch[f"bh:{s}"] = bh
        st.last_seq = s if st.last_seq is None else max(st.last_seq, s)

    # --- rate helper ------------------------------------------------------------------------
    def _flood(self, msg, ctx, st, now, name, rule_id, window_sec, count, title, vectors) -> None:
        w = _rate_window(st, name)
        # use SendingTime when available; else a monotonic message ordinal as a coarse clock
        t = now if now is not None else float(st.message_count)
        w.append(t)
        horizon = t - (window_sec if now is not None else count)
        while w and w[0] < horizon:
            w.popleft()
        if len(w) > count:
            self._emit(ctx, msg, rule_id, M, CM, title,
                       f"{len(w)} {name} messages within {window_sec}s window (threshold {count})",
                       list(vectors), benign=["Busy legitimate sessions can approach the threshold — tune it."],
                       remediation=f"Rate-limit {name} messages; tune the window/count for the venue.")
            w.clear()  # avoid repeating every message in the burst

    def _emit(self, ctx, msg, rule_id, sev, conf, title, message, vectors, *,
              tag=None, benign, remediation) -> None:
        if not ctx.config.rule_enabled(rule_id, "SESS"):
            return
        ctx.add(
            Finding(
                rule_id=rule_id, title=title, message=message, severity=sev, confidence=conf,
                category="SESS", vector_ids=list(vectors), tag=tag,
                benign_notes=list(benign), remediation=remediation,
                dedup_key=f"{rule_id}:{msg.seq_num}",
            ),
            msg,
        )
