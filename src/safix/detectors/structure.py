"""STRUCT detectors — dictionary-driven message structure validation.

Stateless / single-message. Covers unknown/foreign tags, missing required fields, unknown
MsgType, repeating-group count desync and count-value sanity, and duplicate scalar (non-group)
tags (first/last-wins parameter pollution).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..model.finding import Confidence, Finding, Severity
from .base import Detector, register

if TYPE_CHECKING:  # pragma: no cover
    from ..dictionary.spec import FixSpec
    from ..engine.context import ScanContext
    from ..model.message import FixMessage

S, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
CH, CM, CL = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW

_STRUCTURAL = {8, 9, 35, 10}
_UDF_MIN = 5000  # user-defined tag range — unknown tags here are expected


@register
class StructureDetector(Detector):
    id = "structure"
    category = "STRUCT"
    title = "Message structure: unknown/required fields, group desync, duplicate tags"

    def analyze(self, msg: "FixMessage", ctx: "ScanContext") -> None:
        spec = ctx.spec_for(msg)
        if spec is None:
            return
        msgtype = msg.msg_type
        self._check_msgtype(msg, ctx, spec, msgtype)
        known_msgtype = msgtype is not None and spec.message(msgtype) is not None
        allowed = spec.allowed_tags(msgtype) if known_msgtype else set()

        self._check_tags(msg, ctx, spec, msgtype, known_msgtype, allowed)
        if known_msgtype:
            self._check_required(msg, ctx, spec, msgtype)
        self._check_group_counts(msg, ctx, spec)
        self._check_duplicate_scalars(msg, ctx, spec)

    # --- unknown / malformed MsgType --------------------------------------------------------
    def _check_msgtype(self, msg, ctx, spec: "FixSpec", msgtype) -> None:
        if msgtype is None:
            return
        if spec.message(msgtype) is None:
            self._emit(ctx, msg, "SAFIX-STRUCT-120", M, CM, "Unknown or undefined MsgType(35)",
                       f"MsgType(35)={msgtype!r} is not defined in {spec.begin_string}",
                       ["AV-STRUCT-20"], tag=35,
                       benign=["Venue-specific/custom message types exist by bilateral agreement."],
                       remediation="Reject unknown MsgType with BusinessReject(35=j) reason 3.")

    # --- unknown / foreign tags -------------------------------------------------------------
    def _check_tags(self, msg, ctx, spec: "FixSpec", msgtype, known_msgtype, allowed) -> None:
        reported: set[int] = set()
        for fld in msg.fields:
            t = fld.tag
            if t is None or t in reported:
                continue
            if not spec.is_known_tag(t):
                if t >= _UDF_MIN:
                    sev, conf = L, CL
                    note = ["User-defined tag range (>=5000) — extensions are expected here."]
                else:
                    sev, conf = M, CM
                    note = ["A custom/vendor field below the UDF range; confirm with the venue."]
                self._emit(ctx, msg, "SAFIX-STRUCT-110", sev, conf, "Unknown/undefined tag",
                           f"tag {t} is not defined in {spec.begin_string}",
                           ["AV-STRUCT-04", "AV-STRUCT-05"], tag=t, field_index=fld.index,
                           benign=note,
                           remediation="Reject undefined tags if ValidateUserDefinedFields=Y.")
                reported.add(t)
            elif known_msgtype and t not in allowed and t not in _STRUCTURAL:
                self._emit(ctx, msg, "SAFIX-STRUCT-111", M, CM, "Foreign tag for this message type",
                           f"tag {t} ({spec.field_name(t)}) is not valid in MsgType {msgtype}",
                           ["AV-STRUCT-05"], tag=t, field_index=fld.index,
                           benign=["Some venues tolerate extra fields; ValidateFieldsOutOfOrder off."],
                           remediation="Reject out-of-context fields per SessionRejectReason 2.")
                reported.add(t)

    # --- missing required -------------------------------------------------------------------
    def _check_required(self, msg, ctx, spec: "FixSpec", msgtype) -> None:
        present = {f.tag for f in msg.fields if f.tag is not None}
        for req in sorted(spec.required_top_level_tags(msgtype)):
            if req not in present:
                self._emit(ctx, msg, "SAFIX-STRUCT-101", M, CH, "Missing required field",
                           f"required field {req} ({spec.field_name(req)}) missing from MsgType {msgtype}",
                           ["AV-STRUCT-01", "SV-STRUCT-1"], tag=req,
                           benign=["Conditionally-required prose rules vary; a gateway may add it later."],
                           remediation="Reject per SessionRejectReason(373)=1 (required tag missing).")

    # --- repeating-group count desync -------------------------------------------------------
    def _check_group_counts(self, msg, ctx, spec: "FixSpec") -> None:
        for count_tag, delim_tag in spec.group_delimiters.items():
            cfld = msg.get_field(count_tag)
            if cfld is None:
                continue
            raw = cfld.value
            try:
                declared = int(raw)
            except ValueError:
                self._emit(ctx, msg, "SAFIX-STRUCT-132", H, CH, "Non-numeric group count",
                           f"group count {count_tag} ({spec.field_name(count_tag)}) is non-numeric: {cfld.value_str!r}",
                           ["AV-STRUCT-12", "AV-TYPE-13"], tag=count_tag,
                           benign=[], remediation="Reject non-numeric NoXXX counts.")
                continue
            if declared < 0:
                self._emit(ctx, msg, "SAFIX-STRUCT-131", H, CH, "Negative group count",
                           f"group count {count_tag} is negative ({declared})",
                           ["AV-STRUCT-11", "AV-TYPE-13"], tag=count_tag, benign=[],
                           remediation="Reject negative NoXXX counts.")
                continue
            actual = msg.count(delim_tag)
            if declared != actual:
                # declared==0 with actual>0 and vice versa are desync too
                self._emit(ctx, msg, "SAFIX-STRUCT-130", H, CM, "Repeating-group count desync",
                           f"group {count_tag} ({spec.field_name(count_tag)}) declares {declared} "
                           f"but {actual} delimiter tag {delim_tag} ({spec.field_name(delim_tag)}) occurrence(s) present",
                           ["AV-STRUCT-08", "AV-STRUCT-09"], tag=count_tag,
                           benign=["Delimiter tag shared across groups can skew the naive count "
                                   "(confirm with full group parse)."],
                           remediation="Count desync drives parser divergence/field absorption; reject.")

    # --- duplicate scalar tags --------------------------------------------------------------
    def _check_duplicate_scalars(self, msg, ctx, spec: "FixSpec") -> None:
        counts: dict[int, int] = {}
        for f in msg.fields:
            if f.tag is not None:
                counts[f.tag] = counts.get(f.tag, 0) + 1
        repeatable = spec.group_member_tags_for(msg.msg_type)
        for t, c in counts.items():
            if c <= 1 or t in _STRUCTURAL:
                continue
            if t in repeatable or t in spec.group_count_tags:
                continue  # legitimately repeats inside a group for THIS message type
            if not spec.is_known_tag(t):
                continue  # unknown tag duplication handled elsewhere
            self._emit(ctx, msg, "SAFIX-STRUCT-140", H, CH, "Duplicate scalar tag (parameter pollution)",
                       f"scalar tag {t} ({spec.field_name(t)}) appears {c} times "
                       "(first/last-wins parser divergence)",
                       ["AV-STRUCT-06", "AV-STRUCT-07", "SV-STRUCT-24"], tag=t,
                       benign=["Rarely benign for a scalar field outside a repeating group."],
                       remediation="Reject duplicate scalar fields per SessionRejectReason 13.")

    # --- helper -----------------------------------------------------------------------------
    def _emit(self, ctx, msg, rule_id, sev, conf, title, message, vectors, *,
              tag=None, field_index=None, benign, remediation) -> None:
        if not ctx.config.rule_enabled(rule_id, "STRUCT"):
            return
        ctx.add(
            Finding(
                rule_id=rule_id, title=title, message=message, severity=sev, confidence=conf,
                category="STRUCT", vector_ids=list(vectors), tag=tag, field_index=field_index,
                benign_notes=list(benign), remediation=remediation,
                dedup_key=f"{rule_id}:{tag}",
            ),
            msg,
        )
