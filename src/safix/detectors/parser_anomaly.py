"""Promote parser-level anomalies (framing, Len/Data desync, byte-structure) into findings.

The lenient lexer records anomalies with byte offsets; this detector maps the security-relevant
ones to Findings carrying severity/confidence and their source attack-vector IDs. It is stateless
(single message) and covers the SESS-framing, TYPE Len/Data, and byte-level STRUCT vectors.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..model.finding import Confidence, Finding, Severity
from .base import Detector, register

if TYPE_CHECKING:  # pragma: no cover
    from ..engine.context import ScanContext
    from ..model.message import FixMessage


@dataclass(slots=True)
class _Rule:
    rule_id: str
    category: str
    severity: Severity
    confidence: Confidence
    title: str
    vector_ids: list[str] = field(default_factory=list)
    benign: list[str] = field(default_factory=list)
    remediation: str = ""


S, H, M, L, I = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
CH, CM, CL = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW

# anomaly code -> finding rule
_RULES: dict[str, _Rule] = {
    "BODYLENGTH_MISMATCH": _Rule(
        "SAFIX-SESS-FRM-001", "SESS", H, CH, "BodyLength(9) does not match the computed body",
        ["AV-SESS-FRM-07", "AV-SESS-FRM-01", "SV-ENC-4"],
        ["A truncated capture or a log tool that reflowed the message can cause a mismatch."],
        "Reject per SessionRejectReason; a short count may smuggle extra fields past the frame."),
    "BODYLENGTH_NOT_NUMERIC": _Rule(
        "SAFIX-SESS-FRM-002", "SESS", H, CH, "BodyLength(9) is non-numeric",
        ["AV-SESS-FRM-01"], [], "Non-numeric/negative BodyLength can flush the receive buffer."),
    "CHECKSUM_MISMATCH": _Rule(
        "SAFIX-SESS-FRM-003", "SESS", H, CH, "CheckSum(10) does not match the recomputed value",
        ["AV-SESS-FRM-06", "SV-ENC-4"],
        ["A printable-delimiter (pipe) log changes the byte sum; read the true SOH form.",
         "A truncated/edited capture changes the sum."],
        "Reject the message; a forged checksum hides tampering."),
    "CHECKSUM_WRONG_WIDTH": _Rule(
        "SAFIX-SESS-FRM-004", "SESS", M, CM, "CheckSum(10) is not exactly three digits",
        ["SV-TYPE-37"], ["Some non-conformant tools omit zero-padding."],
        "CheckSum must be 3 ASCII digits, 000-255."),
    "TRUNCATED_NO_CHECKSUM": _Rule(
        "SAFIX-SESS-FRM-005", "SESS", M, CM, "Message has no CheckSum(10) (truncated?)",
        ["AV-SESS-FRM-02"], ["A partial/rotated log can cut off the final message."],
        "A truncated frame can stall a length-prefixed reader."),
    "MISSING_OR_MISPLACED_BEGINSTRING": _Rule(
        "SAFIX-SESS-FRM-006", "SESS", H, CM, "Message does not begin with BeginString(8)",
        ["AV-SESS-FRM-05", "AV-STRUCT-16"],
        ["Leading log prefix not stripped; or a mid-stream capture start."],
        "Leading garbage before 8= is stripped by lenient parsers and can hide a smuggled frame."),
    "TRAILING_BYTES_AFTER_CHECKSUM": _Rule(
        "SAFIX-SESS-FRM-007", "SESS", H, CM, "Bytes present after CheckSum(10) within the record",
        ["AV-SESS-FRM-03"], ["Two messages captured on one line without a separator."],
        "Trailing bytes after 10= can smuggle a second message past the frame carve."),
    "DATA_LEN_OVERRUN": _Rule(
        "SAFIX-TYPE-001", "TYPE", S, CH, "DATA field declared length overruns the message (over-read)",
        ["AV-TYPE-1", "AV-TYPE-3", "SV-TYPE-31"],
        ["A legitimately large honest-length payload is NOT this — only a length past the buffer is."],
        "Over-read past the buffer (C++ heap disclosure/SIGSEGV class). Reject on length>remaining."),
    "DATA_LEN_MISMATCH": _Rule(
        "SAFIX-TYPE-002", "TYPE", H, CH, "DATA field declared length disagrees with the field boundary",
        ["AV-TYPE-4", "AV-TYPE-1", "SV-TYPE-32"],
        ["Rare benign tooling quirk; inspect the unframed tail bytes in the finding."],
        "Length<actual leaks a re-parseable tail (field smuggling); length>actual absorbs fields."),
    "DATA_WITHOUT_LENGTH": _Rule(
        "SAFIX-TYPE-003", "TYPE", M, CM, "DATA field has no preceding length field (orphan)",
        ["AV-TYPE-8"], ["A custom/UDF data field the dictionary does not pair."],
        "Without a length prefix an embedded SOH desyncs the parse."),
    "DATA_LENGTH_NOT_NUMERIC": _Rule(
        "SAFIX-TYPE-004", "TYPE", H, CH, "DATA length field is non-numeric",
        ["AV-TYPE-9", "SV-TYPE-33"], [], "A non-numeric length is a parser-fault/DoS primitive."),
    "DATA_LENGTH_NEGATIVE": _Rule(
        "SAFIX-TYPE-005", "TYPE", H, CH, "DATA length field is negative",
        ["AV-TYPE-2", "SV-TYPE-33"], [], "A negative length can underflow a length-prefixed read."),
    "NON_NUMERIC_TAG": _Rule(
        "SAFIX-STRUCT-001", "STRUCT", M, CM, "Field has a non-numeric tag",
        ["AV-TYPE-31", "AV-STRUCT-04"], ["Corrupted/garbled capture."],
        "A non-numeric tag indicates corruption or an injection attempt."),
    "LEADING_ZERO_TAG": _Rule(
        "SAFIX-STRUCT-002", "STRUCT", L, CM, "Tag has a leading zero (alias risk, e.g. 007 == 7)",
        ["AV-TYPE-31", "SV-TYPE-1"],
        ["Both engines accept leading-zero tags; advisory unless it aliases a present tag."],
        "Leading-zero tags can alias a real tag and pollute parameters."),
    "EMPTY_VALUE": _Rule(
        "SAFIX-STRUCT-003", "STRUCT", L, CM, "Field has an empty value",
        ["SV-ENC-3"], ["Some venues send empty optional fields."],
        "Empty values can bypass ValidateFieldsHaveValues=N parsing."),
    "DUPLICATE_STRUCTURAL_TAG": _Rule(
        "SAFIX-STRUCT-004", "STRUCT", H, CH, "A structural tag (8/9/35/10) appears more than once",
        ["AV-STRUCT-06", "SV-STRUCT-24"],
        ["Virtually never benign for structural tags."],
        "Duplicate structural tags cause first/last-wins parser divergence (parameter pollution)."),
    "MALFORMED_FIELD_NO_EQUALS": _Rule(
        "SAFIX-STRUCT-005", "STRUCT", M, CM, "Token without a '=' separator",
        ["AV-STRUCT-04", "AV-TYPE-7"], ["Corrupted capture, or embedded SOH in a non-DATA value."],
        "A token without '=' indicates corruption or SOH smuggling in a value."),
    "NO_FINAL_DELIMITER": _Rule(
        "SAFIX-STRUCT-006", "STRUCT", L, CL, "Field not terminated by a delimiter (truncated?)",
        ["AV-SESS-FRM-02"], ["End-of-file truncation of the last message."],
        "An unterminated final field suggests truncation."),
}


@register
class ParserAnomalyDetector(Detector):
    id = "parser-anomaly"
    category = "FRAMING"
    title = "Parser-level framing / byte-structure anomalies"

    def analyze(self, msg: "FixMessage", ctx: "ScanContext") -> None:
        delim = msg.field_delimiter
        for an in msg.all_anomalies:
            rule = _RULES.get(an.code)
            if rule is None:
                continue
            # category gating honours config (rule.category, not the detector's umbrella)
            if not ctx.config.rule_enabled(rule.rule_id, rule.category):
                continue
            evidence = _excerpt(msg.raw, an.byte_offset, delim) if an.byte_offset is not None else None
            ctx.add(
                Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    message=an.detail,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    category=rule.category,
                    vector_ids=list(rule.vector_ids),
                    tag=an.tag,
                    field_index=an.field_index,
                    byte_offset=an.byte_offset,
                    benign_notes=list(rule.benign),
                    remediation=rule.remediation,
                    evidence=evidence,
                    dedup_key=f"{an.code}:{an.tag}",
                ),
                msg,
            )


def _excerpt(raw: bytes, offset: int, delim: bytes, span: int = 40) -> str:
    start = max(0, offset - 10)
    chunk = raw[start:offset + span]
    return chunk.replace(delim, b"|").decode("latin-1", "replace")
