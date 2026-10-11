"""TYPE detectors — datatype grammar, enum, magnitude, calendar, and MonthYear-defect checks.

Stateless / single-message. Uses the loaded dictionary to know each field's datatype and enum
code-set, then applies :mod:`safix.dictionary.datatypes`. ``enforced-free`` violations (types the
engines never check) are emitted as medium-confidence advisories; hard grammar violations are
higher confidence.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from ..dictionary import datatypes as dt
from ..model.finding import Confidence, Finding, Severity
from .base import Detector, register

if TYPE_CHECKING:  # pragma: no cover
    from ..dictionary.spec import FixSpec
    from ..engine.context import ScanContext
    from ..model.message import FixMessage, RawField

S, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
CH, CM, CL = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW

# security-relevant enum/boolean fields → elevate severity when invalid
_CORE_SESSION_TAGS = {35, 98, 54, 40, 43, 141, 123, 97, 25, 150, 434, 4}

# vector IDs per datatype kind
_KIND_VECTORS = {
    "int": ["AV-TYPE-12", "SV-TYPE-2"],
    "count": ["AV-TYPE-13", "SV-TYPE-4", "SV-TYPE-5"],
    "decimal": ["AV-TYPE-15", "SV-TYPE-7", "SV-TYPE-8"],
    "char": ["AV-TYPE-16", "SV-TYPE-26"],
    "plain": ["AV-TYPE-28"],
    "string": ["AV-TYPE-29"],
    "date": ["AV-TYPE-21", "SV-TYPE-13"],
    "datetime": ["AV-TYPE-18", "SV-TYPE-13", "SV-TYPE-14"],
    "monthyear": ["AV-TYPE-22", "SV-TYPE-21", "SV-TYPE-22"],
}
_ENFORCED_FREE_VECTORS = ["AV-TYPE-23", "AV-TYPE-24", "AV-TYPE-25", "SV-TYPE-18",
                          "SV-TYPE-23", "SV-TYPE-24", "SV-TYPE-25"]

_SPECIAL_DECIMAL = {b"nan", b"inf", b"-inf", b"+inf", b"infinity", b"-infinity"}


@register
class DatatypeDetector(Detector):
    id = "datatype"
    category = "TYPE"
    title = "FIX datatype grammar, enum, magnitude and calendar validation"

    def analyze(self, msg: "FixMessage", ctx: "ScanContext") -> None:
        spec = ctx.spec_for(msg)
        if spec is None:
            return
        thr = ctx.config.thresholds
        for fld in msg.fields:
            if fld.tag is None:
                continue
            dfield = spec.fields_by_number.get(fld.tag)
            if dfield is None:
                continue  # unknown tag handled by the STRUCT detector
            self._check_field(msg, ctx, spec, fld, dfield.type, thr)

    def _check_field(self, msg, ctx, spec: "FixSpec", fld: "RawField",
                     type_name: str, thr) -> None:
        res = dt.validate(type_name, fld.value)
        tag = fld.tag
        ev = f"{tag}={fld.value_str[:60]}"

        # NaN / Inf in a decimal field (risk-check bypass) — High
        if res.kind == "decimal" and fld.value.lower() in _SPECIAL_DECIMAL:
            self._emit(ctx, msg, "SAFIX-TYPE-014", H, CH, "TYPE",
                       f"{type_name} field carries a non-finite value ({fld.value_str})",
                       ["AV-TYPE-15"], fld, ev,
                       benign=[], remediation="NaN/Inf defeat comparison-based risk checks; reject.")
            return

        if res.lexical_ok is False:
            if res.kind == "string":
                self._emit(ctx, msg, "SAFIX-TYPE-021", H, CH, "TYPE",
                           f"STRING field {tag} contains control characters (injection risk)",
                           ["AV-TYPE-29"], fld, ev,
                           benign=["Multibyte UTF-8 names are legitimate; this targets C0/C1 controls."],
                           remediation="Strip/reject NUL/ESC/CR/LF/BS/DEL before logging or display.")
            elif res.enforced_free:
                self._emit(ctx, msg, "SAFIX-TYPE-016", M, CM, "TYPE",
                           f"{type_name} value is off the declared shape (engine does not enforce it)",
                           list(_ENFORCED_FREE_VECTORS), fld, ev,
                           benign=["These types are enforced-free; venues carry locale/venue values.",
                                   "Reserved placeholders (e.g. currency XXX) are legitimate."],
                           remediation=f"Validate {type_name} shape (and ISO/MIC allow-list) at the app layer.")
            else:
                sev = H if tag in _CORE_SESSION_TAGS else M
                self._emit(ctx, msg, "SAFIX-TYPE-010", sev, CH, "TYPE",
                           f"{type_name} field {tag} violates its datatype grammar",
                           list(_KIND_VECTORS.get(res.kind, [])), fld, ev,
                           benign=["Leading-zero integers are accepted by engines (advisory only)."],
                           remediation="Reject with SessionRejectReason(373)=6 (incorrect data format).")

        # zero / sub-one count (SEQNUM, NUMINGROUP, LENGTH prose require >= 1)
        if res.kind == "count" and res.lexical_ok and fld.value.isdigit() and int(fld.value) < 1:
            self._emit(ctx, msg, "SAFIX-TYPE-017", M, CM, "TYPE",
                       f"{type_name} field {tag} is {int(fld.value)} (must be >= 1)",
                       ["AV-TYPE-13", "SV-TYPE-4"], fld, ev,
                       benign=["A few engines tolerate a zero count for an absent group."],
                       remediation="Reject zero/negative SEQNUM/NUMINGROUP/LENGTH values.")

        # impossible calendar date (lexically valid but Feb-31 etc.)
        if res.calendar_ok is False:
            self._emit(ctx, msg, "SAFIX-TYPE-011", M, CH, "TYPE",
                       f"{type_name} field {tag} is a calendar-impossible date",
                       ["SV-TYPE-13"], fld, ev,
                       benign=["Lenient engines silently coerce the date — audit-trail corruption."],
                       remediation="Add a calendar post-check (days-in-month incl. leap year).")

        # integer width / magnitude differential
        if res.magnitude_class == "int32_overflow" and res.kind == "count":
            self._emit(ctx, msg, "SAFIX-TYPE-012", M, CM, "TYPE",
                       f"{type_name} field {tag} exceeds 2^31-1 (C++ u64 vs Java i32 divergence)",
                       ["AV-TYPE-13", "SV-TYPE-4"], fld, ev,
                       benign=["Very large but legitimate counts are rare but possible."],
                       remediation="Normalize integer width handling across engines.")
        elif res.magnitude_class == "int64_overflow":
            self._emit(ctx, msg, "SAFIX-TYPE-012", H, CH, "TYPE",
                       f"{type_name} field {tag} exceeds 2^63-1 (overflow / allocation-bomb class)",
                       ["SV-TYPE-5"], fld, ev, benign=[], remediation="Reject oversized integers.")

        # decimal precision advisory
        if res.significant_digits is not None and res.significant_digits > thr.decimal_significant_digits:
            self._emit(ctx, msg, "SAFIX-TYPE-013", L, CL, "TYPE",
                       f"{type_name} field {tag} has {res.significant_digits} significant digits "
                       f"(> {thr.decimal_significant_digits}; precision-loss)",
                       ["SV-TYPE-9"], fld, ev,
                       benign=["High-precision crypto venues legitimately exceed 15 digits."],
                       remediation="Advisory only; confirm downstream precision handling.")

        # MonthYear XSD regex defect (accepted by schema, forbidden by prose)
        if type_name.upper() == "MONTHYEAR" and dt.monthyear_regex_defect(fld.value):
            self._emit(ctx, msg, "SAFIX-TYPE-015", M, CM, "TYPE",
                       f"MonthYear field {tag} matches the defective XSD pattern but not the prose rule",
                       ["SV-TYPE-21", "SV-TYPE-22"], fld, ev,
                       benign=["Schema-driven validators accept this by design."],
                       remediation="Use the prose-strict MonthYear grammar (MM 01-12, DD 01-31, ww w1-w5).")

        # enum validation
        self._check_enum(ctx, msg, spec, fld, type_name, ev)

    def _check_enum(self, ctx, msg, spec: "FixSpec", fld: "RawField", type_name: str, ev: str) -> None:
        tag = fld.tag
        values = spec.enum_values(tag)
        if not values:
            return
        val = fld.value_str
        up = type_name.upper()
        if up in ("MULTIPLEVALUESTRING", "MULTIPLESTRINGVALUE", "MULTIPLECHARVALUE"):
            tokens = val.split(" ")
        else:
            tokens = [val]
        bad = [t for t in tokens if t and t not in values]
        if not bad:
            return
        sev = H if tag in _CORE_SESSION_TAGS else M
        conf = CM
        self._emit(ctx, msg, "SAFIX-TYPE-020", sev, conf, "TYPE",
                   f"{spec.field_name(tag) or tag}({tag}) value {bad!r} not in the dictionary code-set",
                   ["AV-TYPE-30", "AV-TYPE-33", "SV-TYPE-35"], fld, ev,
                   benign=["Venues with allowUnknownEnumValues / UDF ranges carry extensions.",
                           "User-defined tag ranges are expected to be non-standard."],
                   remediation="Validate enum membership; prioritize core session/routing enums.")

    def _emit(self, ctx, msg, rule_id, sev, conf, cat, message, vectors, fld, ev,
              *, benign, remediation) -> None:
        if not ctx.config.rule_enabled(rule_id, cat):
            return
        ctx.add(
            Finding(
                rule_id=rule_id, title=self._title_for(rule_id), message=message,
                severity=sev, confidence=conf, category=cat, vector_ids=list(vectors),
                tag=fld.tag, field_index=fld.index, byte_offset=fld.value_offset,
                benign_notes=list(benign), remediation=remediation, evidence=ev,
                dedup_key=f"{rule_id}:{fld.tag}",
            ),
            msg,
        )

    @staticmethod
    def _title_for(rule_id: str) -> str:
        return {
            "SAFIX-TYPE-010": "Datatype grammar violation",
            "SAFIX-TYPE-011": "Calendar-impossible date",
            "SAFIX-TYPE-012": "Integer magnitude / width overflow",
            "SAFIX-TYPE-013": "Decimal precision-loss (advisory)",
            "SAFIX-TYPE-014": "Non-finite value in decimal field",
            "SAFIX-TYPE-015": "MonthYear XSD-regex defect",
            "SAFIX-TYPE-016": "Enforced-free type off declared shape",
            "SAFIX-TYPE-017": "Zero/negative count field",
            "SAFIX-TYPE-020": "Enum value not in dictionary code-set",
            "SAFIX-TYPE-021": "Control characters in STRING field",
        }.get(rule_id, rule_id)
