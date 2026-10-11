"""FIX datatype grammar validators.

A byte-oriented validator for every FIX datatype, implementing the grammar table in
``docs/research/detection-TYPE-ENC.md`` §2. Regexes are anchored and applied to the raw value
bytes between ``=`` and the SOH. ``enforced-free`` types are those the QuickFIX engines never
actually check (CURRENCY, COUNTRY, EXCHANGE, LOCALMKTDATE, MONTHYEAR, TZ*, LANGUAGE, DAYOFMONTH,
XMLDATA, ...): for those the scanner is the only line of defence, so a violation is an advisory.

The module returns *facts* (which rule failed, magnitude class, calendar validity). The TYPE
detector maps those facts to findings with severity/confidence/vector IDs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

MAX_INT32 = 2**31 - 1
MAX_INT64 = 2**63 - 1

# --- compiled grammar patterns (byte regexes) ----------------------------------------------
_P = {
    "INT": re.compile(rb"^-?[0-9]+$"),
    "LENGTH": re.compile(rb"^[0-9]+$"),
    "TAGNUM": re.compile(rb"^[1-9][0-9]*$"),
    "SEQNUM": re.compile(rb"^[0-9]+$"),
    "NUMINGROUP": re.compile(rb"^[0-9]+$"),
    "DECIMAL": re.compile(rb"^-?(?:[0-9]+\.?[0-9]*|\.[0-9]+)$"),
    "CHAR": re.compile(rb"(?s)^.$"),
    "BOOLEAN": re.compile(rb"^[YN]$"),
    "STRING": re.compile(rb"^[^\x00-\x08\x0A-\x1F\x7F]*$"),
    "MULTIPLECHARVALUE": re.compile(rb"^[A-Za-z0-9]( [A-Za-z0-9])*$"),
    "MULTIPLEVALUESTRING": re.compile(rb"^\S+( \S+)*$"),
    "UTCTIMESTAMP": re.compile(
        rb"^\d{4}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])-([01]\d|2[0-3]):[0-5]\d:([0-5]\d|60)"
        rb"(\.\d{3}|\.\d{6}|\.\d{9}|\.\d{12})?$"),
    "UTCTIMEONLY": re.compile(
        rb"^([01]\d|2[0-3]):[0-5]\d:([0-5]\d|60)(\.\d{3}|\.\d{6}|\.\d{9}|\.\d{12})?$"),
    "UTCDATEONLY": re.compile(rb"^\d{4}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])$"),
    "MONTHYEAR": re.compile(rb"^\d{4}(0[1-9]|1[0-2])((0[1-9]|[12]\d|3[01])|w[1-5])?$"),
    "MONTHYEAR_XSD": re.compile(rb"^\d{4}(0|1)\d([0-3wW]\d)?$"),  # the *defective* XSD pattern
    "CURRENCY": re.compile(rb"^[A-Z]{3}$"),
    "COUNTRY": re.compile(rb"^[A-Z]{2}$"),
    "EXCHANGE": re.compile(rb"^[A-Z0-9]{4}$"),
    "LANGUAGE": re.compile(rb"^[a-z]{2}$"),
    "DAYOFMONTH": re.compile(rb"^([1-9]|[12]\d|3[01])$"),
    "TENOR": re.compile(rb"^[DMWY][0-9]+$"),
    "TZTIMESTAMP": re.compile(
        rb"^\d{4}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])-([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d+)?"
        rb"(Z|[+-](0[1-9]|1[0-2])(:[0-5]\d)?)$"),
    "TZTIMEONLY": re.compile(
        rb"^([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?(Z|[+-](0[1-9]|1[0-2])(:[0-5]\d)?)$"),
}

# dictionary type-name  ->  (pattern key, kind, enforced_free)
# kind drives the secondary (magnitude/calendar) checks.
_TYPE_MAP: dict[str, tuple[str, str, bool]] = {
    "INT": ("INT", "int", False),
    "LENGTH": ("LENGTH", "count", False),
    "TAGNUM": ("TAGNUM", "int", False),
    "SEQNUM": ("SEQNUM", "count", False),
    "NUMINGROUP": ("NUMINGROUP", "count", False),
    "DAYOFMONTH": ("DAYOFMONTH", "plain", True),
    "FLOAT": ("DECIMAL", "decimal", False),
    "QTY": ("DECIMAL", "decimal", False),
    "QUANTITY": ("DECIMAL", "decimal", False),
    "PRICE": ("DECIMAL", "decimal", False),
    "PRICEOFFSET": ("DECIMAL", "decimal", False),
    "AMT": ("DECIMAL", "decimal", False),
    "PERCENTAGE": ("DECIMAL", "decimal", False),
    "CHAR": ("CHAR", "char", False),
    "BOOLEAN": ("BOOLEAN", "plain", False),
    "STRING": ("STRING", "string", False),
    "MULTIPLECHARVALUE": ("MULTIPLECHARVALUE", "plain", False),
    "MULTIPLEVALUESTRING": ("MULTIPLEVALUESTRING", "plain", True),
    "MULTIPLESTRINGVALUE": ("MULTIPLEVALUESTRING", "plain", True),
    "UTCTIMESTAMP": ("UTCTIMESTAMP", "datetime", False),
    "UTCTIMEONLY": ("UTCTIMEONLY", "plain", False),
    "UTCDATEONLY": ("UTCDATEONLY", "date", False),
    "UTCDATE": ("UTCDATEONLY", "date", False),
    "LOCALMKTDATE": ("UTCDATEONLY", "date", True),
    "LOCALMKTTIME": ("UTCTIMEONLY", "plain", True),
    "MONTHYEAR": ("MONTHYEAR", "monthyear", True),
    "CURRENCY": ("CURRENCY", "plain", True),
    "COUNTRY": ("COUNTRY", "plain", True),
    "EXCHANGE": ("EXCHANGE", "plain", True),
    "LANGUAGE": ("LANGUAGE", "plain", True),
    "TENOR": ("TENOR", "plain", False),
    "TZTIMESTAMP": ("TZTIMESTAMP", "plain", True),
    "TZTIMEONLY": ("TZTIMEONLY", "plain", True),
    # DATA / XMLDATA have no lexical grammar (handled by the Len/Data algorithm + XML scan)
    "DATA": (None, "data", True),
    "XMLDATA": (None, "xmldata", True),
}

# Types with no validator: treat as free STRING-like (no lexical finding) to avoid false alarms.
_UNKNOWN_KIND = "unknown"

_DAYS_IN_MONTH = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


@dataclass(slots=True)
class TypeResult:
    type_name: str
    kind: str
    enforced_free: bool
    lexical_ok: Optional[bool]          # None = no grammar for this type
    calendar_ok: Optional[bool] = None  # for date/datetime kinds
    magnitude_class: Optional[str] = None  # int32_overflow | int64_overflow | huge
    significant_digits: Optional[int] = None
    detail: Optional[str] = None

    @property
    def is_violation(self) -> bool:
        return self.lexical_ok is False or self.calendar_ok is False


def is_leap(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def calendar_date_ok(date8: bytes) -> bool:
    """Validate a YYYYMMDD byte string as a real calendar date."""
    if len(date8) != 8 or not date8.isdigit():
        return False
    y, m, d = int(date8[0:4]), int(date8[4:6]), int(date8[6:8])
    if y < 1:  # year 0000 is never a valid timestamp
        return False
    if not (1 <= m <= 12):
        return False
    dim = _DAYS_IN_MONTH[m - 1]
    if m == 2 and is_leap(y):
        dim = 29
    return 1 <= d <= dim


def significant_digits(value: bytes) -> int:
    s = value.lstrip(b"-").replace(b".", b"").lstrip(b"0")
    return len(s)


def _magnitude_class(value: bytes) -> Optional[str]:
    try:
        n = abs(int(value))
    except ValueError:
        return None
    if n > MAX_INT64:
        return "int64_overflow"
    if n > MAX_INT32:
        return "int32_overflow"
    return None


def validate(type_name: str, value: bytes) -> TypeResult:
    """Validate ``value`` against the named FIX datatype. Never raises."""
    key = (type_name or "").upper()
    entry = _TYPE_MAP.get(key)
    if entry is None:
        return TypeResult(type_name=type_name, kind=_UNKNOWN_KIND, enforced_free=False,
                          lexical_ok=None)
    pattern_key, kind, enforced_free = entry
    res = TypeResult(type_name=type_name, kind=kind, enforced_free=enforced_free, lexical_ok=None)

    if pattern_key is not None:
        res.lexical_ok = bool(_P[pattern_key].match(value))

    # secondary checks
    if kind in ("int", "count"):
        res.magnitude_class = _magnitude_class(value)
        if kind == "count" and res.lexical_ok and value.isdigit() and int(value) < 1:
            # LENGTH/SEQNUM/NUMINGROUP prose requires >= 1 (soft)
            res.detail = "value < 1 (prose requires positive)"
    elif kind == "decimal":
        if res.lexical_ok:
            res.significant_digits = significant_digits(value)
    elif kind == "date":
        if res.lexical_ok:
            res.calendar_ok = calendar_date_ok(value)
    elif kind == "datetime":
        if res.lexical_ok:
            res.calendar_ok = calendar_date_ok(value[:8])

    return res


def monthyear_regex_defect(value: bytes) -> bool:
    """True if ``value`` matches the defective XSD MonthYear regex but not the prose-strict one.

    This surfaces SV-TYPE-21/22: values a schema-driven validator accepts but the prose forbids.
    """
    return bool(_P["MONTHYEAR_XSD"].match(value)) and not bool(_P["MONTHYEAR"].match(value))


def known_type(type_name: str) -> bool:
    return (type_name or "").upper() in _TYPE_MAP
