"""ENC detectors — XML attack-signature scan of XML-bearing field values.

Stateless / single-message. QuickFIX/J do not parse inbound FIXML on the wire, so these are a
**downstream-consumer** concern (an FpML/FIXML/risk system that parses the bytes): the scanner
asserts the signature is present, not that it is exploited (hence medium confidence for most).
The datatype of XmlData/SecurityXML/EncodedText is unrestricted, so the scanner is the only guard.

Covers AV-ENC-1..10, SV-ENC-8..11, SV-TYPE-34.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ..model.finding import Confidence, Finding, Severity
from .base import Detector, register

if TYPE_CHECKING:  # pragma: no cover
    from ..engine.context import ScanContext
    from ..model.message import FixMessage, RawField

H, M, L = Severity.HIGH, Severity.MEDIUM, Severity.LOW
CH, CM, CL = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW

_DOCTYPE = re.compile(rb"<!DOCTYPE", re.I)
_ENTITY = re.compile(rb"<!ENTITY", re.I)
_PARAM_ENTITY = re.compile(rb"<!ENTITY\s+%", re.I)
_SYSTEM = re.compile(rb"\b(SYSTEM|PUBLIC)\b")
_XINCLUDE = re.compile(rb"<xi:include|www\.w3\.org/2001/XInclude", re.I)
_SCHEMALOC = re.compile(rb"xsi:schemaLocation|noNamespaceSchemaLocation", re.I)
_EXTERNAL = re.compile(rb"file://|https?://|ftp://|jar:|netdoc:|169\.254\.169\.254", re.I)
_CDATA = re.compile(rb"<!\[CDATA\[(.*?)\]\]>", re.S)
_ENTITY_REF = re.compile(rb"&[A-Za-z_][\w.\-]*;")
_NESTED_ENTITY = re.compile(rb'<!ENTITY\s+\S+\s+"[^"]*&\w+;', re.I | re.S)  # entity defined via other entities
_ENC_DECL = re.compile(rb'encoding\s*=\s*["\'](UTF-7|UTF-16)', re.I)
_BOMS = (b"\xff\xfe", b"\xfe\xff", b"\x2b\x2f\x76")  # UTF-16 LE/BE, UTF-7
_CONTROL = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _max_depth(value: bytes) -> int:
    depth = cur = 0
    for m in re.finditer(rb"<(/?)([!?]?)", value):
        slash, special = m.group(1), m.group(2)
        if special:  # <!..  or <?..  — declarations, not nesting
            continue
        if slash:
            cur = max(0, cur - 1)
        else:
            cur += 1
            depth = max(depth, cur)
    return depth


@register
class EncodingDetector(Detector):
    id = "encoding"
    category = "ENC"
    title = "XML attack signatures (XXE / entity-expansion / XInclude / CDATA) in field values"

    _BENIGN_XML = ["SecurityXML/FpML fields legitimately carry XML, but a well-formed payload has "
                   "no DOCTYPE/ENTITY/SYSTEM/file:// — those remain anomalous."]

    def analyze(self, msg: "FixMessage", ctx: "ScanContext") -> None:
        thr = ctx.config.thresholds
        for fld in msg.fields:
            v = fld.value
            if b"<" not in v and not v.startswith(_BOMS):
                continue
            self._scan_field(msg, ctx, fld, v, thr)

    def _scan_field(self, msg, ctx, fld: "RawField", v: bytes, thr) -> None:
        has_doctype = bool(_DOCTYPE.search(v))
        has_entity = bool(_ENTITY.search(v))
        has_external = bool(_EXTERNAL.search(v))

        # clear XXE: DOCTYPE/ENTITY with SYSTEM/PUBLIC or an external resource
        if (has_doctype or has_entity) and (_SYSTEM.search(v) or has_external):
            self._emit(msg, ctx, fld, "SAFIX-ENC-001", H, CH,
                       "External-entity XXE signature in a field value",
                       "field carries a DOCTYPE/ENTITY referencing an external resource (XXE/SSRF)",
                       ["AV-ENC-01", "AV-ENC-02", "SV-ENC-8"], self._BENIGN_XML,
                       "Disable DTD/external-entity resolution in every downstream XML parser.")
        if _PARAM_ENTITY.search(v):
            self._emit(msg, ctx, fld, "SAFIX-ENC-002", H, CM,
                       "Parameter-entity (blind XXE) signature",
                       "field defines a parameter entity (<!ENTITY %) — blind/OOB XXE primitive",
                       ["AV-ENC-04", "SV-ENC-9"], self._BENIGN_XML,
                       "Forbid parameter entities; disable external DTD loading.")

        # entity-expansion / billion-laughs: many refs OR a nested entity definition
        refs = len(_ENTITY_REF.findall(v))
        nested = bool(_NESTED_ENTITY.search(v))
        if has_entity and (refs >= thr.xml_entity_ref_threshold or nested):
            why = ("a nested entity definition (entity defined via other entities)" if nested
                   else f"{refs} entity references (>= {thr.xml_entity_ref_threshold})")
            self._emit(msg, ctx, fld, "SAFIX-ENC-003", H, CM,
                       "Entity-expansion / billion-laughs signature",
                       f"field defines entities and contains {why} — expansion DoS",
                       ["AV-ENC-03", "AV-ENC-06"], ["Some legitimate documents use many entities."],
                       "Cap entity expansion and nesting in the XML parser.")

        if _XINCLUDE.search(v):
            self._emit(msg, ctx, fld, "SAFIX-ENC-004", H, CM,
                       "XInclude signature (bypasses DOCTYPE defenses)",
                       "field uses XInclude to pull in external content",
                       ["AV-ENC-05"], self._BENIGN_XML,
                       "Disable XInclude processing in the XML parser.")

        if _SCHEMALOC.search(v) and has_external:
            self._emit(msg, ctx, fld, "SAFIX-ENC-005", M, CM,
                       "schemaLocation pointing off-host (schema poisoning/SSRF)",
                       "field pins an external schemaLocation",
                       ["AV-ENC-09", "SV-ENC-10"], self._BENIGN_XML,
                       "Pin schemas locally; ignore in-document schemaLocation.")

        # CDATA carrying control bytes or an embedded tag=value frame
        for m in _CDATA.finditer(v):
            inner = m.group(1)
            if _CONTROL.search(inner) or b"\x01" in inner or re.search(rb"\d+=.+\x01", inner):
                self._emit(msg, ctx, fld, "SAFIX-ENC-006", M, CM,
                           "CDATA smuggling (control bytes / embedded frame)",
                           "a CDATA section carries control bytes or an embedded tag=value run",
                           ["AV-ENC-10"], ["Benign CDATA is common; only control/frame content flags."],
                           "Treat CDATA content as untrusted; strip control bytes.")
                break

        # deep nesting (stack exhaustion)
        if v.count(b"<") >= thr.xml_nesting_depth_threshold:
            depth = _max_depth(v)
            if depth >= thr.xml_nesting_depth_threshold:
                self._emit(msg, ctx, fld, "SAFIX-ENC-007", M, CL,
                           "Deeply-nested XML (stack-exhaustion DoS)",
                           f"XML nesting depth {depth} >= {thr.xml_nesting_depth_threshold}",
                           ["AV-ENC-07", "SV-ENC-11"], ["Deep but legitimate documents exist."],
                           "Bound XML nesting depth in the parser.")

        # BOM / UTF-7/16 encoding smuggling (filter-bypass primitive)
        if v.startswith(_BOMS) or _ENC_DECL.search(v):
            self._emit(msg, ctx, fld, "SAFIX-ENC-008", L, CL,
                       "UTF-7/16 BOM or encoding declaration (filter-bypass primitive)",
                       "field carries a UTF-16/UTF-7 BOM or encoding declaration",
                       ["AV-ENC-08"], ["Many systems legitimately use UTF-16 — high false-positive rate."],
                       "Normalize to UTF-8 before signature filtering.")

    def _emit(self, msg, ctx, fld, rule_id, sev, conf, title, message, vectors, benign,
              remediation) -> None:
        if not ctx.config.rule_enabled(rule_id, "ENC"):
            return
        ctx.add(
            Finding(
                rule_id=rule_id, title=title, message=message, severity=sev, confidence=conf,
                category="ENC", vector_ids=list(vectors), tag=fld.tag, field_index=fld.index,
                byte_offset=fld.value_offset, benign_notes=list(benign), remediation=remediation,
                evidence=f"{fld.tag}={fld.value_str[:80]}", dedup_key=f"{rule_id}:{fld.tag}",
            ),
            msg,
        )
