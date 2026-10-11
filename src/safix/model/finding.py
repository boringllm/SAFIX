"""The SAFIX Finding — one raised alert, with triage metadata and SARIF mapping."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> float:
        """CVSS-like 0-10 numeric used for SARIF security-severity and ordering."""
        return {
            "critical": 9.5, "high": 8.0, "medium": 5.0, "low": 3.0, "info": 0.0,
        }[self.value]

    @property
    def sarif_level(self) -> str:
        return {
            "critical": "error", "high": "error", "medium": "warning",
            "low": "note", "info": "note",
        }[self.value]

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> float:
        return {"high": 1.0, "medium": 0.6, "low": 0.3}[self.value]


_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def severity_at_least(value: Severity, minimum: Severity) -> bool:
    return value.rank >= minimum.rank


@dataclass(slots=True)
class Finding:
    """A single raised alert."""

    rule_id: str
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    category: str = ""                       # SESS | TYPE | STRUCT | APP | ENC | FRAMING
    vector_ids: list[str] = field(default_factory=list)
    # provenance
    source: Optional[str] = None
    source_line: Optional[int] = None
    msg_offset: int = 0
    byte_offset: Optional[int] = None
    tag: Optional[int] = None
    field_index: Optional[int] = None
    # session / message context
    session: Optional[str] = None
    msg_seq: Optional[int] = None
    msg_type: Optional[str] = None
    direction: str = "unknown"
    timestamp: Optional[str] = None          # recovered log timestamp of the message
    # triage metadata
    benign_notes: list[str] = field(default_factory=list)
    remediation: Optional[str] = None
    regulatory_refs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    evidence: Optional[str] = None           # short raw excerpt pointing at the issue
    # dedup / suppression
    dedup_key: Optional[str] = None          # detector-supplied salient key; falls back below
    suppressed: bool = False
    suppressed_by: Optional[str] = None
    occurrence_count: int = 1

    @property
    def priority(self) -> int:
        """0-100 triage priority = severity score x confidence weight x 10."""
        return round(self.severity.score * self.confidence.weight * 10)

    @property
    def fingerprint(self) -> str:
        key = self.dedup_key or f"{self.msg_type}:{self.tag}:{self.byte_offset}"
        basis = f"{self.rule_id}|{self.session or ''}|{key}"
        return hashlib.sha1(basis.encode("utf-8", "replace")).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "priority": self.priority,
            "category": self.category,
            "vector_ids": self.vector_ids,
            "session": self.session,
            "msg_seq": self.msg_seq,
            "msg_type": self.msg_type,
            "direction": self.direction,
            "timestamp": self.timestamp,
            "source": self.source,
            "source_line": self.source_line,
            "msg_offset": self.msg_offset,
            "byte_offset": self.byte_offset,
            "tag": self.tag,
            "field_index": self.field_index,
            "evidence": self.evidence,
            "benign_notes": self.benign_notes,
            "remediation": self.remediation,
            "regulatory_refs": self.regulatory_refs,
            "tags": self.tags,
            "suppressed": self.suppressed,
            "suppressed_by": self.suppressed_by,
            "occurrence_count": self.occurrence_count,
            "fingerprint": self.fingerprint,
        }
