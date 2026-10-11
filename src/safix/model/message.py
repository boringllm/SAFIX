"""The normalized, security-preserving FIX message model.

Design rule: **never normalize away an anomaly.** The model preserves field order, duplicate
tags, raw bytes and byte offsets exactly as they appeared, so a detector can point at the
precise malicious bytes. Core access is dictionary-free (works on arbitrary garbage); an
optional dictionary-aware pass attaches a repeating-group tree later.
"""

from __future__ import annotations

from dataclasses import dataclass, field as _field
from typing import Iterator, Literal, Optional

Direction = Literal["in", "out", "unknown"]
AnomalySeverity = Literal["info", "warn", "error"]

# --- well-known structural tags -------------------------------------------------------------
TAG_BEGIN_STRING = 8
TAG_BODY_LENGTH = 9
TAG_MSG_TYPE = 35
TAG_MSG_SEQ_NUM = 34
TAG_SENDER_COMP_ID = 49
TAG_TARGET_COMP_ID = 56
TAG_SENDING_TIME = 52
TAG_CHECKSUM = 10


def _to_latin1(b: bytes) -> str:
    """Decode bytes for display; latin-1 round-trips every byte (lossless)."""
    return b.decode("latin-1")


@dataclass(slots=True)
class Anomaly:
    """A structural/parse-level problem recorded (never raised) during parsing.

    Anomalies are evidence: the framing/structure detectors promote the security-relevant
    ones into Findings. ``code`` is a stable machine token (e.g. ``BODYLENGTH_MISMATCH``).
    """

    code: str
    severity: AnomalySeverity
    detail: str
    field_index: Optional[int] = None
    tag: Optional[int] = None
    byte_offset: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "detail": self.detail,
            "field_index": self.field_index,
            "tag": self.tag,
            "byte_offset": self.byte_offset,
        }


@dataclass(slots=True)
class RawField:
    """One ``tag=value`` field, exactly as seen on the wire."""

    index: int                  # 0-based ordinal within the message
    tag_bytes: bytes            # raw tag token before '=' (e.g. b"35", or b"3x5" if malformed)
    tag: Optional[int]          # parsed int tag, or None if non-numeric
    value: bytes                # raw value bytes (may contain SOH for DATA fields)
    raw: bytes                  # exact b"tag=value" slice as it appeared
    tag_offset: int             # byte offset of the tag within the message
    value_offset: int           # byte offset of the value within the message
    end_offset: int             # offset just past the terminating delimiter
    is_data_value: bool = False  # read as a length-prefixed DATA value
    anomalies: list[Anomaly] = _field(default_factory=list)

    @property
    def tag_str(self) -> str:
        return _to_latin1(self.tag_bytes)

    @property
    def value_str(self) -> str:
        return _to_latin1(self.value)

    @property
    def is_numeric_tag(self) -> bool:
        return self.tag is not None

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        v = self.value_str
        if len(v) > 40:
            v = v[:37] + "..."
        return f"RawField(#{self.index} {self.tag_str}={v!r})"


@dataclass(slots=True)
class FixMessage:
    """A parsed FIX message with full provenance and framing re-computation."""

    fields: list[RawField]
    raw: bytes
    field_delimiter: bytes = b"\x01"
    msg_offset: int = 0
    source: Optional[str] = None          # file path / origin label
    source_line: Optional[int] = None
    timestamp: Optional[str] = None       # recovered log timestamp (as text)
    direction: Direction = "unknown"
    anomalies: list[Anomaly] = _field(default_factory=list)

    # framing re-computation (filled by the parser)
    body_length_declared: Optional[int] = None
    body_length_computed: Optional[int] = None
    checksum_declared: Optional[bytes] = None
    checksum_computed: Optional[int] = None

    # optional, dictionary-aware
    groups: object | None = None

    # --- accessors (dictionary-free, duplicate-aware) --------------------------------------
    def get_field(self, tag: int, nth: int = 1) -> Optional[RawField]:
        """Return the nth (1-based) field with ``tag``, or None."""
        seen = 0
        for f in self.fields:
            if f.tag == tag:
                seen += 1
                if seen == nth:
                    return f
        return None

    def get_fields(self, tag: int) -> list[RawField]:
        return [f for f in self.fields if f.tag == tag]

    def get(self, tag: int, nth: int = 1) -> Optional[bytes]:
        f = self.get_field(tag, nth)
        return None if f is None else f.value

    def get_str(self, tag: int, nth: int = 1) -> Optional[str]:
        v = self.get(tag, nth)
        return None if v is None else _to_latin1(v)

    def get_int(self, tag: int, nth: int = 1) -> Optional[int]:
        v = self.get(tag, nth)
        if v is None:
            return None
        try:
            return int(v)
        except ValueError:
            return None

    def get_all(self, tag: int) -> list[bytes]:
        return [f.value for f in self.fields if f.tag == tag]

    def has(self, tag: int) -> bool:
        return any(f.tag == tag for f in self.fields)

    def count(self, tag: int) -> int:
        return sum(1 for f in self.fields if f.tag == tag)

    def __iter__(self) -> Iterator[RawField]:
        return iter(self.fields)

    def __len__(self) -> int:
        return len(self.fields)

    # --- common header conveniences --------------------------------------------------------
    @property
    def begin_string(self) -> Optional[str]:
        return self.get_str(TAG_BEGIN_STRING)

    @property
    def msg_type(self) -> Optional[str]:
        return self.get_str(TAG_MSG_TYPE)

    @property
    def seq_num(self) -> Optional[int]:
        return self.get_int(TAG_MSG_SEQ_NUM)

    @property
    def sender_comp_id(self) -> Optional[str]:
        return self.get_str(TAG_SENDER_COMP_ID)

    @property
    def target_comp_id(self) -> Optional[str]:
        return self.get_str(TAG_TARGET_COMP_ID)

    @property
    def sending_time(self) -> Optional[str]:
        return self.get_str(TAG_SENDING_TIME)

    @property
    def all_anomalies(self) -> list[Anomaly]:
        out = list(self.anomalies)
        for f in self.fields:
            out.extend(f.anomalies)
        return out

    @property
    def body_length_ok(self) -> Optional[bool]:
        if self.body_length_declared is None or self.body_length_computed is None:
            return None
        return self.body_length_declared == self.body_length_computed

    @property
    def checksum_ok(self) -> Optional[bool]:
        if self.checksum_declared is None or self.checksum_computed is None:
            return None
        try:
            return int(self.checksum_declared) == self.checksum_computed
        except ValueError:
            return False

    def pretty(self, delimiter: str = "|") -> str:
        """Human-readable rendering with a printable delimiter."""
        return delimiter.join(f"{f.tag_str}={f.value_str}" for f in self.fields)

    def to_dict(self) -> dict:
        return {
            "msg_type": self.msg_type,
            "begin_string": self.begin_string,
            "seq_num": self.seq_num,
            "sender": self.sender_comp_id,
            "target": self.target_comp_id,
            "direction": self.direction,
            "timestamp": self.timestamp,
            "source": self.source,
            "source_line": self.source_line,
            "msg_offset": self.msg_offset,
            "field_count": len(self.fields),
            "body_length_declared": self.body_length_declared,
            "body_length_computed": self.body_length_computed,
            "checksum_declared": (
                _to_latin1(self.checksum_declared) if self.checksum_declared is not None else None
            ),
            "checksum_computed": self.checksum_computed,
            "anomalies": [a.to_dict() for a in self.all_anomalies],
        }

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"FixMessage(type={self.msg_type!r} seq={self.seq_num} "
            f"{self.sender_comp_id}->{self.target_comp_id} fields={len(self.fields)} "
            f"anomalies={len(self.all_anomalies)})"
        )
