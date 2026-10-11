"""Lenient, byte-oriented FIX tokenizer.

``parse_message`` turns one message's bytes into a :class:`FixMessage`, preserving order,
duplicates, raw bytes and byte offsets. It **never raises** on malformed input — every problem
becomes a recorded :class:`Anomaly`. It is dictionary-free: repeating-group reconstruction and
datatype/enum validation happen in a later, dictionary-aware pass.

It handles length-prefixed DATA fields (whose values may contain the SOH delimiter) using the
``len_to_data``/``data_to_len`` tables, and re-computes BodyLength(9) and CheckSum(10) so the
framing detectors can compare declared vs. actual.
"""

from __future__ import annotations

from typing import Optional

from ..model.message import (
    Anomaly,
    FixMessage,
    RawField,
    TAG_BODY_LENGTH,
    TAG_BEGIN_STRING,
    TAG_CHECKSUM,
    TAG_MSG_TYPE,
)
from .rawdata import DATA_TO_LEN, LEN_TO_DATA, SOH

_SINGLETON_STRUCTURAL_TAGS = (TAG_BEGIN_STRING, TAG_BODY_LENGTH, TAG_MSG_TYPE, TAG_CHECKSUM)


def _parse_tag(tag_bytes: bytes) -> Optional[int]:
    """Parse a tag token to int, or None if it is not a plain non-negative integer."""
    if not tag_bytes or not tag_bytes.isdigit():
        return None
    try:
        return int(tag_bytes)
    except ValueError:  # pragma: no cover - isdigit already guards
        return None


def parse_message(
    raw: bytes,
    *,
    field_delimiter: bytes = SOH,
    len_to_data: dict[int, int] = LEN_TO_DATA,
    data_to_len: dict[int, int] = DATA_TO_LEN,
    msg_offset: int = 0,
    source: Optional[str] = None,
    source_line: Optional[int] = None,
    timestamp: Optional[str] = None,
    direction: str = "unknown",
) -> FixMessage:
    """Tokenize one FIX message. Always returns a :class:`FixMessage`; never raises."""
    delim = field_delimiter
    dlen = len(delim)
    n = len(raw)
    fields: list[RawField] = []
    msg_anoms: list[Anomaly] = []
    pending_data_len: dict[int, int] = {}  # data_tag -> declared byte length
    i = 0
    index = 0

    while i < n:
        field_start = i
        eq = raw.find(b"=", i)
        if eq == -1:
            token_end = raw.find(delim, i)
            stop = n if token_end == -1 else token_end
            token = raw[i:stop]
            if token:
                msg_anoms.append(
                    Anomaly("MALFORMED_FIELD_NO_EQUALS", "error",
                            f"trailing token without '=': {token[:32]!r}",
                            field_index=index, byte_offset=i))
            if token_end == -1:
                break
            i = token_end + dlen
            continue

        # A delimiter before the '=' means a token with no '=' (e.g. embedded-SOH smuggling).
        d_before = raw.find(delim, i, eq)
        if d_before != -1:
            token = raw[i:d_before]
            if token:
                msg_anoms.append(
                    Anomaly("MALFORMED_FIELD_NO_EQUALS", "error",
                            f"token without '=': {token[:32]!r}",
                            field_index=index, byte_offset=i))
            i = d_before + dlen
            continue

        tag_bytes = raw[i:eq]
        tag = _parse_tag(tag_bytes)
        value_offset = eq + 1
        field_anoms: list[Anomaly] = []
        is_data = False

        if tag is None:
            field_anoms.append(
                Anomaly("NON_NUMERIC_TAG", "error", f"non-numeric tag {tag_bytes!r}",
                        field_index=index, byte_offset=i))
        elif len(tag_bytes) > 1 and tag_bytes[:1] == b"0":
            field_anoms.append(
                Anomaly("LEADING_ZERO_TAG", "warn",
                        f"tag has leading zero {tag_bytes!r} (aliases to {tag})",
                        field_index=index, tag=tag, byte_offset=i))

        declared_len = pending_data_len.pop(tag, None) if tag is not None else None

        if tag is not None and tag in data_to_len and declared_len is not None and declared_len >= 0:
            # length-prefixed DATA field: consume exactly declared_len bytes
            is_data = True
            vstart = value_offset
            vend = vstart + declared_len
            if vend > n:
                field_anoms.append(
                    Anomaly("DATA_LEN_OVERRUN", "error",
                            f"declared length {declared_len} for tag {tag} overruns message end "
                            f"by {vend - n} bytes",
                            field_index=index, tag=tag, byte_offset=vstart))
                value = raw[vstart:n]
                value_end = n
                i = n
            elif raw[vend:vend + dlen] == delim:
                value = raw[vstart:vend]
                value_end = vend
                i = vend + dlen
            else:
                # declared length does not land on a delimiter -> desync / smuggling
                nxt = raw.find(delim, vend)
                leaked = raw[vend:(n if nxt == -1 else nxt)]
                field_anoms.append(
                    Anomaly("DATA_LEN_MISMATCH", "error",
                            f"declared length {declared_len} for tag {tag} not followed by a "
                            f"delimiter; {len(leaked)} unframed byte(s) follow: {leaked[:32]!r}",
                            field_index=index, tag=tag, byte_offset=vend))
                value = raw[vstart:vend]
                value_end = vend
                i = n if nxt == -1 else nxt + dlen
        else:
            # normal field: scan to next delimiter
            d = raw.find(delim, value_offset)
            if d == -1:
                value = raw[value_offset:n]
                value_end = n
                i = n
                field_anoms.append(
                    Anomaly("NO_FINAL_DELIMITER", "warn",
                            "field not terminated by a delimiter (truncated message?)",
                            field_index=index, tag=tag, byte_offset=n))
            else:
                value = raw[value_offset:d]
                value_end = d
                i = d + dlen
            if tag is not None and not value:
                field_anoms.append(
                    Anomaly("EMPTY_VALUE", "warn", f"empty value for tag {tag}",
                            field_index=index, tag=tag, byte_offset=value_offset))
            if tag is not None and tag in data_to_len and declared_len is None:
                field_anoms.append(
                    Anomaly("DATA_WITHOUT_LENGTH", "warn",
                            f"DATA field tag {tag} had no preceding length field; scanned to "
                            "delimiter (embedded SOH would desync)",
                            field_index=index, tag=tag, byte_offset=value_offset))

        rf = RawField(
            index=index,
            tag_bytes=tag_bytes,
            tag=tag,
            value=value,
            raw=raw[field_start:value_end],
            tag_offset=field_start,
            value_offset=value_offset,
            end_offset=i,
            is_data_value=is_data,
            anomalies=field_anoms,
        )
        fields.append(rf)

        # If this was a length field, remember the length for its DATA partner.
        if tag is not None and tag in len_to_data:
            try:
                L = int(value)
            except ValueError:
                rf.anomalies.append(
                    Anomaly("DATA_LENGTH_NOT_NUMERIC", "error",
                            f"length field tag {tag} has non-numeric value {value[:16]!r}",
                            field_index=index, tag=tag, byte_offset=value_offset))
            else:
                if L < 0:
                    rf.anomalies.append(
                        Anomaly("DATA_LENGTH_NEGATIVE", "error",
                                f"length field tag {tag} is negative ({L})",
                                field_index=index, tag=tag, byte_offset=value_offset))
                else:
                    pending_data_len[len_to_data[tag]] = L

        index += 1

    msg = FixMessage(
        fields=fields,
        raw=raw,
        field_delimiter=delim,
        msg_offset=msg_offset,
        source=source,
        source_line=source_line,
        timestamp=timestamp,
        direction=direction,  # type: ignore[arg-type]
        anomalies=msg_anoms,
    )
    _finalize_framing(msg, delim)
    return msg


def _finalize_framing(msg: FixMessage, delim: bytes) -> None:
    """Re-compute BodyLength and CheckSum and record message-level framing anomalies."""
    raw = msg.raw
    dlen = len(delim)
    fields = msg.fields

    # first field should be BeginString(8)
    if not fields or fields[0].tag != TAG_BEGIN_STRING:
        msg.anomalies.append(
            Anomaly("MISSING_OR_MISPLACED_BEGINSTRING", "error",
                    "message does not begin with BeginString(8)", byte_offset=0))

    bl = msg.get_field(TAG_BODY_LENGTH)
    cs = msg.get_field(TAG_CHECKSUM)

    if bl is not None:
        try:
            msg.body_length_declared = int(bl.value)
        except ValueError:
            msg.anomalies.append(
                Anomaly("BODYLENGTH_NOT_NUMERIC", "error",
                        f"BodyLength(9) is non-numeric: {bl.value[:16]!r}",
                        tag=TAG_BODY_LENGTH, byte_offset=bl.value_offset))

    if cs is not None:
        msg.checksum_declared = cs.value
        # CheckSum is computed over all bytes up to the start of "10=". The original was summed
        # over SOH delimiters, so normalize a printable delimiter (e.g. a pipe log) back to SOH
        # before summing — otherwise a correctly-checksummed pipe log looks tampered.
        head = raw[: cs.tag_offset]
        if delim != SOH:
            head = head.replace(delim, SOH)
        msg.checksum_computed = sum(head) % 256
    else:
        msg.anomalies.append(
            Anomaly("TRUNCATED_NO_CHECKSUM", "warn",
                    "message has no CheckSum(10) field", byte_offset=len(raw)))

    if bl is not None and cs is not None:
        start = bl.end_offset            # first body byte (just past 9's delimiter)
        end = cs.tag_offset              # start of "10=" (includes the preceding SOH)
        msg.body_length_computed = end - start

    # record framing mismatches as anomalies (detectors may also read declared/computed)
    if msg.body_length_ok is False:
        msg.anomalies.append(
            Anomaly("BODYLENGTH_MISMATCH", "error",
                    f"declared BodyLength {msg.body_length_declared} != computed "
                    f"{msg.body_length_computed}", tag=TAG_BODY_LENGTH,
                    byte_offset=bl.value_offset if bl else None))
    if msg.checksum_ok is False:
        detail = (f"declared CheckSum {msg.checksum_declared!r} != computed "
                  f"{msg.checksum_computed:03d}" if msg.checksum_computed is not None
                  else f"CheckSum {msg.checksum_declared!r} invalid")
        msg.anomalies.append(
            Anomaly("CHECKSUM_MISMATCH", "error", detail, tag=TAG_CHECKSUM,
                    byte_offset=cs.value_offset if cs else None))
    if cs is not None and cs.value is not None and len(cs.value) != 3:
        msg.anomalies.append(
            Anomaly("CHECKSUM_WRONG_WIDTH", "warn",
                    f"CheckSum(10) should be exactly 3 digits, got {cs.value!r}",
                    tag=TAG_CHECKSUM, byte_offset=cs.value_offset))

    # trailing bytes after the checksum field within this record
    if cs is not None and cs.end_offset < len(raw):
        trailing = raw[cs.end_offset:]
        if trailing.strip(delim):
            msg.anomalies.append(
                Anomaly("TRAILING_BYTES_AFTER_CHECKSUM", "warn",
                        f"{len(trailing)} byte(s) after CheckSum(10): {trailing[:32]!r}",
                        byte_offset=cs.end_offset))

    # duplicate singleton structural tags
    for t in _SINGLETON_STRUCTURAL_TAGS:
        c = msg.count(t)
        if c > 1:
            msg.anomalies.append(
                Anomaly("DUPLICATE_STRUCTURAL_TAG", "error",
                        f"structural tag {t} appears {c} times (expected once)", tag=t))
