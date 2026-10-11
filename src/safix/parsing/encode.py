"""Build well-formed FIX messages (correct BodyLength + CheckSum).

Used by tests and sample-data generation. Mirrors the canonical QuickFIX/simplefix encoding:
BodyLength(9) counts from the first body byte through the SOH before CheckSum(10); CheckSum is
the mod-256 sum of all bytes up to the start of ``10=``.
"""

from __future__ import annotations

from typing import Iterable

from .rawdata import SOH

FieldLike = tuple[object, object]


def _to_bytes(v: object) -> bytes:
    if isinstance(v, bytes):
        return v
    return str(v).encode("latin-1")


def encode(
    body_fields: Iterable[FieldLike],
    *,
    begin_string: str = "FIX.4.2",
    delimiter: bytes = SOH,
) -> bytes:
    """Encode a message from ``body_fields`` (tag 35 onward; exclude 8/9/10).

    ``body_fields`` is an ordered iterable of ``(tag, value)`` pairs. BeginString(8),
    BodyLength(9) and CheckSum(10) are added/computed automatically. BodyLength and CheckSum are
    always computed over the canonical SOH form (as on the wire); if ``delimiter`` is not SOH the
    whole message is then rendered with it (as a pretty-printed/pipe log would be).
    """
    body = b"".join(_to_bytes(t) + b"=" + _to_bytes(v) + SOH for t, v in body_fields)
    head = (
        b"8=" + begin_string.encode("latin-1") + SOH
        + b"9=" + str(len(body)).encode("latin-1") + SOH
    )
    without_cs = head + body
    checksum = sum(without_cs) % 256
    msg = without_cs + b"10=" + f"{checksum:03d}".encode("latin-1") + SOH
    return msg if delimiter == SOH else msg.replace(SOH, delimiter)
