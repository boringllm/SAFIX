"""Input-format auto-detection and message segmentation.

SAFIX accepts FIX data captured by many tools. This module decides the field delimiter,
whether the file is line-oriented (QuickFIX ``messages.log``, pretty-printed pipe logs) or a
single concatenated blob (FileStore ``.body``, raw-SOH TCP capture), recovers an optional
per-line timestamp/direction prefix, and segments a buffer into individual message byte ranges.

Every detected parameter is overridable so a scan is always explainable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator, Optional

from .rawdata import SOH

# candidate printable delimiters, in priority order (SOH always wins if present)
_PRINTABLE_DELIMS = [b"|", b"\x01", b"^", b";", b"\t"]

# YYYYMMDD-HH:MM:SS(.fraction)? optionally with trailing Z / timezone
_TS_RE = re.compile(rb"^\s*(\d{8}-\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)(?:Z|[+-]\d{2}:?\d{2})?")

_DIR_TOKENS: list[tuple[bytes, str]] = [
    (b"-->", "out"), (b"<--", "in"),
    (b"outgoing", "out"), (b"incoming", "in"),
    (b"sent", "out"), (b"recv", "in"), (b"received", "in"),
    (b" out ", "out"), (b" in ", "in"),
    (b"[tx]", "out"), (b"[rx]", "in"),
]

_BEGIN_RE = re.compile(rb"8=FIXT?\.\d")


@dataclass(slots=True)
class DetectedFormat:
    field_delimiter: bytes = SOH
    line_oriented: bool = True
    has_timestamp: bool = False
    direction_source: str = "none"   # "prefix" | "none" (comp-id resolution happens later)
    input_kind: str = "unknown"      # raw-soh | pipe | quickfix-log | filestore-body | unknown

    def describe(self) -> dict:
        return {
            "input_kind": self.input_kind,
            "field_delimiter": self.field_delimiter.decode("latin-1"),
            "line_oriented": self.line_oriented,
            "has_timestamp": self.has_timestamp,
            "direction_source": self.direction_source,
        }


def pick_delimiter(probe: bytes) -> bytes:
    """Choose the field delimiter from a probe of the file's bytes."""
    if SOH in probe:
        return SOH
    for d in _PRINTABLE_DELIMS:
        if d == SOH:
            continue
        # a printable delimiter should appear right after a 3-digit checksum "10=ddd<d>"
        if re.search(rb"\b10=\d{3}" + re.escape(d), probe) or (d in probe and b"8=" in probe):
            # confirm it actually separates tag=value tokens
            parts = probe.split(d)
            if sum(1 for p in parts[:20] if b"=" in p) >= 3:
                return d
    return SOH


def split_prefix(line: bytes) -> tuple[Optional[str], str, int]:
    """Split a log line into ``(timestamp, direction_hint, msg_start_index)``.

    ``msg_start_index`` is the byte index of the first ``8=`` (the start of the FIX message);
    it is ``-1`` if the line contains no FIX message.
    """
    m = _BEGIN_RE.search(line)
    if m is None:
        # tolerate a bare "8=" without a version token
        idx = line.find(b"8=")
        if idx == -1:
            return None, "unknown", -1
        start = idx
    else:
        start = m.start()
    prefix = line[:start]
    ts: Optional[str] = None
    tm = _TS_RE.match(prefix)
    if tm:
        ts = tm.group(1).decode("latin-1")
    direction = "unknown"
    low = prefix.lower()
    for token, d in _DIR_TOKENS:
        if token in low:
            direction = d
            break
    return ts, direction, start


def iter_blob_segments(buf: bytes, delimiter: bytes = SOH) -> Iterator[tuple[bytes, int]]:
    """Yield ``(message_bytes, offset)`` from a concatenated blob using the 8=…10=ddd rule.

    A message starts at a ``8=`` that begins a field (at buffer start or just after a
    delimiter) and ends at the delimiter following ``10=`` + exactly three digits. If no proper
    checksum terminator is found, the segment runs to the next message start (or end).
    """
    n = len(buf)
    dlen = len(delimiter)

    def is_field_start(idx: int) -> bool:
        return idx == 0 or buf[idx - dlen:idx] == delimiter

    start = buf.find(b"8=")
    while start != -1 and start < n:
        # ensure 8= is a field start; otherwise skip this occurrence
        if not is_field_start(start):
            start = buf.find(b"8=", start + 2)
            continue
        # find a proper checksum terminator
        end = None
        j = start
        while True:
            k = buf.find(b"10=", j)
            if k == -1:
                break
            if (buf[k - dlen:k] == delimiter or k == start) and \
               k + 3 + 3 <= n + dlen and buf[k + 3:k + 6].isdigit() and \
               buf[k + 6:k + 6 + dlen] == delimiter:
                end = k + 6 + dlen
                break
            j = k + 3
        if end is None:
            nxt = buf.find(b"8=", start + 2)
            while nxt != -1 and not is_field_start(nxt):
                nxt = buf.find(b"8=", nxt + 2)
            seg_end = nxt if nxt != -1 else n
            yield buf[start:seg_end], start
            start = nxt
            continue
        yield buf[start:end], start
        nxt = buf.find(b"8=", end)
        start = nxt


def detect(data: bytes) -> DetectedFormat:
    """Detect the format of a buffer (uses up to the first 64 KiB)."""
    probe = data[:65536]
    delim = pick_delimiter(probe)
    has_nl = b"\n" in probe
    fmt = DetectedFormat(field_delimiter=delim)

    if not has_nl:
        # single concatenated blob
        fmt.line_oriented = False
        fmt.input_kind = "filestore-body" if probe.count(b"8=") > 1 else "raw-soh"
        return fmt

    # line-oriented: inspect the first FIX-bearing line for a timestamp prefix
    fmt.line_oriented = True
    for line in probe.split(b"\n"):
        line = line.rstrip(b"\r")
        if b"8=" not in line:
            continue
        ts, direction, start = split_prefix(line)
        fmt.has_timestamp = ts is not None
        if direction in ("in", "out"):
            fmt.direction_source = "prefix"
        if delim == SOH:
            fmt.input_kind = "quickfix-log" if (ts is not None or start > 0) else "raw-soh"
        else:
            fmt.input_kind = "pipe"
        break
    return fmt
