"""Read FIX messages from files, directories, or raw bytes.

Detects the format, segments the buffer, and parses each message with the lenient lexer,
attaching source/line/timestamp/direction provenance. Direction from a line prefix is kept;
comp-id-based direction resolution happens later (it needs the session's own CompID).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from ..model.message import FixMessage, RawField
from . import formats
from .formats import DetectedFormat
from .lexer import parse_message
from .rawdata import DATA_TO_LEN, LEN_TO_DATA, SOH

_XML_MARKERS = (b"<?xml", b"<!DOCTYPE", b"<!ENTITY", b"<FIXML", b"<xi:", b"<![CDATA[")


def _looks_like_xml(data: bytes) -> bool:
    low = data.lower()
    return any(m.lower() in low for m in _XML_MARKERS)


def _content_message(content: bytes, *, source=None, source_line=None, msg_offset=0) -> FixMessage:
    """Wrap non-FIX (e.g. whole-FIXML) content as a single-field message so content detectors
    (ENC XML-signature scan) can inspect it. No FIX field/framing detectors fire on it."""
    fld = RawField(index=0, tag_bytes=b"", tag=None, value=content, raw=content,
                   tag_offset=0, value_offset=0, end_offset=len(content))
    return FixMessage(fields=[fld], raw=content, msg_offset=msg_offset, source=source,
                      source_line=source_line)


@dataclass(slots=True)
class ReadOptions:
    """Overrides for the reader; any left None are auto-detected."""

    field_delimiter: Optional[bytes] = None
    line_oriented: Optional[bool] = None
    len_to_data: dict[int, int] = field(default_factory=lambda: dict(LEN_TO_DATA))
    data_to_len: dict[int, int] = field(default_factory=lambda: dict(DATA_TO_LEN))


def sniff(data: bytes, options: Optional[ReadOptions] = None) -> DetectedFormat:
    fmt = formats.detect(data)
    if options:
        if options.field_delimiter is not None:
            fmt.field_delimiter = options.field_delimiter
        if options.line_oriented is not None:
            fmt.line_oriented = options.line_oriented
    return fmt


def iter_messages(
    data: bytes,
    *,
    source: Optional[str] = None,
    options: Optional[ReadOptions] = None,
) -> Iterator[FixMessage]:
    """Yield :class:`FixMessage` objects parsed from ``data``."""
    opts = options or ReadOptions()
    fmt = sniff(data, opts)
    delim = fmt.field_delimiter

    if fmt.line_oriented:
        yield from _iter_line_oriented(data, delim, source, opts)
    else:
        segs = list(formats.iter_blob_segments(data, delim))
        if segs:
            for seg, off in segs:
                yield parse_message(
                    seg, field_delimiter=delim, len_to_data=opts.len_to_data,
                    data_to_len=opts.data_to_len, msg_offset=off, source=source,
                )
        elif _looks_like_xml(data):
            yield _content_message(data, source=source)


def parse_line(
    line: bytes, delim: bytes, opts: ReadOptions, *,
    source: Optional[str] = None, lineno: Optional[int] = None, base_offset: int = 0,
) -> list[FixMessage]:
    """Parse one log line (optional timestamp/direction prefix + one or more FIX messages).

    Returns a list (usually one message). Used by the batch reader and the live tailer.
    """
    stripped = line.rstrip(b"\r")
    if b"8=" not in stripped:
        if _looks_like_xml(stripped):
            return [_content_message(stripped, source=source, source_line=lineno,
                                     msg_offset=base_offset)]
        return []
    ts, direction, start = formats.split_prefix(stripped)
    if start < 0:
        return []
    msg_part = stripped[start:]
    base = base_offset + start
    segs = list(formats.iter_blob_segments(msg_part, delim)) or [(msg_part, 0)]
    out: list[FixMessage] = []
    for seg, rel in segs:
        out.append(parse_message(
            seg, field_delimiter=delim, len_to_data=opts.len_to_data,
            data_to_len=opts.data_to_len, msg_offset=base + rel, source=source,
            source_line=lineno, timestamp=ts, direction=direction,
        ))
    return out


def _iter_line_oriented(
    data: bytes, delim: bytes, source: Optional[str], opts: ReadOptions,
) -> Iterator[FixMessage]:
    offset = 0
    lineno = 0
    for line in data.split(b"\n"):
        line_start = offset
        offset += len(line) + 1  # account for the stripped '\n'
        lineno += 1
        yield from parse_line(line, delim, opts, source=source, lineno=lineno,
                              base_offset=line_start)


def read_file(path: str | os.PathLike, options: Optional[ReadOptions] = None) -> Iterator[FixMessage]:
    p = Path(path)
    data = p.read_bytes()
    yield from iter_messages(data, source=str(p), options=options)


def read_paths(
    paths: list[str | os.PathLike], options: Optional[ReadOptions] = None,
) -> Iterator[FixMessage]:
    """Read every file in ``paths`` (directories are walked for common FIX log files)."""
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file() and _looks_like_fix_log(child):
                    yield from read_file(child, options)
        elif p.is_file():
            yield from read_file(p, options)


def _looks_like_fix_log(p: Path) -> bool:
    if p.suffix.lower() in {".log", ".txt", ".fix", ".body", ".cap"} or p.name.endswith(".messages.log"):
        return True
    # otherwise sniff the first bytes
    try:
        with p.open("rb") as fh:
            head = fh.read(256)
    except OSError:
        return False
    return b"8=FIX" in head or (SOH in head and b"8=" in head)
