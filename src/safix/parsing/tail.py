"""Follow a growing FIX log (tail -f) and yield complete messages — passively and read-only.

SAFIX **never sits in the FIX message path**. It opens the engine's log file read-only in a
separate process and polls for appended bytes, so it adds zero latency to the trading engine
(the engine writes that log regardless; SAFIX only reads what has already been flushed). It is
rotation-aware (detects truncation / re-created files) and can also read a piped stream from
stdin, so SAFIX can run entirely off the trading host (e.g. `tail -f log | safix watch -`).
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Callable, Iterator, Optional

from ..model.message import FixMessage
from . import formats
from .logreader import ReadOptions, parse_line, parse_message
from .rawdata import SOH

_DLEN_SCAN = 65536
_MAX_BUFFER = 16 * 1024 * 1024  # hard cap so an unterminated message can't exhaust memory


def _bound_buffer(buffer: bytes) -> bytes:
    """Keep the live-tail buffer bounded: if it grows past the cap with no complete message,
    resync to the most recent BeginString (dropping unparseable leading bytes)."""
    if len(buffer) <= _MAX_BUFFER:
        return buffer
    idx = buffer.rfind(b"8=", len(buffer) - _MAX_BUFFER)
    return buffer[idx:] if idx != -1 else buffer[-(_MAX_BUFFER // 2):]


def _complete_frames(buf: bytes, delim: bytes) -> tuple[list[tuple[bytes, int]], int]:
    """Return (complete 8=…10=ddd<delim> frames, bytes_consumed). The trailing incomplete
    frame is left unconsumed so it can be completed by the next read."""
    out: list[tuple[bytes, int]] = []
    n = len(buf)
    dlen = len(delim)
    consumed = 0
    start = buf.find(b"8=")
    while start != -1:
        if not (start == 0 or buf[start - dlen:start] == delim):
            start = buf.find(b"8=", start + 2)
            continue
        end = None
        j = start
        while True:
            k = buf.find(b"10=", j)
            if k == -1:
                break
            if (k == start or buf[k - dlen:k] == delim) and k + 6 <= n \
                    and buf[k + 3:k + 6].isdigit() and buf[k + 6:k + 6 + dlen] == delim:
                end = k + 6 + dlen
                break
            j = k + 3
        if end is None:
            break  # incomplete tail — wait for more bytes
        out.append((buf[start:end], start))
        consumed = end
        start = buf.find(b"8=", end)
    return out, consumed


def _segment(buffer: bytes, delim: bytes, line_oriented: bool, opts: ReadOptions,
             source: Optional[str], lineno_start: int) -> tuple[list[FixMessage], int, int]:
    """Segment the buffer into complete messages. Returns (messages, consumed, lines_used)."""
    msgs: list[FixMessage] = []
    if line_oriented:
        idx = buffer.rfind(b"\n")
        if idx == -1:
            return [], 0, 0
        complete = buffer[:idx + 1]
        lines = complete.split(b"\n")[:-1]  # last split element is empty (trailing \n)
        for i, line in enumerate(lines):
            msgs.extend(parse_line(line, delim, opts, source=source, lineno=lineno_start + i))
        return msgs, idx + 1, len(lines)
    frames, consumed = _complete_frames(buffer, delim)
    for blob, off in frames:
        msgs.append(parse_message(blob, field_delimiter=delim, len_to_data=opts.len_to_data,
                                  data_to_len=opts.data_to_len, source=source))
    return msgs, consumed, 0


def _resolve_delim_and_mode(buffer: bytes, opts: ReadOptions) -> tuple[bytes, bool]:
    delim = opts.field_delimiter or formats.pick_delimiter(buffer)
    line_oriented = opts.line_oriented if opts.line_oriented is not None else (b"\n" in buffer)
    return delim, line_oriented


def follow_file(
    path: str | Path,
    *,
    options: Optional[ReadOptions] = None,
    from_start: bool = False,
    poll_interval: float = 0.5,
    stop: Optional[Callable[[], bool]] = None,
) -> Iterator[FixMessage]:
    """Yield messages from a growing log file, tailing it read-only. Blocks between polls."""
    opts = options or ReadOptions()
    stop = stop or (lambda: False)
    p = Path(path)
    pos = 0
    ident: Optional[tuple] = None   # (st_dev, st_ino) to detect a replaced/rotated file
    buffer = b""
    delim: Optional[bytes] = None
    line_oriented = True
    lineno = 0
    started = False
    # NOTE: the file is opened read-only and closed on every poll — SAFIX never holds a handle,
    # so it can never block the engine writing or rotating its log (true zero-impact on Windows).
    while not stop():
        try:
            st = p.stat()
        except OSError:
            time.sleep(poll_interval)
            continue
        new_ident = (st.st_dev, st.st_ino)
        if not started:
            pos = 0 if from_start else st.st_size
            ident = new_ident
            started = True
        elif new_ident != ident or st.st_size < pos:
            pos, buffer, delim, ident = 0, b"", None, new_ident  # rotated / truncated
        if st.st_size <= pos:
            time.sleep(poll_interval)
            continue
        try:
            with p.open("rb") as fh:
                fh.seek(pos)
                data = fh.read()
                pos = fh.tell()
        except OSError:
            time.sleep(poll_interval)
            continue
        if not data:
            time.sleep(poll_interval)
            continue
        buffer += data
        if delim is None and (b"8=" in buffer):
            delim, line_oriented = _resolve_delim_and_mode(buffer, opts)
        if delim is None:
            continue
        msgs, consumed, used = _segment(buffer, delim, line_oriented, opts, str(p), lineno + 1)
        buffer = _bound_buffer(buffer[consumed:])
        lineno += used
        for m in msgs:
            yield m


def follow_stream(
    fileobj=None,
    *,
    options: Optional[ReadOptions] = None,
    stop: Optional[Callable[[], bool]] = None,
) -> Iterator[FixMessage]:
    """Yield messages from a piped byte stream (default: stdin). For `tail -f log | safix watch -`."""
    opts = options or ReadOptions()
    stop = stop or (lambda: False)
    stream = fileobj or sys.stdin.buffer
    buffer = b""
    delim: Optional[bytes] = None
    line_oriented = True
    lineno = 0
    while not stop():
        chunk = stream.readline()
        if chunk == b"":
            break  # EOF
        buffer += chunk
        if delim is None and (b"8=" in buffer):
            delim, line_oriented = _resolve_delim_and_mode(buffer, opts)
        if delim is None:
            continue
        msgs, consumed, used = _segment(buffer, delim, line_oriented, opts, "<stdin>", lineno + 1)
        buffer = _bound_buffer(buffer[consumed:])
        lineno += used
        for m in msgs:
            yield m
