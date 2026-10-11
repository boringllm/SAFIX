"""Parse FIX UTC timestamps to epoch seconds (best-effort, never raises)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def parse_utc_timestamp(value: Optional[str]) -> Optional[float]:
    """Parse ``YYYYMMDD-HH:MM:SS(.fraction)?`` to epoch seconds, or None if unparseable."""
    if not value:
        return None
    s = value.strip()
    if len(s) < 17 or s[8] != "-":
        return None
    try:
        y, mo, d = int(s[0:4]), int(s[4:6]), int(s[6:8])
        hh, mm = int(s[9:11]), int(s[12:14])
        ss = int(s[15:17])
        frac = 0.0
        if len(s) > 17 and s[17] == ".":
            digits = s[18:]
            if digits.isdigit():
                frac = int(digits) / (10 ** len(digits))
        if ss == 60:  # leap second — clamp for arithmetic
            ss = 59
        return datetime(y, mo, d, hh, mm, ss, tzinfo=timezone.utc).timestamp() + frac
    except (ValueError, OverflowError):
        return None
