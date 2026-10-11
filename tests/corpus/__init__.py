"""Ground-truth corpora for measuring SAFIX detection rate (recall) and false positives."""

from __future__ import annotations

import json
from pathlib import Path

from safix.parsing.encode import encode

CORPUS_DIR = Path(__file__).parent
FIXFUZZ_CORPUS = CORPUS_DIR / "fixfuzz_corpus.jsonl"


def load_fixfuzz_corpus() -> list[dict]:
    """Load the labeled attack corpus produced by the independent fixfuzz-plus fuzzer."""
    if not FIXFUZZ_CORPUS.exists():
        return []
    rows = []
    for line in FIXFUZZ_CORPUS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def benign_messages() -> list[tuple[str, bytes]]:
    """A set of well-formed, benign FIX messages that must NOT raise active findings.

    Returns (label, raw) pairs. Correct framing, valid datatypes/enums, in-dictionary tags,
    plausible values — the kind of ordinary traffic a scanner must stay quiet on.
    """
    out: list[tuple[str, bytes]] = []

    def m(label, fields, bs="FIX.4.4"):
        out.append((label, encode(fields, begin_string=bs)))

    m("logon", [(35, "A"), (34, 1), (49, "CLIENT"), (52, "20231015-09:00:00.000"),
                (56, "SERVER"), (98, 0), (108, 30)])
    m("heartbeat", [(35, "0"), (34, 2), (49, "CLIENT"), (52, "20231015-09:00:30.000"),
                    (56, "SERVER")])
    m("testrequest", [(35, "1"), (34, 3), (49, "CLIENT"), (52, "20231015-09:01:00.000"),
                      (56, "SERVER"), (112, "TRID-1")])
    m("new_order", [(35, "D"), (34, 4), (49, "CLIENT"), (52, "20231015-09:02:00.000"),
                    (56, "SERVER"), (11, "ORD-1001"), (55, "AAPL"), (54, "1"), (38, "100"),
                    (40, "2"), (44, "150.25"), (59, "0"), (60, "20231015-09:02:00.000")])
    m("exec_report", [(35, "8"), (34, 5), (49, "SERVER"), (52, "20231015-09:02:01.000"),
                      (56, "CLIENT"), (37, "EX-1"), (11, "ORD-1001"), (17, "E-1"),
                      (150, "0"), (39, "0"), (55, "AAPL"), (54, "1"), (38, "100"),
                      (151, "100"), (14, "0"), (6, "0"), (31, "150.25"), (32, "0")])
    m("cancel_replace", [(35, "G"), (34, 6), (49, "CLIENT"), (52, "20231015-09:03:00.000"),
                         (56, "SERVER"), (41, "ORD-1001"), (11, "ORD-1002"), (55, "AAPL"),
                         (54, "1"), (38, "120"), (40, "2"), (44, "150.30"),
                         (60, "20231015-09:03:00.000")])
    m("order_cancel", [(35, "F"), (34, 7), (49, "CLIENT"), (52, "20231015-09:04:00.000"),
                       (56, "SERVER"), (41, "ORD-1002"), (11, "ORD-1003"), (55, "AAPL"),
                       (54, "1"), (60, "20231015-09:04:00.000")])
    m("market_data_request", [(35, "V"), (34, 8), (49, "CLIENT"), (52, "20231015-09:05:00.000"),
                              (56, "SERVER"), (262, "MDREQ-1"), (263, "1"), (264, "1"),
                              (267, "1"), (269, "0"), (146, "1"), (55, "AAPL")])
    m("resend_request", [(35, "2"), (34, 9), (49, "CLIENT"), (52, "20231015-09:06:00.000"),
                         (56, "SERVER"), (7, 5), (16, 8)])
    m("logout", [(35, "5"), (34, 10), (49, "CLIENT"), (52, "20231015-09:07:00.000"),
                 (56, "SERVER"), (58, "normal shutdown")])
    return out
