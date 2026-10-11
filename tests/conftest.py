"""Shared pytest fixtures/helpers for SAFIX tests."""

from __future__ import annotations

import pytest

from safix.parsing.encode import encode
from safix.parsing.rawdata import SOH


@pytest.fixture
def soh() -> bytes:
    return SOH


def make_logon(begin_string: str = "FIX.4.2", seq: int = 1,
               sender: str = "CLIENT", target: str = "SERVER") -> bytes:
    """A well-formed Logon(35=A) with correct framing."""
    return encode(
        [
            (35, "A"),
            (34, seq),
            (49, sender),
            (52, "20231015-14:30:00.000"),
            (56, target),
            (98, 0),
            (108, 30),
        ],
        begin_string=begin_string,
    )


def make_order(begin_string: str = "FIX.4.2", seq: int = 2, clordid: str = "ORD1",
               symbol: str = "AAPL", side: str = "1", qty: str = "100",
               price: str = "150.00", sender: str = "CLIENT", target: str = "SERVER") -> bytes:
    """A well-formed NewOrderSingle(35=D) with correct framing."""
    return encode(
        [
            (35, "D"),
            (34, seq),
            (49, sender),
            (52, "20231015-14:30:01.000"),
            (56, target),
            (11, clordid),
            (55, symbol),
            (54, side),
            (38, qty),
            (40, "2"),
            (44, price),
            (60, "20231015-14:30:01.000"),
        ],
        begin_string=begin_string,
    )
