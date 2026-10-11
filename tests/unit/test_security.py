"""Regression tests for security hardening."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from rich.console import Console

from safix.dictionary import loader
from safix.engine.live import LiveScanner
from safix.engine.runner import scan_bytes
from safix.parsing import lexer
from safix.parsing.encode import encode
from safix.reporting import console as console_report


def _order_with_compid(compid: str) -> bytes:
    return encode([(35, "D"), (34, 2), (49, compid), (52, "20231015-10:00:00"), (56, "SERVER"),
                   (11, "O1"), (55, "AAPL"), (54, "1"), (38, "-5"), (40, "2"), (44, "150"),
                   (60, "20231015-10:00:00")], begin_string="FIX.4.4")


def test_console_report_no_markup_injection():
    # a SenderCompID of "[/]" must not crash rich's markup parser
    res = scan_bytes(_order_with_compid("[/]"), source="t.log")
    assert res.active_findings
    buf = io.StringIO()
    console_report.render(res, console=Console(file=buf, width=120))  # must not raise
    assert "SAFIX-APP-001" in buf.getvalue()


def test_console_report_handles_style_like_compid():
    res = scan_bytes(_order_with_compid("[bold red]EVIL"), source="t.log")
    buf = io.StringIO()
    console_report.render(res, console=Console(file=buf, width=120))  # must not raise


def test_live_scanner_markup_compid_is_safe():
    # feeding a crafted CompID must still produce findings without error
    ls = LiveScanner()
    out = ls.feed(lexer.parse_message(_order_with_compid("[/]")))
    assert any(f.rule_id == "SAFIX-APP-001" for f in out)


def test_dictionary_rejects_doctype(tmp_path: Path):
    evil = tmp_path / "evil.xml"
    evil.write_bytes(
        b'<?xml version="1.0"?>\n'
        b'<!DOCTYPE fix [<!ENTITY a "AAAA"><!ENTITY b "&a;&a;&a;&a;&a;">]>\n'
        b"<fix type='FIX' major='4' minor='4'><fields>"
        b"<field number='1' name='Account' type='STRING'/></fields></fix>")
    with pytest.raises(ValueError, match="DOCTYPE/ENTITY"):
        loader.load_file(evil)


def test_dictionary_rejects_entity_only(tmp_path: Path):
    evil = tmp_path / "evil2.xml"
    evil.write_bytes(b"<fix><!ENTITY x 'y'><fields/></fix>")
    with pytest.raises(ValueError):
        loader.load_file(evil)


def test_bundled_dictionaries_still_load():
    # the guard must not break legitimate dictionaries
    spec = loader.load("FIX.4.4")
    assert spec.field_number("MsgType") == 35


def test_tail_buffer_is_bounded():
    from safix.parsing.tail import _bound_buffer, _MAX_BUFFER
    big = b"8=FIX.4.4\x01" + b"X" * (_MAX_BUFFER + 1000)
    out = _bound_buffer(big)
    assert len(out) <= _MAX_BUFFER + 16
