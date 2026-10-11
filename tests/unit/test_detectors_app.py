"""Tests for the APP (order/trade abuse) detector."""

from __future__ import annotations

from safix.config import Config
from safix.engine.runner import scan_bytes
from safix.parsing.encode import encode


def _rules(blob: bytes, config: Config | None = None) -> set[str]:
    res = scan_bytes(blob, config=config, source="t.log")
    return {f.rule_id for f in res.active_findings}


def _order(seq=2, sender="CLIENT", clordid="O1", symbol="AAPL", side="1",
           qty="100", price="150.00", t="20231015-10:00:00", mtype="D", extra=None):
    f = [(35, mtype), (34, seq), (49, sender), (52, t), (56, "SERVER"),
         (11, clordid), (55, symbol), (54, side), (38, qty), (40, "2"), (44, price),
         (60, t)]
    if extra:
        f.extend(extra)
    return encode(f, begin_string="FIX.4.4")


def test_negative_qty():
    assert "SAFIX-APP-001" in _rules(_order(qty="-5"))


def test_qty_over_max():
    assert "SAFIX-APP-002" in _rules(_order(qty="200000"))


def test_nonpositive_price():
    assert "SAFIX-APP-005" in _rules(_order(price="0"))


def test_notional_over_max():
    # 1000 * 6000 = 6,000,000 > default 5,000,000
    assert "SAFIX-APP-004" in _rules(_order(qty="1000", price="6000"))


def test_origclordid_bola_cross_owner():
    alice = _order(seq=2, sender="ALICE", clordid="O1")
    # BOB cancels ALICE's order O1
    bob_cancel = encode([(35, "F"), (34, 2), (49, "BOB"), (52, "20231015-10:00:01"),
                         (56, "SERVER"), (41, "O1"), (11, "C1"), (55, "AAPL"), (54, "1")],
                        begin_string="FIX.4.4")
    rules = _rules(alice + bob_cancel)
    assert "SAFIX-APP-010" in rules


def test_bola_suppressed_by_ownership_group():
    cfg = Config.default()
    cfg.session_ownership_groups = [["ALICE", "BOB"]]
    alice = _order(seq=2, sender="ALICE", clordid="O1")
    bob_cancel = encode([(35, "F"), (34, 2), (49, "BOB"), (52, "20231015-10:00:01"),
                         (56, "SERVER"), (41, "O1"), (11, "C1"), (55, "AAPL"), (54, "1")],
                        begin_string="FIX.4.4")
    assert "SAFIX-APP-010" not in _rules(alice + bob_cancel, cfg)


def test_clordid_reuse():
    assert "SAFIX-APP-008" in _rules(_order(seq=2, clordid="DUP") + _order(seq=3, clordid="DUP"))


def test_escalation_on_replace():
    order = _order(seq=2, clordid="O1", qty="100")
    replace = encode([(35, "G"), (34, 3), (49, "CLIENT"), (52, "20231015-10:00:02"),
                      (56, "SERVER"), (41, "O1"), (11, "O2"), (55, "AAPL"), (54, "1"),
                      (38, "5000"), (40, "2"), (44, "150.00"), (60, "20231015-10:00:02")],
                     begin_string="FIX.4.4")
    assert "SAFIX-APP-012" in _rules(order + replace)


def test_future_transacttime():
    # TransactTime far ahead of SendingTime
    msg = _order()
    msg = msg.replace(b"60=20231015-10:00:00", b"60=20231015-12:00:00")
    assert "SAFIX-APP-018" in _rules(msg)


def test_stale_transacttime():
    msg = _order()
    msg = msg.replace(b"60=20231015-10:00:00", b"60=20231015-08:00:00")
    assert "SAFIX-APP-019" in _rules(msg)


def test_mass_cancel_all():
    q = encode([(35, "q"), (34, 2), (49, "CLIENT"), (52, "20231015-10:00:00"),
                (56, "SERVER"), (11, "MC1"), (530, "7")], begin_string="FIX.4.4")
    assert "SAFIX-APP-022" in _rules(q)


def test_wash_self_trade():
    buy = _order(seq=2, side="1", price="150.00")
    sell = _order(seq=3, clordid="O2", side="2", price="150.00")
    assert "SAFIX-APP-020" in _rules(buy + sell)


def test_order_rate_throttle():
    cfg = Config.default()
    cfg.thresholds.order_rate_count = 3
    blob = b"".join(_order(seq=i, clordid=f"O{i}") for i in range(2, 8))
    assert "SAFIX-APP-021" in _rules(blob, cfg)


def test_clean_order_no_app_findings():
    assert not any(r.startswith("SAFIX-APP-") for r in _rules(_order()))
