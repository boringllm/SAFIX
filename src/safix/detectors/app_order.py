"""APP detectors — order/trade abuse (venue/risk layer), with regulatory tags.

These fire on semantically-valid FIX, so they are the most false-positive-prone layer: thresholds
are config-driven and confidence is calibrated down where a benign explanation exists (market
makers, give-up/drop-copy, legitimate large orders). Findings carry SEC 15c3-5 / MiFID II RTS 6
references.

Covers: D01 OrderQty sanity, D02 fat-finger price (baseline), D07 OrigClOrdID BOLA,
D08 ClOrdID reuse, D12 escalation-on-replace, D18 stale/future TransactTime, D19 wash/self-trade,
D20 order-rate throttle, D21 mass-cancel scope.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from ..model.finding import Confidence, Finding, Severity
from ..util.fixtime import parse_utc_timestamp
from .base import Detector, register

if TYPE_CHECKING:  # pragma: no cover
    from ..engine.context import ScanContext
    from ..model.message import FixMessage

H, M, L = Severity.HIGH, Severity.MEDIUM, Severity.LOW
CH, CM, CL = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW

NEW_ORDER, CANCEL, REPLACE, EXEC, MASSCANCEL = "D", "F", "G", "8", "q"
T_CLORDID, T_ORIGCLORDID, T_SYMBOL, T_SIDE, T_QTY, T_PRICE = 11, 41, 55, 54, 38, 44
T_TRANSACTTIME, T_LASTPX, T_MDENTRYPX, T_MASSCANCELTYPE, T_ACCOUNT = 60, 31, 270, 530, 1

REG_FATFINGER = ["SEC 15c3-5(c)(1)(ii)", "MiFID II RTS 6 Art.15"]
REG_BOLA = ["SEC 15c3-5(c)(2)(iii)", "MiFID II RTS 6 Art.18", "RTS 6 Art.20-21 (DEA)"]
REG_ESCALATION = ["SEC 15c3-5(b)", "MiFID II RTS 6 Art.15"]
REG_THROTTLE = ["SEC 15c3-5(c)(1)(i)", "MiFID II RTS 6 Art.15"]
REG_WASH = ["MiFID II RTS 6 Art.13", "RTS 6 Art.16"]
REG_TIME = ["MiFID II RTS 25 (clock sync)"]
REG_KILL = ["MiFID II RTS 6 Art.12 (kill functionality)"]


@dataclass(slots=True)
class OrderRecord:
    clordid: str
    owner: str
    symbol: Optional[str]
    side: Optional[str]
    qty: Optional[float]
    price: Optional[float]
    session: str
    seq: Optional[int]


def _f(value: Optional[bytes | str]) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


@register
class AppOrderDetector(Detector):
    id = "app-order"
    category = "APP"
    title = "Order/trade abuse: fat-finger, BOLA, escalation, wash, throttle, time"

    def analyze(self, msg: "FixMessage", ctx: "ScanContext") -> None:
        mt = msg.msg_type
        if mt not in (NEW_ORDER, CANCEL, REPLACE, EXEC, MASSCANCEL):
            return
        owner = msg.sender_comp_id or "?"

        # update instrument baseline from actual market prints
        self._update_baseline(ctx, msg)

        if mt in (NEW_ORDER, REPLACE):
            self._fat_finger(msg, ctx)
            self._order_rate(msg, ctx, owner)
        if mt == NEW_ORDER:
            self._clordid_reuse(msg, ctx, owner)
            self._register_order(msg, ctx, owner)
            self._wash(msg, ctx, owner)
        if mt in (CANCEL, REPLACE):
            self._bola(msg, ctx, owner)
        if mt == REPLACE:
            self._escalation(msg, ctx)
            self._register_order(msg, ctx, owner)  # the replacement gets a new ClOrdID
        if mt == MASSCANCEL:
            self._mass_cancel(msg, ctx)
        self._transact_time(msg, ctx)

    # --- baseline ---------------------------------------------------------------------------
    def _update_baseline(self, ctx, msg) -> None:
        sym = msg.get_str(T_SYMBOL)
        if not sym:
            return
        for tag in (T_LASTPX, T_MDENTRYPX):
            px = _f(msg.get(tag))
            if px and px > 0:
                b = ctx.instrument_baseline.setdefault(sym, {"n": 0, "sum": 0.0})
                b["n"] += 1
                b["sum"] += px

    def _ref_price(self, ctx, sym: Optional[str], thr) -> Optional[float]:
        b = ctx.instrument_baseline.get(sym or "")
        if not b or b["n"] < thr.baseline_min_samples:
            return None
        return b["sum"] / b["n"]

    # --- D01 / D02 --------------------------------------------------------------------------
    def _fat_finger(self, msg, ctx) -> None:
        thr = ctx.config.thresholds
        qty = _f(msg.get(T_QTY))
        price = _f(msg.get(T_PRICE))
        sym = msg.get_str(T_SYMBOL)

        if qty is not None:
            if thr.require_positive_qty and qty <= 0:
                self._emit(msg, ctx, "SAFIX-APP-001", H, CH, "Non-positive OrderQty(38)",
                           f"OrderQty(38)={qty:g} is <= 0", ["AV-APP-01", "SV-APP-1"], REG_FATFINGER,
                           tag=T_QTY, benign=[], remediation="Hard-reject non-positive quantities.")
            elif qty > thr.max_order_qty:
                self._emit(msg, ctx, "SAFIX-APP-002", M, CM, "OrderQty(38) exceeds max order size",
                           f"OrderQty(38)={qty:g} > max_order_qty {thr.max_order_qty:g}",
                           ["AV-APP-01"], REG_FATFINGER, tag=T_QTY,
                           benign=["Large but legitimate institutional orders exist — tune the limit."],
                           remediation="Apply a 15c3-5 max-order-size hard block.")
            elif thr.round_lot > 1 and qty % thr.round_lot != 0:
                self._emit(msg, ctx, "SAFIX-APP-003", L, CL, "Sub-round-lot OrderQty(38)",
                           f"OrderQty(38)={qty:g} is not a multiple of {thr.round_lot:g}",
                           ["AV-APP-03"], REG_FATFINGER, tag=T_QTY,
                           benign=["Many venues/instruments allow odd lots."],
                           remediation="Advisory; confirm odd-lot policy.")

        if qty is not None and price is not None and qty > 0 and price > 0:
            notional = qty * price
            if notional > thr.max_order_notional:
                self._emit(msg, ctx, "SAFIX-APP-004", M, CM, "Order notional exceeds limit",
                           f"notional {notional:,.0f} > max_order_notional {thr.max_order_notional:,.0f}",
                           ["AV-APP-01"], REG_FATFINGER, tag=T_PRICE,
                           benign=["Block trades legitimately exceed the limit — tune it."],
                           remediation="Apply a 15c3-5 max-notional hard block.")

        if price is not None:
            if thr.require_positive_price and price <= 0:
                self._emit(msg, ctx, "SAFIX-APP-005", H, CH, "Non-positive Price(44)",
                           f"Price(44)={price:g} is <= 0", ["AV-APP-02", "SV-APP-2"], REG_FATFINGER,
                           tag=T_PRICE, benign=[], remediation="Hard-reject non-positive prices.")
            else:
                ref = self._ref_price(ctx, sym, thr)
                if ref and price > 0:
                    if price > ref * thr.absurd_price_multiple or price < ref / thr.absurd_price_multiple:
                        self._emit(msg, ctx, "SAFIX-APP-006", H, CM, "Absurd Price(44) vs reference",
                                   f"Price(44)={price:g} vs reference {ref:.4g} "
                                   f"(> {thr.absurd_price_multiple:g}x band)",
                                   ["AV-APP-02"], REG_FATFINGER, tag=T_PRICE,
                                   benign=["Thin/volatile instruments move sharply; widen the band."],
                                   remediation="Apply a 15c3-5/RTS6 price collar.")
                    elif abs(price - ref) / ref * 100 > thr.price_band_pct:
                        self._emit(msg, ctx, "SAFIX-APP-007", M, CL, "Price(44) outside the price band",
                                   f"Price(44)={price:g} deviates "
                                   f"{abs(price - ref) / ref * 100:.1f}% from reference {ref:.4g} "
                                   f"(> {thr.price_band_pct:g}%)",
                                   ["AV-APP-02"], REG_FATFINGER, tag=T_PRICE,
                                   benign=["Reference is learned from the log; early samples are noisy."],
                                   remediation="Confirm against an authoritative reference price.")

    # --- D08 / registration -----------------------------------------------------------------
    def _clordid_reuse(self, msg, ctx, owner) -> None:
        cl = msg.get_str(T_CLORDID)
        if not cl:
            return
        if msg.get_str(43) == "Y":  # PossDup resends legitimately repeat the ClOrdID
            return
        existing = ctx.orderbook.get(cl)
        if existing is not None:
            self._emit(msg, ctx, "SAFIX-APP-008", M, CM, "ClOrdID(11) reuse / collision",
                       f"ClOrdID {cl!r} was already used (by {existing.owner})",
                       ["AV-APP-06", "SV-APP-7"], REG_BOLA, tag=T_CLORDID,
                       benign=["Daily ClOrdID namespace resets can legitimately reuse IDs across days."],
                       remediation="Enforce per-session ClOrdID uniqueness.")

    def _register_order(self, msg, ctx, owner) -> None:
        cl = msg.get_str(T_CLORDID)
        if not cl:
            return
        ctx.orderbook[cl] = OrderRecord(
            clordid=cl, owner=owner, symbol=msg.get_str(T_SYMBOL), side=msg.get_str(T_SIDE),
            qty=_f(msg.get(T_QTY)), price=_f(msg.get(T_PRICE)),
            session=str(ctx.session_state(msg).key), seq=msg.seq_num,
        )

    # --- D07 BOLA ---------------------------------------------------------------------------
    def _bola(self, msg, ctx, owner) -> None:
        orig_id = msg.get_str(T_ORIGCLORDID)
        if not orig_id:
            return
        orig = ctx.orderbook.get(orig_id)
        if orig is None:
            return  # referenced order not seen in this log — cannot assert ownership
        if not self._same_owner(ctx, orig.owner, owner):
            self._emit(msg, ctx, "SAFIX-APP-010", Severity.CRITICAL, CH,
                       "OrigClOrdID(41) BOLA — cancel/replace of a foreign order",
                       f"{msg.msg_type} by {owner!r} targets order {orig_id!r} owned by {orig.owner!r}",
                       ["AV-APP-05", "SV-APP-6"], REG_BOLA, tag=T_ORIGCLORDID,
                       benign=["Give-up/drop-copy and shared order namespaces — list them in "
                               "config.session_ownership_groups to suppress."],
                       remediation="Bind every order ID to its authenticated owner (object-level authz).")

    # --- D12 escalation on replace ----------------------------------------------------------
    def _escalation(self, msg, ctx) -> None:
        thr = ctx.config.thresholds
        orig = ctx.orderbook.get(msg.get_str(T_ORIGCLORDID) or "")
        if orig is None:
            return
        new_qty = _f(msg.get(T_QTY))
        if orig.qty and new_qty and orig.qty > 0 and new_qty > orig.qty * thr.replace_qty_ratio:
            self._emit(msg, ctx, "SAFIX-APP-012", H, CM, "Quantity escalation on replace",
                       f"replace raises OrderQty from {orig.qty:g} to {new_qty:g} "
                       f"(> {thr.replace_qty_ratio:g}x)",
                       ["AV-APP-10", "SV-APP-12"], REG_ESCALATION, tag=T_QTY,
                       benign=["Legitimate order scaling exists; tune replace_qty_ratio."],
                       remediation="Re-apply full pre-trade risk checks on every replace (15c3-5(b)).")

    # --- D18 time ---------------------------------------------------------------------------
    def _transact_time(self, msg, ctx) -> None:
        thr = ctx.config.thresholds
        tt = parse_utc_timestamp(msg.get_str(T_TRANSACTTIME))
        st = parse_utc_timestamp(msg.sending_time)
        if tt is None or st is None:
            return
        if tt > st + thr.future_transacttime_seconds:
            self._emit(msg, ctx, "SAFIX-APP-018", M, CM, "Future-dated TransactTime(60)",
                       f"TransactTime is {tt - st:.0f}s ahead of SendingTime",
                       ["AV-APP-16", "SV-APP-18"], REG_TIME, tag=T_TRANSACTTIME,
                       benign=["Clock skew between hosts can produce small offsets."],
                       remediation="Verify clock sync (RTS 25); reject grossly future timestamps.")
        elif st - tt > thr.stale_transacttime_seconds:
            self._emit(msg, ctx, "SAFIX-APP-019", M, CM, "Stale TransactTime(60)",
                       f"TransactTime is {st - tt:.0f}s behind SendingTime",
                       ["AV-APP-16", "SV-APP-18"], REG_TIME, tag=T_TRANSACTTIME,
                       benign=["Batch/replayed flows legitimately carry older TransactTimes."],
                       remediation="Reject stale order timestamps beyond the tolerance.")

    # --- D19 wash / self-trade --------------------------------------------------------------
    def _wash(self, msg, ctx, owner) -> None:
        thr = ctx.config.thresholds
        sym = msg.get_str(T_SYMBOL)
        side = msg.get_str(T_SIDE)
        price = _f(msg.get(T_PRICE))
        t = parse_utc_timestamp(msg.sending_time) or float(ctx.session_state(msg).message_count)
        if not sym or side not in ("1", "2"):
            return
        recent = ctx.windows.setdefault(f"wash:{sym}", deque())
        # evict old
        horizon = t - thr.wash_window_sec
        while recent and recent[0][0] < horizon:
            recent.popleft()
        opp = "2" if side == "1" else "1"
        for (_t, o_owner, o_side, o_price) in recent:
            if o_owner == owner and o_side == opp and (
                price is None or o_price is None or abs(price - o_price) <= max(0.0, (o_price or 0) * 0.001)
            ):
                self._emit(msg, ctx, "SAFIX-APP-020", M, CL, "Potential wash / self-trade",
                           f"{owner!r} placed opposite-side orders on {sym} within "
                           f"{thr.wash_window_sec}s at overlapping prices",
                           ["AV-APP-17", "SV-APP-19"], REG_WASH, tag=T_SIDE,
                           benign=["Market makers quote both sides legitimately; confirm intent/account."],
                           remediation="Surveil for self-match; apply self-trade prevention.")
                break
        recent.append((t, owner, side, price))

    # --- D20 order rate ---------------------------------------------------------------------
    def _order_rate(self, msg, ctx, owner) -> None:
        thr = ctx.config.thresholds
        st = ctx.session_state(msg)
        w = st.rate_windows.setdefault("orders", deque())
        t = parse_utc_timestamp(msg.sending_time)
        clock = t if t is not None else float(st.message_count)
        w.append(clock)
        horizon = clock - (thr.order_rate_window_sec if t is not None else thr.order_rate_count)
        while w and w[0] < horizon:
            w.popleft()
        if len(w) > thr.order_rate_count:
            self._emit(msg, ctx, "SAFIX-APP-021", M, CM, "Order-rate throttle breach",
                       f"{len(w)} orders within {thr.order_rate_window_sec}s "
                       f"(threshold {thr.order_rate_count})",
                       ["AV-APP-18", "SV-APP-20"], REG_THROTTLE,
                       benign=["Legitimate algos burst; tune order_rate_count/window."],
                       remediation="Apply a 15c3-5 message/order rate throttle.")
            w.clear()

    # --- D21 mass cancel --------------------------------------------------------------------
    def _mass_cancel(self, msg, ctx) -> None:
        scope = msg.get_str(T_MASSCANCELTYPE)
        if scope == "7":  # cancel all orders
            self._emit(msg, ctx, "SAFIX-APP-022", M, CM, "Mass-cancel-all (kill-switch scope)",
                       "OrderMassCancelRequest(35=q) with MassCancelRequestType(530)=7 (cancel all)",
                       ["AV-APP-19"], REG_KILL, tag=T_MASSCANCELTYPE,
                       benign=["Legitimate kill-switch / end-of-day flattening uses this."],
                       remediation="Authorize and scope mass-cancel; log and alert on cancel-all.")

    # --- helpers ----------------------------------------------------------------------------
    def _same_owner(self, ctx, a: str, b: str) -> bool:
        if a == b:
            return True
        for group in ctx.config.session_ownership_groups:
            if a in group and b in group:
                return True
        return False

    def _emit(self, msg, ctx, rule_id, sev, conf, title, message, vectors, reg, *,
              tag=None, benign, remediation) -> None:
        if not ctx.config.rule_enabled(rule_id, "APP"):
            return
        ctx.add(
            Finding(
                rule_id=rule_id, title=title, message=message, severity=sev, confidence=conf,
                category="APP", vector_ids=list(vectors), regulatory_refs=list(reg), tag=tag,
                benign_notes=list(benign), remediation=remediation, dedup_key=f"{rule_id}:{msg.get_str(T_CLORDID)}",
            ),
            msg,
        )
