# SAFIX — Application-Layer (APP) Detection Specifications & Regulatory Mapping

**Scope.** Detections for the FIX **application / order-lifecycle business-logic** abuse surface — the
counterparty/venue **pre-trade risk and authorization layer** (SEC Rule 15c3-5, MiFID II RTS 6), *not*
the FIX engine. QuickFIX / QuickFIX-J implement session + parsing only; they carry no
price/size/credit/throttle/ownership controls, so every detection here fires on **semantically-valid FIX
messages carrying malicious intent**, read from QuickFIX-format message logs after the fact.

**Input model (what SAFIX reads).** QuickFIX `FileLogFactory` writes one message log per session, named by
`BeginString-SenderCompID-TargetCompID[-Qualifier]` (e.g. `FIX.4.4-CLIENTA-VENUE.messages.current.log`),
each line a raw `tag=value<SOH>` message with `SendingTime(52)` in the header. SAFIX therefore knows, per
line: **(a) the owning session** (from the filename), **(b) message direction** (compare the message's
`SenderCompID(49)`/`TargetCompID(56)` against the session identity — inbound = client→venue order flow),
and **(c) wall-clock arrival** (from `52`, falling back to log timestamp). This is the substrate for every
stateful detection below.

**Honest framing.** These detections observe *what crossed the wire*. Whether a given message was an
**attack that succeeded**, a **blocked attempt**, or a **benign edge case** usually requires correlating
the order (35=D/F/G/q/J) with the venue's response (ExecutionReport 35=8 `ExecType(150)`/`OrdStatus(39)`,
OrderCancelReject 35=9 `CxlRejReason(102)`, BusinessMessageReject 35=j `BusinessRejectReason(380)`). The
**oracle codes** that distinguish accepted-abuse from rejected-attempt are called out per vector:
`380=6` Not authorized, `380=8/9/10` throttle, `102=1` Unknown order. Application detections are the most
false-positive-prone in the whole catalogue, so the **benign-case analysis is the most load-bearing part
of each spec** and SAFIX should emit every APP finding with its confidence band and the correlating
response (or its absence) attached.

---

## 1. Summary table

Detection-method class: **C** = pure-config (static threshold / rule table, evaluable on one message),
**B** = baseline-learned (needs a per-instrument/per-session statistical baseline built from the log),
**X** = correlation/stateful (needs an order-ownership map, time window, or rate counter). Many are hybrids
(primary class first).

| ID | Name | Category | Stateful? | Needs baseline? | Method | Severity | Confidence |
|----|------|----------|-----------|-----------------|--------|----------|-----------|
| D01 | Negative / zero / sub-lot / huge `OrderQty(38)` | order-tampering | No (single msg) | Optional | C (+B) | High | High (neg/zero) · Med (huge) |
| D02 | Fat-finger / far-from-market `Price(44)` | order-tampering | No per-msg; needs ref price | Yes | B (+C) | High | Low-Med |
| D03 | Conditional-required field omission (StopPx, Price, SettlCurrency…) | order-tampering | No | No | C | High | High |
| D04 | "At-least-one" identifier omission (`11`/`37`/`2430`) | lifecycle | No | No | C | Med | High |
| D05 | Conflicting qty constraints `MinQty(110)`/`MaxFloor(111)`/`DisplayQty` vs `38` | order-tampering | No | No | C | Med | High |
| D06 | Dangerous but valid enum combos (`40`/`59`/`18`/`99`) | order-tampering | No (per-msg); liquidity needs B | Partial | C (+B) | Med/High | Med |
| D07 | `OrigClOrdID(41)` BOLA — cancel/replace a foreign order | authz-BOLA | **Yes** (ownership map) | No | X | **Critical** | High |
| D08 | `ClOrdID(11)` reuse / collision / sequential-guess | authz-BOLA / lifecycle | **Yes** (seen-ID set) | No | X | Med/High | Med |
| D09 | `Account(1)` substitution / omission | authz-BOLA | **Yes** (session↔acct map) | Entitlement cfg | X (+C) | High | High w/ map · Low w/o |
| D10 | Party spoofing via `453`/`448`/`452` | spoofing-manipulation / authz | Partly (entitlement) | Entitlement cfg | C (+X) | High | Med |
| D11 | Cancel-on-fill / replace-after-partial **race** | lifecycle | **Yes** (order state + window) | No | X | Med/High | Low-Med |
| D12 | Privilege / qty / price **escalation on replace** | order-tampering / lifecycle | **Yes** (order map) | Thresholds | X (+C) | High | Med |
| D13 | Spoofed / unsolicited `ExecutionReport(35=8)` | spoofing-manipulation | Partly (role cfg; unsolicited=X) | No | C (+X) | Med/High | High (direction) |
| D14 | `MarketDataRequest(V)` flood / huge `MarketDepth(264)` | market-data | **Yes** (rate counter) | Partial | X (+C) | Med | Med |
| D15 | `MDReqID(262)` hijack / foreign unsubscribe (`263=2`) | authz-BOLA (market-data) | **Yes** (MDReqID owner map) | No | X | Med/High | High w/ map |
| D16 | `Quote(S)`/`QuoteRequest(R)` abuse | market-data / manipulation | **Yes** (rate + ID map) | Yes (price) | X (+B) | Med | Low-Med |
| D17 | `Currency(15)` mismatch vs instrument | order-tampering | No | Reference data | C | Med | High w/ ref data |
| D18 | Stale / future `TransactTime(60)` | lifecycle / recordkeeping | No | No | C | Med | High (gross) · Med (skew) |
| D19 | Self-trade / wash-trade patterning | spoofing-manipulation | **Yes** (cross-side window) | Price window | X (+B) | High | Med |
| D20 | Order-rate / notional throttle breach | order-tampering (throttle) | **Yes** (rate/notional counter) | Limits cfg | X (+C) | Med/High | Med/High |
| D21 | `OrderMassCancelRequest(35=q)` scope abuse | lifecycle / authz | **Yes** (affected-order count) | No | C (+X) | Med/High | Med |
| D22 | Post-trade / allocation mis-booking (`J`/`AE`) | post-trade | **Yes** (fill↔alloc link) | Entitlement cfg | X (+C) | Med/High | Med |

**22 detections.** Source cross-reference: `AV-APP-01..20` (raw-agent-reports/APP.md) and `SV-APP-1..22`
(spec-derived/APP.md). D03/D04 realize the spec-derived prose-only conditional and at-least-one families
(SV-APP-3/4/5) that have no raw-agent equivalent.

**Method-class rollup (asked explicitly):**
- **Pure-config (C primary): D01, D03, D04, D05, D06, D13, D17, D18, D21** — 9 detections. Evaluable on a
  single message against a static rule table / threshold / reference-data map. Cheapest, most deterministic.
- **Baseline-learned (B primary): D02** — 1 detection (fat-finger price), because a meaningful price band
  requires a per-instrument reference price. D01/D06/D16/D19 use baselines as a *secondary* enrichment.
- **Correlation / stateful (X primary): D07, D08, D09, D11, D12, D14, D15, D16, D19, D20, D22** — 11
  detections. These are the authorization set, the lifecycle races, and the rate/pattern detectors; they
  need the order/session state model in §4.

---

## 2. Detection specifications

Each spec: **Vector IDs · Name · Category · Detection signal (tags + condition) · Statefulness · Baseline/
config dependence (+ defaults + tuning) · Severity · Confidence · True-positive signature · False-positive
sources · Oracle (correlating response)**.

---

### D01 — Negative / zero / sub-lot / oversized OrderQty(38)
- **Vector IDs:** AV-APP-01 / SV-APP-1 · **Category:** order-tampering
- **Detection signal:** On `35=D` (NewOrderSingle), `35=G` (Replace), and quote/order qty carriers, inspect
  `OrderQty(38)` (and `CashOrderQty(152)` / `OrderPercent(516)` where present):
  - `38 <= 0` → **hard flag** (negative or zero quantity; never legitimate).
  - `38` not an integer multiple of the instrument round-lot → **sub-lot flag** (if odd-lots disallowed for
    that instrument).
  - `38 > max_order_qty[instrument]` → **max-size flag**; and/or `38 * ref_price > max_order_notional` →
    **notional flag**.
- **Statefulness:** None required for the hard/config checks (single message). The statistical variant (see
  baseline) needs a per-instrument qty baseline built from the log.
- **Baseline/config dependence:** **Config-driven with optional baseline.**
  - *Defaults (equities):* round-lot = 100; `max_order_qty` fallback = **100,000 shares**;
    `max_order_notional` fallback = **$5,000,000**. For futures/FX, round-lot = 1 and limits are
    contract/notional-specific — must be set per product class.
  - *Baseline variant:* flag `38 > mean + 6σ` of that instrument's observed order sizes **or** `38 > 10×`
    the session/instrument 95th-percentile order size (whichever is larger), so a single venue-wide default
    doesn't drown legitimate size diversity.
  - *Tuning:* operator sets `max_order_qty` / `max_order_notional` per instrument (or per asset class) from
    the venue's published erroneous-order parameters; raises the σ multiplier for naturally bursty books.
- **Severity:** High · **Confidence:** High for `<=0`; Medium for "huge" (legit block trades exist).
- **True-positive signature:** `38<=0`, or `38` wildly above both the per-instrument cap and the learned
  distribution, especially from a session that otherwise trades normal sizes.
- **False-positive sources:** legitimate **block/program trades**, index rebalances, basket legs, and
  institutional parent orders that are genuinely large; **sub-lot** flags on instruments that *permit* odd
  lots; CashOrderQty-denominated orders where `38` is absent by design.
- **Oracle:** venue acceptance (ExecReport `150=0` New) vs rejection (`35=8 150=8` Rejected, or `35=j
  380=...`). An accepted `38<=0` is a definite control gap.

---

### D02 — Fat-finger / far-from-market Price(44)
- **Vector IDs:** AV-APP-02 / SV-APP-2 · **Category:** order-tampering
- **Detection signal:** On limit-type orders (`OrdType(40)` ∈ {2 Limit, 4 Stop-limit, …}) inspect
  `Price(44)` (and `StopPx(99)` for stops):
  - `44 <= 0` where the instrument is not a valid negative/zero-price product → **hard flag**.
  - `|44 − ref_price| / ref_price > collar_pct[instrument]` → **price-collar flag** (deviation from the
    reference price band).
  - `44 > absurd_high × ref_price` or `44 < absurd_low × ref_price` → **absurd-price flag** regardless of
    collar config.
- **Statefulness:** Needs a **per-instrument reference price**. SAFIX derives `ref_price` from the log
  itself — most recent `MDEntryPx(270)` (MarketDataSnapshot/Incremental, 35=W/X) for that `Symbol(55)`, or a
  trailing mean of executed `LastPx(31)` / last limit prices — or from static config. This is baseline
  state, not full order-book state.
- **Baseline/config dependence:** **Baseline-learned (primary) + config band.**
  - *Defaults:* static collar `collar_pct` = **±20%** fallback; **tighter ±5–10%** for liquid large-caps,
    **wider ±30–50%** for illiquid names. Absurd band: `absurd_high = 10×`, `absurd_low = 0.1×`.
  - *Dynamic variant:* flag `44` beyond **±6σ** of the recent trade/mid distribution for that instrument;
    final threshold = the **wider** of static collar and dynamic band (avoids firing on legitimately volatile
    books while still catching gross outliers).
  - *Tuning:* per-instrument `collar_pct`; choose the reference source (last trade vs mid vs config);
    widen for pre-open / auction periods where the reference is stale.
- **Severity:** High · **Confidence:** **Low–Medium** (the most FP-prone detection in the set).
- **True-positive signature:** limit price 1–3 orders of magnitude off a well-established reference, on a
  liquid instrument, during continuous trading.
- **False-positive sources:** **legitimate aggressive/marketable limits** priced through the book;
  **stale reference** (first order of the day, illiquid name, no recent MD in the log); **away-market
  pegging**; genuine **wide-spread** instruments; options/warrants with legitimately tiny prices; corporate
  actions resetting price scale. Never fire on a market order (`40=1`, no `44`).
- **Oracle:** accepted far-from-market limit (`150=0`) then immediate fill at a dislocated `LastPx(31)` is a
  true erroneous-execution; `150=8` Rejected = collar working.

---

### D03 — Conditional-required field omission
- **Vector IDs:** SV-APP-3 / SV-APP-4 · **Category:** order-tampering (order-parameter validation)
- **Detection signal:** Rule-table of (trigger field=value → dependent field required), evaluated per
  message. Ship with (spec-cited, Trade.txt):
  - `OrdType(40)` ∈ {3 Stop, 4 Stop-limit} → `StopPx(99)` **required** (Trade.txt:1216). Missing → flag.
  - `OrdType(40)` ∈ {2 Limit, 4 Stop-limit} → `Price(44)` required (Trade.txt:1209).
  - `ForexReq(121)=Y` → `SettlCurrency(120)` required (Trade.txt:1544).
  - `TimeInForce(59)=6 (GTD)` → `ExpireDate(432)` **or** `ExpireTime(126)` required.
  - `TimeInForce(59)=10` → `ExposureDuration(1629)` required (Trade.txt:1378).
  - short-sale `Side(54)` ∈ {5,6} → `LocateReqd(114)` present where required (Trade.txt:1193).
- **Statefulness:** None — single-message structural rule.
- **Baseline/config dependence:** **Pure config (rule table).** No numeric thresholds. Tuning = add/remove
  conditional rules per the venue's order API. These are *prose-only* conditionals absent from the
  machine-readable FIX repo, so repo-driven validators miss them — high-value, deterministic detections.
- **Severity:** High · **Confidence:** High (deterministic).
- **True-positive signature:** a Stop order (`40=3`) with no `99`; a GTD order with neither `432` nor `126`.
- **False-positive sources:** venue-specific dialects that legitimately default a missing field (e.g. a Stop
  that uses `Price(44)` as the trigger); custom OrdType extensions. Keep the rule table venue-scoped.
- **Oracle:** `35=j 380=5` (Conditionally Required Field Missing) = venue caught it; silent acceptance =
  a validation gap that lets an under-specified order reach matching.

---

### D04 — "At-least-one" identifier omission
- **Vector IDs:** SV-APP-5 · **Category:** lifecycle
- **Detection signal:** On order messages, require at least one of `ClOrdID(11)` / `OrderID(37)` /
  `OrderEntryID(2430)` (Trade.txt:2395-2403). All absent → flag. Also flag an **unexpected combination**
  (e.g. both `11` and `2430` with conflicting values) if the venue forbids it.
- **Statefulness:** None (single message). (Cross-message uniqueness is D08.)
- **Baseline/config dependence:** **Pure config** (cardinality rule). No thresholds.
- **Severity:** Med · **Confidence:** High.
- **True-positive signature:** `35=D` with no client/order identifier at all → unreferenceable order.
- **False-positive sources:** message types where the venue assigns the identifier (unsolicited cross,
  venue-originated orders); rare. Scope the rule to client-originated inbound flow.
- **Oracle:** `35=j 380=5` or `380=1` (Unknown ID) vs acceptance.

---

### D05 — Conflicting quantity constraints
- **Vector IDs:** AV-APP-03 / SV-APP-11 · **Category:** order-tampering
- **Detection signal:** Intra-message logical contradictions among the qty family:
  - `MinQty(110) > OrderQty(38)` → flag (min exceeds total).
  - `MaxFloor(111) > OrderQty(38)` or `DisplayQty(1138) > OrderQty(38)` → flag (display exceeds total —
    iceberg abuse).
  - `MinQty(110) > MaxFloor(111)` where both present and semantically coupled → flag.
- **Statefulness:** None — purely logical, single message. No threshold.
- **Baseline/config dependence:** **Pure config / logic** — nothing to tune except which fields the venue
  supports.
- **Severity:** Med · **Confidence:** High (logical contradiction is unambiguous).
- **True-positive signature:** `38=100 110=1000`.
- **False-positive sources:** minimal; some venues interpret `MaxFloor` relative to displayed vs total
  differently — confirm the venue's iceberg semantics before enabling the `111`/`1138` arm.
- **Oracle:** reject vs undefined handling (divergent behaviour across engines is itself the finding).

---

### D06 — Dangerous but grammatically-valid enum combinations
- **Vector IDs:** AV-APP-04 / SV-APP-10 · **Category:** order-tampering
- **Detection signal:** Combination rules over `OrdType(40)`, `TimeInForce(59)`, `ExecInst(18, multi-value)`,
  `Side(54)`, `99`, `432/126`:
  - `40=1 (Market)` + `59=4 (FOK)` + `38 > liquidity_ref[instrument]` → **liquidity-sweep flag**.
  - `40=1 (Market)` + `59=1 (GTC)` → suspicious (resting market order).
  - `59=6 (GTD)` with `ExpireDate(432)`/`ExpireTime(126)` **in the past** → flag.
  - conflicting `ExecInst(18)` flags in one list (e.g. both participate-don't-initiate and aggressive) → flag.
- **Statefulness:** Per-message for most; the liquidity-sweep arm needs a per-instrument liquidity/volume
  baseline (from MD or traded volume in the log).
- **Baseline/config dependence:** **Config rule table (primary) + optional liquidity baseline.** Default
  `liquidity_ref` = the instrument's recent average displayed depth or a fraction (e.g. 50%) of trailing
  per-minute volume; tune per instrument.
- **Severity:** Med/High · **Confidence:** Med (combo-dependent: Stop-without-StopPx≈high via D03;
  Market+FOK-huge is contextual).
- **True-positive signature:** `40=1 59=4 38=100000000` on a thin book.
- **False-positive sources:** **legitimate IOC/FOK sweeps** by liquidity-taking strategies; GTD with a past
  date due to **timezone/day-boundary** rounding; multi-flag ExecInst that the venue genuinely supports.
- **Oracle:** fill that sweeps multiple levels / self-induced halt vs rejection.

---

### D07 — OrigClOrdID(41) BOLA: cancel/replace a foreign order
- **Vector IDs:** AV-APP-05 / SV-APP-6 · **Category:** authz-BOLA
- **Detection signal:** On `35=F` (OrderCancelRequest) / `35=G` (OrderCancelReplaceRequest), take
  `OrigClOrdID(41)` and look it up in the **order-ownership map**. If the referenced order's **owning
  session** (originating `SenderCompID(49)` / session identity) **differs from the current message's
  session** → **BOLA flag**. Strengthen when the foreign `41` is **sequential/guessable** relative to the
  attacker's own ClOrdID series.
- **Statefulness:** **Stateful — core.** Requires the order-ownership map (§4): every `ClOrdID(11)` seen on
  an inbound order recorded with its owning session + instrument + current state. The F/G is matched against
  that map.
- **Baseline/config dependence:** None (no thresholds). Depends only on the ownership map being populated
  (i.e. SAFIX must have seen the original order in the log, or multiple sessions' logs).
- **Severity:** **Critical** · **Confidence:** High when the ownership map is complete; Low if the original
  order wasn't observed (then it's an unresolved reference, not confirmed cross-session).
- **True-positive signature:** session B sends `35=G 41=<ClOrdID first issued by session A>` and receives
  `150=5` (Replaced) / `150=4` (Canceled) — i.e. it **acted on an order it did not place**.
- **False-positive sources:** **legitimate order-routing / give-up / OMS relay** where one session manages
  orders on behalf of another by arrangement; **drop-copy** sessions; **care/desk** workflows where a broker
  session legitimately cancels a client's order; ClOrdID-chaining where the "foreign" ID is actually the same
  logical owner under a different CompID by design. SAFIX must let operators declare **trusted
  session-groups** that share an ownership namespace (see config `session_ownership_groups`).
- **Oracle:** `380=6` Not authorized or `102=1` Unknown order = venue bound ownership correctly (attempt
  blocked); success (`150=4/5`) on a cross-session reference = **confirmed BOLA**.

---

### D08 — ClOrdID(11) reuse / collision / sequential-guess
- **Vector IDs:** AV-APP-06 / SV-APP-7 · **Category:** authz-BOLA (enabler) / lifecycle
- **Detection signal:** Maintain a **seen-ClOrdID set per session (per trading day)**.
  - `11` already seen in-session (and not a permitted chaining reference) → **reuse/collision flag**.
  - `11` sequence is **monotonic/predictable** (integer++ or timestamp+counter) across a session → **
    guessable-ID flag** (feeds D07 risk).
  - same `11` appearing under **two different sessions** → **namespace-collision flag**.
- **Statefulness:** **Stateful** — per-session seen-ID set + simple sequence-pattern analysis.
- **Baseline/config dependence:** No numeric threshold; the predictability check is heuristic (regex/
  arithmetic-progression test). Tunable: day-boundary reset, whether chaining re-use is allowed.
- **Severity:** Med/High · **Confidence:** Med.
- **True-positive signature:** duplicate `11=dup` on two `35=D` in one session; or a perfectly sequential
  ClOrdID series that an attacker could enumerate.
- **False-positive sources:** **legitimate session-level resend/retransmission** (same ClOrdID re-sent after
  a gap-fill), **PossDupFlag(43)=Y** retransmits, and **naturally sequential** ClOrdID generators used by
  well-behaved clients (predictability ≠ attack by itself — rate this *informational* unless paired with a
  D07 hit).
- **Oracle:** duplicate-order rejection vs duplicate acceptance (two live orders from one `11`).

---

### D09 — Account(1) substitution / omission
- **Vector IDs:** AV-APP-07 / SV-APP-8 · **Category:** authz-BOLA
- **Detection signal:** Compare `Account(1)` on each inbound order against the set of accounts the **owning
  session is entitled to**. `1` ∉ entitlement[session] → **substitution flag**. `1` absent where required →
  **omission flag** (order hits a default account).
- **Statefulness:** **Stateful + config.** Needs a session→allowed-accounts entitlement map. SAFIX can
  **learn** a provisional map (the set of accounts each session normally uses in the log) and flag
  first-time/rare account use, but authoritative detection needs the operator's entitlement config.
- **Baseline/config dependence:** **Entitlement config (authoritative) or learned baseline (provisional).**
  Tuning: supply `session_account_entitlements`; set a learning window and a "new account = alert" toggle.
- **Severity:** High · **Confidence:** High with an authoritative map; Low with learned-only (a legitimate
  new account looks identical to a substitution).
- **True-positive signature:** session CLIENTA sends `1=FIRM-PROP` (an account belonging to another entity)
  and the order is accepted.
- **False-positive sources:** **legitimate multi-account** traders, new-account onboarding, **omnibus/sub-
  account** structures, give-up accounts; a learned map will flag every genuinely new account.
- **Oracle:** `380=6` Not authorized vs acceptance/booking under the foreign account.

---

### D10 — Party spoofing via NoPartyIDs(453)/PartyID(448)/PartyRole(452)
- **Vector IDs:** AV-APP-08 / SV-APP-9 · **Category:** spoofing-manipulation / authz
- **Detection signal:** Walk the `NoPartyIDs(453)` repeating group. For each `(PartyID(448),
  PartyIDSource(447), PartyRole(452))`:
  - role `452=1` ExecutingFirm / `452=4` ClearingFirm / `452=3` ClientID whose `448` is **not in the
    session's allowed party set** → **spoofing flag**.
  - executing/clearing party **inconsistent** with the session identity (claims a different firm) → flag.
  - MiFID II **short-code** roles (investment-decision/execution-within-firm) present but malformed/empty
    → recordkeeping-integrity flag.
- **Statefulness:** Mostly per-message against a session→allowed-parties map (config/entitlement); optional
  learned baseline of normal party tuples per session.
- **Baseline/config dependence:** **Entitlement config (session→parties) + rule.** Defaults: none numeric;
  operator supplies allowed `448` values per role per session. Learned variant flags first-seen party tuples.
- **Severity:** High · **Confidence:** Med (benign give-up/clearing arrangements are common).
- **True-positive signature:** a client session asserting `452=1 448=OTHERFIRM` (executing-firm it is not).
- **False-positive sources:** **legitimate give-up** (executing vs clearing firm genuinely differ),
  agency/broker-of-record flows, correspondent clearing, and multi-role institutional setups where many
  party tuples are legitimate. Requires the entitlement map to be meaningful.
- **Oracle:** `380=6` vs acceptance with the spoofed attribution persisting into the ExecReport/clearing.

---

### D11 — Cancel-on-fill / replace-after-partial race (TOCTOU)
- **Vector IDs:** AV-APP-09 / SV-APP-12 · **Category:** lifecycle
- **Detection signal:** Correlate, per order (keyed by `11`/`41` chain), the sequence and timing of
  inbound `35=F`/`35=G` against the venue's outbound `35=8` fills:
  - inbound `35=F` (cancel) arriving within `race_window_ms` of an outbound partial/full fill
    (`150=1` Partial / `150=F` Trade) for the same order → **cancel-on-fill race flag**.
  - inbound `35=G` **increasing** `38` within `race_window_ms` after a `150=1` partial → **replace-after-
    partial flag** (qty inflation racing the fill).
- **Statefulness:** **Stateful — core.** Needs per-order state (working / partial-filled / filled, cumulative
  `CumQty(14)`/`LeavesQty(151)`) and a time window over interleaved in/out messages.
- **Baseline/config dependence:** `race_window_ms` config. **Default 50 ms** (tune to the venue's observed
  ack latency; too wide → FP, too narrow → misses).
- **Severity:** Med/High · **Confidence:** **Low–Med** (cancel/replace near a fill is routine order
  management).
- **True-positive signature:** repeated, tightly-timed cancel/replace-up immediately after each partial, in
  a pattern that over-fills or inflates exposure beyond the initial checked size.
- **False-positive sources:** **ordinary cancel/replace** activity, legitimate chasing of the market,
  algo re-pricing on every partial, and normal latency jitter. Only elevate when combined with D12
  (escalation) or an observed over-fill (`CumQty > original 38`).
- **Oracle:** over-fill (`14` exceeding the pre-trade-checked quantity) or a double-action on one order.

---

### D12 — Privilege / quantity / price escalation on replace
- **Vector IDs:** AV-APP-10 / SV-APP-13 · **Category:** order-tampering / lifecycle
- **Detection signal:** For each `35=G`, retrieve the original order from the order map (via
  `OrigClOrdID(41)` chain) and compare:
  - new `38` ≫ original `38` (ratio > `replace_qty_ratio`) **and** the new `38` would breach a D01 limit
    the original passed → **escalation flag**.
  - new `44`/`99` moves **outside** the D02 collar the original satisfied → **price-escalation flag**.
  - replace changes `Account(1)` / party tuple / `Side(54)` / `Symbol(55)` (fields that should be immutable
    on amend) → **privilege/identity-escalation flag**.
- **Statefulness:** **Stateful — core.** Needs the original order's checked qty/price/identity in the map to
  diff against the replacement. This is the "controls must apply to modifications too" test (ESMA: a control
  bypassable by post-check replace is a finding against RTS 6 Art 15).
- **Baseline/config dependence:** `replace_qty_ratio` **default 10×**; price arm reuses D02 collar; identity
  arm is pure logic. Tune the ratio per asset class.
- **Severity:** High · **Confidence:** Med.
- **True-positive signature:** `35=D 38=100` (passes), then `35=G 41=o 38=100000000 44=0.01` — a size/price
  that would have been rejected as a *new* order is accepted on amend.
- **False-positive sources:** **legitimate order growth** (clients routinely replace up as they work a
  parent order), re-pricing, and reload strategies; most replaces increase size. The discriminating signal
  is that the replaced value **crosses a hard limit the original respected** — not mere growth.
- **Oracle:** replace accepted (`150=5`) at a value that a fresh order at the same value gets rejected for =
  **confirmed control-bypass-on-amend**.

---

### D13 — Spoofed / unsolicited ExecutionReport(35=8)
- **Vector IDs:** AV-APP-11 / SV-APP-17 · **Category:** spoofing-manipulation
- **Detection signal:** Direction/role rule: a `35=8` ExecutionReport (or `35=9` OrderCancelReject) whose
  **direction is client→venue** (SenderCompID = a client session that is not entitled to originate execution
  reports) → **direction-violation flag**. Secondary: an ExecReport referencing an `OrderID(37)`/`ClOrdID(11)`
  with **no matching order** in the map, or a fill (`150=F`) with no preceding order → **unsolicited/fabricated
  fill flag**.
- **Statefulness:** The direction arm is per-message against session-role config; the unsolicited-fill arm is
  stateful (needs the order map to confirm no originating order).
- **Baseline/config dependence:** **Config (session roles: which sessions may emit 35=8).** No thresholds.
- **Severity:** Med/High (role-dependent) · **Confidence:** High for the direction rule (a pure client
  should never send `35=8`).
- **True-positive signature:** a client-role session emits `35=8 150=2 39=2` (fabricated full fill) toward a
  downstream OMS.
- **False-positive sources:** **drop-copy / order-routing / broker hub** sessions that legitimately relay or
  originate ExecReports; venue-as-client bidirectional hubs. Must be scoped by the session's declared role.
- **Oracle:** downstream OMS booking a fill that has no corresponding venue execution.

---

### D14 — MarketDataRequest(V) flood / huge MarketDepth(264)
- **Vector IDs:** AV-APP-12 / SV-APP-15 · **Category:** market-data
- **Detection signal:** On `35=V` (MarketDataRequest):
  - count distinct `MDReqID(262)` with `SubscriptionRequestType(263)=1` (snapshot+updates) per session per
    second; rate > `md_req_rate_limit` → **flood flag**.
  - `MarketDepth(264)=0` (full book) on many symbols, or an aggregate subscription count >
    `md_subscription_cap` → **amplification flag**.
- **Statefulness:** **Stateful** — per-session MD request-rate counter and live-subscription count.
- **Baseline/config dependence:** **Config limits + rate counter.** Defaults: `md_req_rate_limit` =
  **20 requests/sec/session**; `md_subscription_cap` = **500 concurrent full-depth subscriptions/session**.
  Tune to the MD gateway's capacity.
- **Severity:** Med · **Confidence:** Med.
- **True-positive signature:** a burst of hundreds of `35=V 263=1 264=0` across symbols, one session.
- **False-positive sources:** **legitimate market-data vendors / aggregators** that genuinely subscribe
  broadly; startup re-subscription storms after reconnect; index/ETF arbitrage desks tracking many names.
- **Oracle:** `380=8/9/10` throttle responses, or MD-gateway resource symptoms.

---

### D15 — MDReqID(262) hijack / foreign unsubscribe
- **Vector IDs:** AV-APP-13 / SV-APP-16 · **Category:** authz-BOLA (market-data)
- **Detection signal:** On `35=V` with `SubscriptionRequestType(263)=2` (Unsubscribe), look up `MDReqID(262)`
  in the **MD-subscription ownership map**. If the referenced subscription's owning session ≠ current session
  → **MD-BOLA flag**.
- **Statefulness:** **Stateful — core.** Map each `262` (from `263=1`) to its owning session; match the
  unsubscribe against it.
- **Baseline/config dependence:** None (no thresholds); depends on the ownership map and (like D07) a
  `session_ownership_groups` config for legitimately shared namespaces.
- **Severity:** Med/High · **Confidence:** High when the map is complete.
- **True-positive signature:** session B sends `263=2 262=<reqID owned by session A>` and A's feed stops —
  a DoS on a competitor's data.
- **False-positive sources:** shared MD-management sessions; aggregator sessions that manage subscriptions on
  behalf of others by arrangement.
- **Oracle:** the targeted feed terminating / `380=6` Not authorized.

---

### D16 — Quote(S) / QuoteRequest(R) abuse
- **Vector IDs:** AV-APP-14 · **Category:** market-data / manipulation
- **Detection signal:** On `35=R` (QuoteRequest) / `35=S` (Quote):
  - QuoteRequest rate per session > `quote_req_rate_limit` → **quote-flood flag**.
  - `35=S` with `BidPx(132)`/`OfferPx(133)` outside the D02 collar → **erroneous-quote flag**.
  - `35=S`/`35=R` referencing a `QuoteID(117)`/`QuoteReqID(131)` owned by another session → **cross-reference
    flag** (uses the ownership-map machinery of D07/D15).
- **Statefulness:** **Stateful** — quote-ID ownership map + rate counter; price arm uses the D02 baseline.
- **Baseline/config dependence:** `quote_req_rate_limit` **default 50/sec/session**; price band reuses D02.
- **Severity:** Med · **Confidence:** Low–Med.
- **True-positive signature:** sustained quote-request floods, or quotes priced grossly off-market, or a
  foreign QuoteID reference.
- **False-positive sources:** **market makers** whose entire job is high-rate two-sided quoting and frequent
  requoting; RFQ workflows; legitimate wide quotes in illiquid names.
- **Oracle:** quote-engine throttle (`380=8/9/10`) or cross-reference rejection.

---

### D17 — Currency(15) mismatch vs instrument
- **Vector IDs:** AV-APP-15 / SV-APP-18 · **Category:** order-tampering
- **Detection signal:** Compare `Currency(15)` (and `SettlCurrency(120)`) on the order against the
  instrument's **native currency** from reference data (keyed by `Symbol(55)` / `SecurityID(48)`+
  `SecurityIDSource(22)`). Mismatch → flag (possible notional/credit miscalculation).
- **Statefulness:** None — single message against a reference-data map.
- **Baseline/config dependence:** **Reference data (instrument→currency map).** No thresholds. Tuning =
  supply/maintain the instrument reference file; optionally allow a whitelist of legitimate cross-currency
  pairs (ADR/dual-listed).
- **Severity:** Med · **Confidence:** High when reference data is present; otherwise cannot fire.
- **True-positive signature:** `55=IBM 15=JPY` where IBM trades in USD.
- **False-positive sources:** **dual-listed / cross-listed** securities, ADRs/GDRs, instruments that
  genuinely trade in multiple currencies, and `SettlCurrency` legitimately differing from trade currency
  (FX settlement). Whitelist these.
- **Oracle:** rejection vs acceptance with a mis-valued notional in the credit check.

---

### D18 — Stale / future TransactTime(60)
- **Vector IDs:** AV-APP-16 / SV-APP-19 · **Category:** lifecycle / recordkeeping
- **Detection signal:** Compare `TransactTime(60)` against `SendingTime(52)` (and/or log arrival time):
  - `52 − 60 > stale_threshold` → **stale flag** (business time far behind transmission).
  - `60 − 52 > future_threshold` → **future-dated flag**.
  - `60` at an absurd epoch (e.g. `19700101-…`, or year ≫ current) → **hard flag**.
- **Statefulness:** None — single message (uses the message's own `52`).
- **Baseline/config dependence:** **Pure config thresholds.** Defaults aligned to RTS 25 tolerances:
  `stale_threshold` = **1 second** (non-HFT electronic) / **100 µs** (HFT sessions); `future_threshold` =
  **1 second** (any positive clock-ahead beyond tolerance is suspect). Tune per session class.
- **Severity:** Med · **Confidence:** High for gross (epoch/far-future); Med for small skews (clock drift).
- **True-positive signature:** `60=19700101-00:00:00` on a live order; or `60` hours in the future.
- **False-positive sources:** **legitimate clock drift** within tolerance, timezone-mislabeled-but-benign
  stamps, store-and-forward / batch submissions where business time legitimately precedes send time (e.g.
  staged orders released later). Distinguish RTS 25 tolerance breaches from gross manipulation by magnitude.
- **Oracle:** venue business-time rejection vs acceptance (and audit-trail timestamp distortion downstream).

---

### D19 — Self-trade / wash-trade patterning
- **Vector IDs:** AV-APP-17 / SV-APP-21 · **Category:** spoofing-manipulation
- **Detection signal:** Within a sliding time window per instrument, detect a **buy** (`Side(54)=1`) and a
  **sell** (`Side(54)=2`) from the **same or affiliated identity** (matching `Account(1)`, or matching
  `PartyID(448)` for a configured role, or same session-group) at **overlapping/crossing prices**
  (buy `44` ≥ sell `44`) and comparable sizes → **wash/self-trade flag**. Strongest signal: an actual
  execution (`35=8 150=F`) where both sides trace to the same identity.
- **Statefulness:** **Stateful — core.** Needs a per-instrument, per-identity window of resting/recent
  opposite-side orders, plus the price-overlap test.
- **Baseline/config dependence:** `wash_window_ms` **default 1000 ms**; `price_overlap` = crossing or within
  **±1 tick**; identity-affiliation set from `session_ownership_groups` / account-grouping config.
- **Severity:** High · **Confidence:** Med (market-maker two-sided quoting is the dominant benign case).
- **True-positive signature:** same `Account` buying and selling the same symbol at the same price within the
  window, resulting in a self-match — classic wash trade (MAR).
- **False-positive sources:** **market makers / designated liquidity providers** legitimately quoting both
  sides continuously; **agency crosses** between two genuinely different clients under one firm; internal
  transfers; different strategies under one account with no intent to self-match. Self-Trade-Prevention
  configuration (which the venue *should* enforce) and affiliation grouping are what separate abuse from
  normal two-sided activity — so emit with the affiliation basis attached.
- **Oracle:** an execution where both the aggressor and resting side resolve to the same/affiliated identity
  (STP failure) = confirmed self-trade.

---

### D20 — Order-rate / notional throttle breach
- **Vector IDs:** AV-APP-18 / SV-APP-20 · **Category:** order-tampering (throttle)
- **Detection signal:** Per-session rolling counters:
  - inbound order messages (`35=D`/`F`/`G`) per second > `msg_rate_limit` → **rate-breach flag**.
  - cumulative open notional (Σ `38 × ref_price` of working orders) > `max_open_notional` → **notional-breach
    flag**.
  - new-order count per rolling window > `max_orders_per_window` → **order-count-breach flag**.
- **Statefulness:** **Stateful — core.** Rolling rate/notional counters over the message stream per session.
- **Baseline/config dependence:** **Config limits + counters.** Defaults: `msg_rate_limit` =
  **100 msgs/sec/session**; `max_orders_per_window` = **500 / 1 s`; `max_open_notional` = **$10,000,000**/
  session. Tune to the agreed throttle in the client's venue agreement.
- **Severity:** Med/High · **Confidence:** Med/High (rate is objective; the "limit" must match the agreement).
- **True-positive signature:** a valid-order burst ramping past the agreed per-second throttle.
- **False-positive sources:** **legitimate HFT / algo** bursts within an agreed high limit; news-driven
  activity spikes; a default limit set below the client's actual entitlement (tune per session).
- **Oracle:** `380=8` (Throttle exceeded) → `380=9` (will disconnect) → `380=10` (throttled messages
  rejected). Seeing orders accepted *past* the stated limit = throttle not enforced.

---

### D21 — OrderMassCancelRequest(35=q) scope abuse
- **Vector IDs:** AV-APP-19 / SV-APP-14 · **Category:** lifecycle / authz
- **Detection signal:** On `35=q`, inspect `MassCancelRequestType(530)`:
  - `530=7` (Cancel all) or other broad scopes beyond the session's permitted scope → **over-broad flag**.
  - correlate the resulting mass-cancel ExecReports / `OrderMassCancelReport(35=r)` — if orders belonging to
    **other sessions** are cancelled → **cross-session kill flag** (authz).
- **Statefulness:** The scope rule is per-message (config); the cross-session-impact arm is stateful (count
  how many foreign orders the cancel touched, via the ownership map).
- **Baseline/config dependence:** **Config (allowed mass-cancel scopes per session).** No numeric threshold;
  optionally alert when a single `35=q` cancels > `mass_cancel_alert_count` orders (**default 100**).
- **Severity:** Med/High · **Confidence:** Med.
- **True-positive signature:** a client session issuing `530=7` cancel-all that reaches orders it doesn't own.
- **False-positive sources:** **legitimate kill-switch / panic-cancel** use (cancel-all is a *required* RTS 6
  Art 12 feature — a client cancelling *its own* book is expected); end-of-day flatten; risk-desk mass cancel.
  The finding is scope reaching *foreign* orders or exceeding the session's authorized scope — not mass-cancel
  per se.
- **Oracle:** `35=r` MassCancelReport with `MassCancelResponse(531)` and the set of affected orders; `380=6`
  for an unauthorized scope.

---

### D22 — Post-trade / allocation mis-booking (AllocationInstruction J / TradeCaptureReport AE)
- **Vector IDs:** AV-APP-20 / SV-APP-22 · **Category:** post-trade
- **Detection signal:**
  - On `35=J` (AllocationInstruction), walk `NoAllocs(78)` / `AllocAccount(79)`: any `79` ∉ the submitting
    session's entitled accounts → **mis-allocation flag**; Σ `AllocQty(80)` ≠ the trade's executed qty →
    **allocation-imbalance flag**.
  - On `35=AE` (TradeCaptureReport): a report referencing a trade/exec with **no matching execution** in the
    map, or altering `SettlDate(64)`/`Currency(15)`/price vs the originating fill → **TCR injection/alteration
    flag**.
- **Statefulness:** **Stateful — core.** Needs the fill record (from ExecReports) to link allocations/TCRs
  back to a real execution, plus the account-entitlement map.
- **Baseline/config dependence:** **Entitlement config (session→accounts) + execution map.** No thresholds.
- **Severity:** Med/High · **Confidence:** Med.
- **True-positive signature:** `35=J … 79=OTHERACCT` allocating a fill to an account the session doesn't
  control; or a TCR with no underlying execution.
- **False-positive sources:** **legitimate give-up / block allocation** across many sub-accounts (the normal
  purpose of `J`), average-price bookings, step-outs, and corrections/amendments (`35=AE` with a correction
  flag). Entitlement grouping is essential.
- **Oracle:** AllocationReport (`35=P`) `AllocStatus(87)` accept/reject; booking under a foreign account =
  confirmed mis-booking.

---

## 3. Regulatory mapping table

Detection → **SEC Rule 15c3-5** clause → **MiFID II RTS 6** clause → **control under test**. (15c3-5
structure: `(c)(1)` financial risk controls — `(i)` credit/capital aggregate, `(ii)` erroneous-order &
duplicative; `(c)(2)` regulatory risk controls — `(i)` pre-order regulatory compliance, `(ii)` restricted
securities, `(iii)` access restricted to authorized persons/accounts, `(iv)` immediate post-trade reports
to surveillance; `(b)` controls under the BD's direct & exclusive control; `(e)` documented annual review.)

| Det | 15c3-5 clause | RTS 6 clause | Control under test |
|-----|---------------|--------------|--------------------|
| D01 Qty bounds | (c)(1)(ii) erroneous size; (c)(1)(i) credit/capital (huge) | Art 15 — max order volume / value | Max-order-size hard block |
| D02 Fat-finger price | (c)(1)(ii) erroneous price parameters | Art 15 — price collar | Price-collar / reference-band hard block |
| D03 Conditional-required omission | (c)(1)(ii) erroneous; (c)(2)(i) pre-order compliance | Art 15 — order-parameter validation | Completeness of order validation |
| D04 At-least-one identifier | (c)(2)(i) pre-order compliance | Art 15; (recordkeeping RTS 24) | Order identifiability / audit integrity |
| D05 Qty-constraint conflict | (c)(1)(ii) erroneous | Art 15 — order-parameter validation | Intra-order constraint validation |
| D06 Dangerous enum combos | (c)(1)(ii) erroneous; (c)(1)(i) aggregate (sweep) | Art 15 — order-type risk controls | Order-type / TIF risk control |
| D07 OrigClOrdID BOLA | (c)(2)(iii) access to authorized only; **(b)** direct/exclusive control | Art 18 identity & access mgmt; Art 20–21 DEA per-client segregation | Object-level authorization (order ownership binding) |
| D08 ClOrdID reuse | (c)(1)(ii) **duplicative orders** | Art 15 — duplicate-order check | Duplicate / predictable-ID detection |
| D09 Account substitution | (c)(2)(iii) authorized accounts | Art 18; Art 21 per-client limits | Account entitlement / access control |
| D10 Party spoofing | (c)(2)(iii) access; (c)(2)(i) regulatory (short codes) | Art 18; MiFIR RTS 24 party identification | Identity integrity in the order/clearing record |
| D11 Cancel/replace race | (c)(1)(i) aggregate exposure (concurrency) | Art 15 + Art 16 real-time monitoring | Controls hold under concurrency (TOCTOU) |
| D12 Escalation-on-replace | (c)(1)(ii)+(i) controls apply to modifications; **(b)** non-bypassable | Art 15 — hard block (ESMA: not bypassable by post-check replace) | Re-validation on amend |
| D13 Spoofed ExecReport | (c)(2)(iv) exec reports to surveillance; **(b)** direct control | Art 18 authenticity; Art 16 monitoring | Message direction/role enforcement; exec-report authenticity |
| D14 MD flood / huge depth | (capacity — weak 15c3-5 nexus) | Art 15 — max message limit; (RTS 7 capacity) | Message-rate / subscription capacity throttle |
| D15 MDReqID hijack | (c)(2)(iii) access | Art 18; Art 21 segregation | Object-level authz on MD subscriptions |
| D16 Quote abuse | (c)(1)(ii) erroneous; rate | Art 15 — throttle; Art 13 surveillance | Quote throttle / erroneous-quote / cross-ref authz |
| D17 Currency mismatch | (c)(1)(i) credit/capital computation integrity | Art 15 / Art 17 | Notional & credit-calc integrity |
| D18 Stale/future TransactTime | (c)(2)(i) regulatory; recordkeeping | Art 18 traceability; **RTS 25** clock sync | Timestamp/clock integrity; replay-window |
| D19 Wash / self-trade | (c)(2)(i) regulatory (MAR) | Art 13 automated surveillance (+ STP) | Self-trade prevention & manipulation surveillance |
| D20 Rate/notional throttle | (c)(1)(i) aggregate; (c)(1)(ii) over a period | Art 15 — max message limit & repeated-execution throttle | Rate / notional throttle enforcement |
| D21 Mass-cancel scope | **(b)** direct/exclusive control | **Art 12 kill functionality** (scope); Art 18 access | Kill-switch scope & authorization |
| D22 Post-trade mis-booking | (c)(2)(iv) post-trade reports; (c)(2)(iii) access | Art 17 post-trade controls; Art 18; MiFIR RTS 22 | Post-trade record integrity & allocation authz |

**Coverage of the top regulatory controls:** the detection set exercises **RTS 6 Art 15 pre-trade hard
blocks** (price collar, max order value/volume, max message limit, repeated-execution throttle) via
D01/D02/D03/D05/D06/D12/D16/D20; **Art 18 security & access + DEA Art 20–21 per-client segregation** (the
object-level authorization set) via D07/D09/D10/D13/D15; **Art 12 kill functionality** via D21; **Art 13/16
surveillance & real-time monitoring** via D19/D11; **Art 17 post-trade** via D22; and **RTS 25 clock sync**
via D18. On the US side this is **15c3-5(c)(1)(ii) erroneous-order**, **(c)(1)(i) credit/capital aggregate**,
**(c)(2)(iii) access control**, and **(b) direct & exclusive, non-bypassable control** (the escalation-on-
replace test D12 directly probes the ESMA "cannot be bypassed by crafting the FIX message directly" clause).

---

## 4. ORDER/SESSION STATE MODEL FOR APP DETECTIONS

To support the stateful detections (D07, D08, D09, D11, D12, D14, D15, D16, D19, D20, D21, D22), SAFIX must
build the following in-memory model by replaying the log(s) in timestamp order. QuickFIX writes one log per
session; SAFIX ingests **all** session logs for a venue together so cross-session references (BOLA) resolve.

### 4.1 Session registry
Keyed by session id (from the log filename / header `49`+`56`+`BeginString`):
```
Session { sessionId, senderCompID, targetCompID, role (client|venue|drop-copy|aggregator),
          ownershipGroup, entitledAccounts[], entitledParties[{role,partyId}],
          class (normal|HFT),  // drives RTS 25 tolerance & throttle defaults
          counters: { msgRateWindow, orderCountWindow, openNotional } }
```
Direction of each message is derived by matching `49`/`56` against the session identity.

### 4.2 Order map (the core structure) — keyed by ClOrdID
```
Order { clOrdID,            // tag 11 (and chain of OrigClOrdID 41 → clOrdID)
        orderID,            // tag 37 (venue-assigned, once seen on 35=8)
        owningSession,      // session that first submitted this clOrdID  ← ownership for D07
        account,            // tag 1
        parties[],          // NoPartyIDs 453 group tuples
        symbol,             // tag 55 (+ 48/22)
        side,               // tag 54
        ordType, tif,       // tags 40, 59
        origQty, curQty,    // tag 38 at new vs latest replace  ← diff for D12
        price, stopPx,      // tags 44, 99                       ← diff for D12
        cumQty, leavesQty,  // tags 14, 151 (from ExecReports)   ← D11 over-fill
        state,              // New|PartiallyFilled|Filled|Canceled|Replaced|Rejected (39/150)
        checkedQty,checkedPx,// value that passed pre-trade check  ← escalation baseline (D12)
        tHistory[] }        // (msgType, direction, SendingTime, TransactTime) for race timing (D11)
```
- **Ownership** = `owningSession` set on the first inbound `35=D` carrying a given `ClOrdID`. A later
  `35=F`/`35=G` whose `OrigClOrdID(41)` resolves to an order with a *different* `owningSession` (and the two
  sessions are not in the same `ownershipGroup`) → **D07 BOLA**.
- **ClOrdID chain:** `35=G` creates a new `ClOrdID` linked to the prior via `41`; SAFIX threads these so the
  order's full lifecycle (and its original checked qty/price) is one logical object.

### 4.3 Seen-ID sets (D08)
Per session per day: `Set<ClOrdID>` plus a lightweight sequence-pattern detector (arithmetic/timestamp
progression) for guessability scoring.

### 4.4 Market-data subscription map (D14, D15, D16)
```
MDSub { mdReqID (262), owningSession, symbols[], depth (264), subType (263) }
Quote { quoteID (117)/quoteReqID (131), owningSession }
```
Unsubscribe (`263=2`) / quote cross-reference checked against `owningSession`.

### 4.5 Per-instrument baselines (D01 stat variant, D02, D06 liquidity, D16, D19)
```
InstrumentBaseline { symbol,
   refPrice,            // latest MDEntryPx(270) or trailing mean LastPx(31)
   priceDist (μ,σ),     // for ±Nσ collar
   qtyDist (μ,σ,p95),   // for max-size statistical flag
   liquidityRef,        // avg displayed depth / trailing per-minute volume
   nativeCurrency }     // reference data for D17
```

### 4.6 Rate / notional counters (D20, D14, D16)
Rolling-window counters per session: messages/sec, new-orders/window, cumulative open notional
(Σ working `38 × refPrice`).

### 4.7 Cross-side window (D19) and race window (D11)
Time-ordered, per-instrument buffer of recent opposite-side orders (for wash detection) and a per-order
interleaving of inbound F/G vs outbound fills within `race_window_ms`.

### 4.8 Execution / allocation linkage (D13, D22)
Executions (`35=8 150=F`) recorded with `OrderID`/`ExecID`; allocations (`35=J`) and trade-capture reports
(`35=AE`) must link back to a recorded execution and to an entitled account, else flagged as
fabricated/mis-booked.

---

## 5. CONFIG SCHEMA FOR THRESHOLDS

Proposed tunable parameters with sensible defaults. Scope precedence: **per-instrument** → **per-asset-class**
→ **global default**. Entitlement/reference maps are supplied by the operator (authoritative) or learned from
the log (provisional, lower confidence).

```yaml
safix_app:
  # ---- D01 order size ----
  order_qty:
    round_lot:            { equities: 100, futures: 1, fx: 1 }     # sub-lot detection
    max_order_qty:        { default: 100000 }                      # per-instrument override expected
    max_order_notional:   { default: 5_000_000 }                   # USD; used when no qty cap
    stat_sigma:           6        # flag qty > mean + Nσ
    stat_p95_multiple:    10       # or qty > 10× instrument 95th pct
    hard_reject_nonpositive: true  # 38 <= 0 always flags

  # ---- D02 fat-finger price ----
  price_collar:
    default_pct:          0.20     # ±20% from reference
    liquid_pct:           0.10     # large-caps
    illiquid_pct:         0.40
    absurd_high_multiple: 10       # >10× ref → hard flag
    absurd_low_multiple:  0.1      # <0.1× ref → hard flag
    dynamic_sigma:        6        # ±6σ dynamic band; effective = max(static, dynamic)
    reference_source:     last_trade   # last_trade | mid | config
    hard_reject_nonpositive: true

  # ---- D03/D04/D05 structural rules ----
  conditional_required:  [ { if: "40 in [3,4]", need: 99 },
                           { if: "40 in [2,4]", need: 44 },
                           { if: "121=Y",       need: 120 },
                           { if: "59=6",        need_any: [432,126] },
                           { if: "59=10",       need: 1629 } ]
  at_least_one_identifier: [11, 37, 2430]
  qty_conflict_checks:   [ "110>38", "111>38", "1138>38", "110>111" ]

  # ---- D06 enum combos ----
  dangerous_enum_combos: [ { match: "40=1 and 59=4 and 38>liquidity_ref", sev: high },
                           { match: "40=1 and 59=1", sev: med },
                           { match: "59=6 and expire_in_past", sev: med } ]

  # ---- D07/D15 authorization ----
  session_ownership_groups: {}     # e.g. { groupA: [CLIENTA, CLIENTA-DROPCOPY] }
  flag_unresolved_origclordid: true

  # ---- D09/D10/D22 entitlement ----
  session_account_entitlements: {} # authoritative; else learned
  session_party_entitlements:   {} # per role
  learn_entitlements: true
  learn_window_hours: 24
  alert_on_new_account: true

  # ---- D11 race / D12 escalation ----
  race_window_ms:        50
  replace_qty_ratio:     10        # new 38 > 10× original → escalation if crosses a limit
  immutable_on_replace:  [1, 54, 55, 448]   # account/side/symbol/party must not change on G

  # ---- D13 direction/role ----
  client_may_send_exec_report: false        # true only for drop-copy/hub roles

  # ---- D14/D16 market-data & quote ----
  md_req_rate_limit:     20        # 35=V per sec per session
  md_subscription_cap:   500       # concurrent full-depth subs
  quote_req_rate_limit:  50        # 35=R per sec per session

  # ---- D17 currency ----
  instrument_currency_ref: {}      # symbol -> native ccy (reference data)
  cross_currency_whitelist: []     # dual-listed / ADR

  # ---- D18 time ----
  transacttime:
    stale_threshold_ms:  { normal: 1000, hft: 0.1 }   # RTS 25 aligned
    future_threshold_ms: 1000
    absurd_year_low:     2000
    absurd_year_high:    2100

  # ---- D19 wash ----
  wash_window_ms:        1000
  wash_price_overlap_ticks: 1
  # affiliation uses session_ownership_groups + account grouping

  # ---- D20 throttle ----
  msg_rate_limit:        100       # msgs/sec/session
  max_orders_per_window: 500       # per 1s
  rate_window_ms:        1000
  max_open_notional:     10_000_000

  # ---- D21 mass cancel ----
  allowed_mass_cancel_scopes: {}   # per session; e.g. [1,7] allowed
  mass_cancel_alert_count: 100
```

**Tuning guidance.** Operators should seed `max_order_qty` / `price_collar` / `msg_rate_limit` /
`max_open_notional` from the client's **venue agreement and the venue's published erroneous-order
parameters** (these mirror the RTS 6 Art 15 hard-block limits the venue itself enforces), supply
authoritative `session_account_entitlements` / `session_party_entitlements` / `instrument_currency_ref`
where available (learned maps only give provisional confidence), and set `session_ownership_groups` to
suppress the dominant false positives on the authorization detections (give-up, drop-copy, routing, and
aggregator flows). Baseline-learned thresholds (D02 reference price, D01 statistical, D06 liquidity) need a
warm-up window of representative log data before they are trustworthy; flag findings produced during warm-up
at reduced confidence.
