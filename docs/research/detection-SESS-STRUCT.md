# SAFIX Detection Specifications — SESS & STRUCT

**Purpose.** Convert the SESSION (`SESS`) and STRUCTURE (`STRUCT`) attack-vector
catalogues into precise, **log-observable** detection specifications that directly seed
the SAFIX scanner's detector rules. Every vector in the source corpus is covered — both
the engine-grounded `AV-` IDs and the spec-derived `SV-` IDs.

**Source corpus (read-only reference):**
- `fix-attack-vectors/raw-agent-reports/SESS.md` — AV-SESS-* (27), QuickFIX C++/J source-grounded.
- `fix-attack-vectors/raw-agent-reports/STRUCT.md` — AV-STRUCT-* (20), QuickFIX source-grounded.
- `fix-attack-vectors/spec-derived/SESS.md` + `fix-pentest-skills/fix-session-attacks/vectors.md` — SV-SESS-* (31), FIX.Latest spec-derived.
- `fix-attack-vectors/spec-derived/STRUCT.md` + `fix-pentest-skills/fix-structure-group-attacks/vectors.md` — SV-STRUCT-* (28), FIX.Latest spec-derived.
- `fix-attack-vectors/ATTACK-VECTORS.md` — headline/summary.

**Totals: 106 source vector IDs** (27 AV-SESS + 20 AV-STRUCT + 31 SV-SESS + 28 SV-STRUCT),
consolidated into **~60 detectors** (overlapping `AV-`/`SV-` IDs that share one log signal are
merged into a single detector and cross-referenced). **77 vectors are stateless, 29 are stateful.**

---

## 0. Operating model (how SAFIX sees the data) — READ FIRST

SAFIX scans **QuickFIX-format message logs** (`messages.log`): raw, SOH-delimited FIX
messages, one per line, both inbound and outbound, in receive/send order. The detection
rules below assume this substrate. Several design facts drive everything:

1. **Raw-bytes vs normalized.** Framing detectors (BodyLength, CheckSum, embedded SOH,
   leading garbage, header-field order) are only decidable if the log preserves the **raw
   on-the-wire bytes**. QuickFIX's `FileLog` records the raw inbound string, so these are
   normally observable — **except** messages that failed to *frame at all* (e.g. a
   buffer-flush from a non-numeric BodyLength) may never be written as a message line; those
   are detectable only as a **sequence gap + an `event.log` parse-error**, not as a bad
   message. Where a detector needs raw bytes, it is flagged `[RAW-BYTES]`.

2. **Direction.** Inbound = received from counterparty = **attacker-controlled** = where
   essentially all of these attacks live. Outbound = emitted by the local engine. QuickFIX
   **recomputes 8/9/10/34 on outbound**, so a malformed-framing or bad-seqnum signature on an
   *outbound* line implies either a non-QuickFIX local engine, log tampering, or a local
   compromise — report those at `info`/`high-anomaly`, not as counterparty attacks. Direction
   is derived by comparing `SenderCompID(49)`/`TargetCompID(56)` to the session's configured
   local CompID, or from the log's incoming/outgoing marker if present.

3. **Reject-vs-silent-accept oracle (the most valuable correlation).** For most malformed
   inbound messages the real question is not "was it malformed" but "**did the engine catch
   it**". SAFIX should, for each flagged inbound message, look at what the local side emitted
   next:
   - An outbound `Reject(35=3)` with `RefSeqNum(45)` = the bad message's `34` and a
     `SessionRejectReason(373)` → engine **caught** it (lower severity; validation is live).
   - An outbound `BusinessMessageReject(35=j)` with `BusinessRejectReason(380)` → business-layer caught it.
   - An outbound `Logout(35=5)` / disconnect → engine treated it as fatal.
   - **No reject and the session proceeds** → **silent accept** = the high-severity finding
     (the malformed/forged message reached the application/matching layer). Elevate severity
     one notch whenever the oracle shows silent accept.

4. **Clock for rate/time windows.** Prefer the log's own receipt timestamp (deployment prefix
   or a correlated pcap). If only in-band time is available, fall back to `SendingTime(52)`,
   but remember `52` is **attacker-controlled on inbound** and therefore unreliable for
   rate-limiting an attacker who freezes/advances it.

5. **Dictionary dependence.** All STRUCT presence/validity detectors (`D-REQ-*`, `D-FLD-*`,
   most `D-GRP-*`, `D-MSG-*`) require the **FIX DataDictionary/Orchestra model** for the
   negotiated `BeginString(8)` so the scanner knows required fields, valid tags per MsgType,
   group delimiters, member order, and nesting. Ship the relevant dictionaries with SAFIX.

**Severity scale:** critical / high / medium / low / info.
**Confidence:** high = signature rarely benign; medium = benign causes exist but
distinguishable; low = frequently benign / needs corroboration / refuted.

---

## 1. Summary table (all 106 vectors)

| Vector ID(s) | Name | Stateful? | Severity | Confidence |
|---|---|---|---|---|
| **SESS — seqnum** |
| AV-SESS-SEQ-01 / SV-SESS-1 | MsgSeqNum too high → resend + enqueue | STATEFUL | high | medium |
| AV-SESS-SEQ-02 | Escalating too-high flood → queue OOM | STATEFUL | high | medium |
| AV-SESS-SEQ-03 / SV-SESS-2 | MsgSeqNum too low / duplicate (no PossDup) → logout | STATEFUL | medium | medium |
| AV-SESS-SEQ-04 / SV-SESS-4 | Malformed MsgSeqNum (0/neg/non-numeric/overflow/missing) | STATELESS | medium | high |
| **SESS — resend** |
| AV-SESS-SEQ-05 / SV-SESS-5 | ResendRequest EndSeqNo=0 (infinity) amplification | STATELESS | high | medium |
| AV-SESS-SEQ-06 | ResendRequest flood | STATEFUL | high | medium |
| AV-SESS-SEQ-07 / SV-SESS-6 | ResendRequest inverted / zero / oversized range | STATELESS | medium | high |
| **SESS — gapfill** |
| AV-SESS-SEQ-08 / SV-SESS-7 / AV-SESS-SEQ-10 | SequenceReset-GapFill NewSeqNo too-high (leapfrog / huge) | STATEFUL | high | medium |
| AV-SESS-SEQ-09 / SV-SESS-8 | SequenceReset-GapFill NewSeqNo ≤ expected (rewind/no-op) | STATEFUL | medium | high |
| AV-SESS-SEQ-11 / SV-SESS-9 | SequenceReset-Reset mode (123=N/absent) unsolicited | STATEFUL | medium | medium |
| AV-SESS-SEQ-13 | CHAIN: gap → GapFill smuggles queued message | STATEFUL | high | medium |
| **SESS — replay** |
| AV-SESS-SEQ-12 / SV-SESS-3 / SV-SESS-10 | PossDup=Y replay/injection + OrigSendingTime anomaly | STATEFUL | high | medium |
| SV-SESS-11 | SendingTime chronology / future-dating replay | STATELESS | medium | low |
| SV-SESS-12 | PossResend(97)=Y application-layer replay | STATELESS | medium | medium |
| **SESS — framing** |
| AV-SESS-FRM-01 / SV-SESS-27(a) | BodyLength non-numeric / negative / zero / empty | STATELESS | high | high |
| AV-SESS-FRM-02 / AV-SESS-FRM-07 / SV-SESS-27(b) | BodyLength value mismatch (over/under) | STATELESS | medium | high |
| AV-SESS-FRM-03 / AV-SESS-FRM-08 / SV-SESS-29 / SV-STRUCT-27(SOH) | Embedded SOH / smuggling / non-DATA delimiter injection | STATELESS `[RAW-BYTES]` | critical | medium |
| AV-SESS-FRM-04 / SV-SESS-26 | BeginString not first / wrong value / leading garbage | STATELESS `[RAW-BYTES]` | medium | medium |
| AV-SESS-FRM-05 / SV-STRUCT-21 | Header fields out of order (8/9/35 position) | STATELESS | medium | high |
| AV-SESS-FRM-06 / SV-SESS-28 / SV-STRUCT-22 | CheckSum wrong / non-3-digit / missing / not last | STATELESS `[RAW-BYTES]` | medium | high |
| SV-SESS-30 | Pipelining / oversized frame / MaxMessageSize(383) | STATEFUL | medium | low |
| **SESS — state machine** |
| AV-SESS-STA-01 / SV-SESS-15 | Logon ResetSeqNumFlag(141)=Y attacker-driven reset | STATELESS (flag) | high | medium |
| AV-SESS-STA-02 | Logon flood / half-open logons | STATEFUL | medium | medium |
| AV-SESS-STA-03 / SV-SESS-16 | Non-Logon before Logon / logon ordering abuse | STATEFUL | medium | high |
| AV-SESS-STA-04 | Double / spurious Logon on live session | STATEFUL | medium | medium |
| AV-SESS-STA-05 / SV-SESS-19 | TestRequest flood + TestReqID(112) echo abuse | STATEFUL | medium | medium |
| AV-SESS-STA-06 / SV-SESS-18 | Logout abuse (premature / unsolicited / duplicate) | STATEFUL | medium | low |
| SV-SESS-20 | Heartbeat spoofing / suppression | STATEFUL | low | low |
| **SESS — logon negotiation** |
| SV-SESS-13 | EncryptMethod(98) out-of-range / downgrade | STATELESS | medium | high |
| SV-SESS-14 | HeartBtInt(108) = 0 / negative / huge | STATELESS | medium | medium |
| SV-SESS-17 | NextExpectedMsgSeqNum(789) manipulation | STATEFUL | high | medium |
| **SESS — identity / routing** |
| SV-SESS-21 | SenderCompID/TargetCompID spoof / swap / empty / overlong | STATEFUL | high | medium |
| SV-SESS-22 | OnBehalfOf(115)/DeliverTo(128)/HopGrp routing abuse | STATELESS (flag) | medium | low |
| **SESS — throttle** |
| SV-SESS-23 | Throttle / inbound-rate abuse | STATEFUL | high | medium |
| **SESS — application sequencing** |
| SV-SESS-24 | ApplicationMessageRequest(BW) infinite/huge ApplSeqNum range | STATELESS (flag) | medium | medium |
| SV-SESS-25 | ApplicationMessageReport(BY) reset + dual 1352/43 camouflage | STATELESS (flag) | medium | low |
| **SESS — time** |
| SV-SESS-31 | SendingTime precision / leap-second / format abuse | STATELESS | medium | low |
| **STRUCT — required / conditional** |
| AV-STRUCT-01 / SV-STRUCT-1 | Required body field omitted | STATELESS | high | high |
| AV-STRUCT-02 / SV-STRUCT-2 / SV-STRUCT-4 | Required header / trailer field omitted | STATELESS | high | high |
| AV-STRUCT-03 / SV-STRUCT-5 / SV-STRUCT-6 / SV-STRUCT-7 / SV-STRUCT-8 | Conditionally-required field omitted | STATELESS | critical | medium |
| SV-STRUCT-20 | Required component present but all members omitted | STATELESS | high | medium |
| **STRUCT — unknown / foreign fields** |
| AV-STRUCT-04 / SV-STRUCT-26 | Undefined / unknown tag; reserved/UDF ranges | STATELESS | medium | medium |
| AV-STRUCT-05 / SV-STRUCT-25 | Tag defined but not valid for this MsgType | STATELESS | medium | medium |
| SV-STRUCT-27(empty) | Tag present with empty value | STATELESS | medium | medium |
| **STRUCT — ordering** |
| AV-STRUCT-17 / SV-STRUCT-16 | Body / intra-group field order (C++ silently sorts) | STATELESS | low | low |
| AV-STRUCT-16 / SV-STRUCT-23 | Header field in body / body field in header | STATELESS | medium | medium |
| **STRUCT — duplicate** |
| AV-STRUCT-06 / SV-STRUCT-24 | Duplicate scalar tag (first-wins/last-wins pollution) | STATELESS | critical | high |
| AV-STRUCT-07 | Duplicate delimiter / repeated member within group entry | STATELESS | medium | medium |
| **STRUCT — group desync** |
| AV-STRUCT-08 / SV-STRUCT-10 | NoXXX count > actual entries (under-population/absorption) | STATELESS | high | high |
| AV-STRUCT-09 / SV-STRUCT-11 | NoXXX count < actual entries (over-population/truncation) | STATELESS | high | high |
| AV-STRUCT-11 / SV-STRUCT-12 / SV-STRUCT-19 | NoXXX = 0 or body empty with/without entries | STATELESS | medium | medium |
| AV-STRUCT-12 / SV-STRUCT-14 | NoXXX negative / non-numeric / empty | STATELESS | high | high |
| AV-STRUCT-10 / SV-STRUCT-13 | NoXXX huge → pre-alloc OOM **[REFUTED on QuickFIX]** | STATELESS | info | low |
| AV-STRUCT-13 / SV-STRUCT-3 / SV-STRUCT-15 | Missing delimiter / wrong first member in entry | STATELESS | high | high |
| AV-STRUCT-14 / SV-STRUCT-18 | Interleaved / overlapping groups | STATELESS | medium | medium |
| **STRUCT — nesting** |
| AV-STRUCT-15 / SV-STRUCT-17 | Deep nested groups + nested count mismatch | STATELESS | low | low |
| **STRUCT — length / DATA** |
| SV-STRUCT-9 | Length/DATA field desync (absent/wrong/non-adjacent) | STATELESS `[RAW-BYTES]` | critical | medium |
| **STRUCT — msgtype** |
| AV-STRUCT-20 / SV-STRUCT-28(a-c) | Unknown / empty / multi-char MsgType(35) | STATELESS | high | high |
| AV-STRUCT-19 / SV-STRUCT-28(d) | MsgType valid but body borrowed from another type | STATELESS | medium | medium |
| **STRUCT — meta** |
| AV-STRUCT-18 | Validation-posture probe (accept-vs-reject oracle) | STATEFUL | high | n/a (meta) |

---

## 2. SESS detectors

### 2.1 Sequence numbers (seqnum)

#### D-SEQ-01 — MsgSeqNum too high (gap-induced resend storm)
- **Vector ID(s):** AV-SESS-SEQ-01, SV-SESS-1
- **Category:** SESS / seqnum
- **Detection signal:** inbound message with `MsgSeqNum(34)` **>** the session's expected-inbound
  seqnum, with no `PossDupFlag(43)=Y`. Confirm the gap reaction: an outbound
  `ResendRequest(35=2)` with `BeginSeqNo(7)`=expected and `EndSeqNo(16)`=0 or =(34−1). Flag the
  delta `Δ = 34 − expected`; alert escalates with Δ (Δ≥1e3 notable, Δ≥1e6 strong).
- **Statefulness:** STATEFUL. Track **expected-inbound seqnum** per session (increment on each
  accepted in-order inbound message; updated by resets/GapFills).
- **Severity/Confidence:** high / medium. A single frame weaponizes the peer's recovery into a
  large outbound burst; but legitimate gaps occur after packet loss / reconnect.
- **True-positive signature:** one inbound `34` jumps by a large Δ with no `43=Y` and no preceding
  disconnect/reconnect, immediately followed by our `35=2` and then the peer does **not** fill the
  gap (no resend of 7..34−1) — the gap is a pure lever, not a real loss.
- **False-positive sources:** genuine message loss / network reorder; reconnect where the peer
  resumed at a higher number; a legitimately high starting seqnum after a counterparty-side reset.
  Benign gaps are small (Δ single/low digits) and get *filled* by a subsequent resend.
- **Detector note (stateful):** keep `expected_in`; on inbound non-dup `34 > expected_in` emit a
  candidate; correlate the outbound `35=2`; score by Δ and by whether the gap is later filled.
- **Direction:** inbound only (outbound 34 is engine-generated and monotonic).

#### D-SEQ-02 — Escalating too-high flood (out-of-order queue exhaustion)
- **Vector ID(s):** AV-SESS-SEQ-02
- **Category:** SESS / seqnum
- **Detection signal:** a run of inbound app messages (`35` ∈ app types, e.g. `D`,`G`,`F`) with
  **strictly increasing, never-filled** `MsgSeqNum(34)` far above expected, where the gap is never
  satisfied (no in-order increment of expected-inbound between them). Signal = many queued
  (held) messages accumulating + repeated/suppressed `35=2`.
- **Statefulness:** STATEFUL. Track expected-inbound, the set/count of **outstanding queued
  seqnums** (34 > expected not yet filled), and a rate window.
- **Severity/Confidence:** high / medium. Memory-exhaustion DoS (each held whole message retained
  in QuickFIX's unbounded `std::map` queue); destructive.
- **True-positive signature:** ≥N (e.g. ≥100) inbound messages with monotonically rising `34`,
  none of which reduce the gap, within a short window; our side stops re-issuing `35=2` (dup
  suppression) but keeps queuing.
- **False-positive sources:** a real, large, in-progress resend that genuinely fills over time;
  bursty catch-up after an outage (but that *fills*, lowering the gap).
- **Detector note (stateful):** monitor `len(outstanding_queued)` growth rate; alert when it
  exceeds a threshold without the expected-inbound advancing.
- **Direction:** inbound only.

#### D-SEQ-03 — MsgSeqNum too low / duplicate (no PossDup) → forced logout
- **Vector ID(s):** AV-SESS-SEQ-03, SV-SESS-2
- **Category:** SESS / seqnum
- **Detection signal:** inbound `MsgSeqNum(34)` **<** expected-inbound **and** `PossDupFlag(43)`
  absent or ≠ `Y`; or the **same `34` seen twice** where the second is now below expected and
  carries no `43=Y`. Expect an outbound `Logout(35=5)` (often with `Text(58)` "MsgSeqNum too low
  expecting X but received Y") and disconnect.
- **Statefulness:** STATEFUL. Track expected-inbound and the set of seqnums already seen.
- **Severity/Confidence:** medium / medium. Deterministic one-frame session kill (availability).
- **True-positive signature:** inbound `34 < expected_in`, no `43=Y`, immediately followed by our
  `35=5` + disconnect; or a verbatim replay of a prior frame.
- **False-positive sources:** legitimate mid-recovery retransmission that *should* carry `43=Y`
  but a buggy peer omitted it; a counterparty seqnum reset the local side didn't honor. These look
  the same on the wire — rely on the lifecycle context (was there a reset/reconnect?).
- **Detector note (stateful):** compare `34` to `expected_in`; flag low-without-43; if followed by
  our Logout, it's the attack's realized effect.
- **Direction:** inbound only.

#### D-SEQ-04 — Malformed MsgSeqNum (0 / negative / non-numeric / overflow / missing)
- **Vector ID(s):** AV-SESS-SEQ-04, SV-SESS-4
- **Category:** SESS / seqnum
- **Detection signal:** `MsgSeqNum(34)` value is `0`, has a sign (`-1`, `+42`), contains
  non-digits (`abc`, `4.0`, `0x2A`), has leading zeros (`007`), exceeds int64
  (`99999999999999999999`), is empty (`34=`), or tag 34 is **absent** from a non-framing message.
- **Statefulness:** STATELESS (pure value/format inspection of one message). Overflow/sign-poison
  *effects* are stateful but the trigger is single-message.
- **Severity/Confidence:** medium / high. `34∈{0,neg,non-numeric,empty,absent}` is never legitimate
  (34 is a positive integer ordinal); very low false-positive.
- **True-positive signature:** regex on the `34=` field value failing `^[1-9][0-9]*$` (within
  int64), or tag 34 missing on a message that is not a pre-frame fragment.
- **False-positive sources:** essentially none for 0/neg/non-numeric. Leading `+`/leading-zeros may
  appear from a sloppy-but-benign peer encoder (lower confidence for those two sub-cases only).
- **Detector note (stateless):** field-match `34` value against `^[1-9]\d{0,18}$`; separately flag
  `007`-style leading zeros and `+`-prefix as a sub-case (tag-aliasing / lenient-parse probe).
- **Direction:** inbound (outbound always well-formed under QuickFIX).

### 2.2 Resend / ResendRequest (resend)

#### D-RSD-01 — ResendRequest EndSeqNo=0 ("infinity") full-store amplification
- **Vector ID(s):** AV-SESS-SEQ-05, SV-SESS-5
- **Category:** SESS / resend
- **Detection signal:** inbound `ResendRequest(35=2)` with `EndSeqNo(16)=0` (and typically
  `BeginSeqNo(7)=1`), demanding replay of the entire persisted outbound history. Amplification =
  the (large) outbound byte volume our side emits in response vs the (tiny) request.
- **Statefulness:** STATELESS to flag the single message (`35=2` ∧ `16=0`). The *amplification
  severity* becomes stateful if you also measure the induced outbound volume (optional enrichment).
- **Severity/Confidence:** high / medium. Cheap request → unbounded outbound work. But `7=1,16=0`
  **is a legitimate full-resync** after a counterparty lost its store.
- **True-positive signature:** `35=2|7=1|16=0` arriving when there was **no** preceding gap/
  disconnect that would justify a full resync, and/or repeated (see D-RSD-02).
- **False-positive sources:** genuine disaster-recovery full resync; first reconnect after a
  counterparty store wipe; `ResetSeqNumFlag` sessions catching up. A single `16=0` right after a
  reconnect is normal.
- **Detector note (stateless + context):** field-match `35=2` and `16=0`; raise severity if not
  preceded by a reconnect/Logon within a short window, or if the response byte ratio is high.
- **Direction:** inbound only.

#### D-RSD-02 — ResendRequest flood
- **Vector ID(s):** AV-SESS-SEQ-06
- **Category:** SESS / resend
- **Detection signal:** many inbound `ResendRequest(35=2)` in a short window (optionally each with
  full range `7=1,16=0` and/or escalating too-high own `34`), each forcing a full/large retransmit.
- **Statefulness:** STATEFUL. Rate window of `35=2` count per session per interval.
- **Severity/Confidence:** high / medium. Repeated full-store amplification; Java variant also
  grows the out-of-order queue.
- **True-positive signature:** `35=2` rate ≫ baseline (e.g. >K per minute) with overlapping/
  identical ranges that produce repeated large retransmits.
- **False-positive sources:** a flapping link causing repeated legitimate recovery; a
  mis-configured peer stuck in a resend loop (still worth flagging as availability risk).
- **Detector note (stateful):** sliding-window counter of inbound `35=2`; alert on threshold;
  enrich with range overlap and response volume.
- **Direction:** inbound only.

#### D-RSD-03 — ResendRequest inverted / zero / oversized range
- **Vector ID(s):** AV-SESS-SEQ-07, SV-SESS-6
- **Category:** SESS / resend
- **Detection signal:** inbound `ResendRequest(35=2)` where `BeginSeqNo(7) > EndSeqNo(16)` (and
  `16≠0`); or `7=0`; or `7`/`16` far beyond the highest seqnum we have ever sent (out-of-history).
- **Statefulness:** the inverted (`7>16`,`16≠0`) and zero (`7=0`) cases are **STATELESS**. The
  "beyond history" case is **STATEFUL** (needs our max-sent seqnum).
- **Severity/Confidence:** medium / high for inverted/zero (never legitimate); medium for
  out-of-history.
- **True-positive signature:** `7>16 ∧ 16≠0`, or `7=0`.
- **False-positive sources:** none for `7=0`/inverted. Out-of-history can be a peer that believes
  it saw more than we sent (a desync, still notable).
- **Detector note:** stateless compare of `7` vs `16` on `35=2`; add stateful out-of-history check
  using `max_sent_out`.
- **Direction:** inbound only.

### 2.3 SequenceReset / GapFill (gapfill)

#### D-GF-01 — SequenceReset-GapFill NewSeqNo too-high (leapfrog / message suppression / huge)
- **Vector ID(s):** AV-SESS-SEQ-08, SV-SESS-7, AV-SESS-SEQ-10 (huge variant)
- **Category:** SESS / gapfill
- **Detection signal:** inbound `SequenceReset(35=4)` with `GapFillFlag(123)=Y` and
  `NewSeqNo(36)` **far above** the next real expected seqnum, advancing the target past messages
  that were never delivered. Huge variant: `36` near SEQNUM max (`≈9.2e18`), which then makes every
  subsequent legitimate message appear too-low (durable desync → self-DoS via D-SEQ-03).
- **Statefulness:** STATEFUL. Compare `36` to expected-inbound and to the owed/queued range to
  judge "too high"; track that the jump skipped undelivered messages. (The raw "huge 36" value is
  flaggable statelessly as a weak signal.)
- **Severity/Confidence:** high / medium. Lets a MITM/compromised peer censor messages while keeping
  the session "in sync"; the huge case is durable availability denial.
- **True-positive signature:** `35=4|123=Y|36=N` where `N ≫ expected_in` and there are queued/owed
  seqnums below `N` that get silently discarded; no corresponding legitimate resend conversation.
- **False-positive sources:** legitimate GapFill during recovery advances the counter past admin
  messages (heartbeats/resend-requests) that genuinely won't be resent — that is its purpose. The
  attack is distinguished by the **magnitude** of the jump and by skipping *application* messages,
  not just admin fillers.
- **Detector note (stateful):** on `35=4 ∧ 123=Y`, compute `jump = 36 − expected_in`; alert when
  jump is large or when queued app messages below `36` are dropped; special-case `36 > 2^53` as
  the huge/desync variant.
- **Direction:** inbound only.

#### D-GF-02 — SequenceReset-GapFill NewSeqNo ≤ expected (backward rewind / no-op)
- **Vector ID(s):** AV-SESS-SEQ-09, SV-SESS-8
- **Category:** SESS / gapfill
- **Detection signal:** inbound `SequenceReset(35=4)` (GapFill or Reset) with `NewSeqNo(36)` **<**
  expected-inbound (rewind attempt → expect our `Reject(35=3, 373=5 ValueIsIncorrect)`), or
  `36 == expected` (a **silent no-op** probe — accepted by neither reject branch).
- **Statefulness:** STATEFUL. Needs expected-inbound to classify `<` vs `==`.
- **Severity/Confidence:** medium / high. A backward reset, if honored, re-opens a replay window;
  `==` is a benign-looking oracle probe. Rewind is never legitimate.
- **True-positive signature:** `35=4|36=M` with `M ≤ expected_in`; `M<expected` should draw a
  `373=5` reject (if it doesn't → silent accept, elevate); `M==expected` is a reconnaissance no-op.
- **False-positive sources:** a confused peer re-sending a stale GapFill after its own reset;
  harmless but worth noting.
- **Detector note (stateful):** compare `36` to `expected_in`; branch on `<` (reject-expected) vs
  `==` (silent-oracle).
- **Direction:** inbound only.

#### D-GF-03 — SequenceReset-Reset mode (123=N/absent) unsolicited
- **Vector ID(s):** AV-SESS-SEQ-11, SV-SESS-9
- **Category:** SESS / gapfill (state-machine adjacent)
- **Detection signal:** inbound `SequenceReset(35=4)` with `GapFillFlag(123)` **absent or =N**
  (Reset mode) carrying an arbitrary `NewSeqNo(36)`, sent **outside** any resend/recovery window.
  In Reset mode QuickFIX runs verify with both seqnum and PossDup checks **off**, so the target
  leaps unconditionally regardless of the message's own `34`.
- **Statefulness:** STATEFUL. "Outside recovery" requires knowing whether a resend is in progress
  (outstanding ResendRequest state); the unconditional-jump effect needs expected-inbound tracking.
- **Severity/Confidence:** medium / medium. Reset mode is the most "trusted" control message; prime
  unsolicited-injection target. But Reset mode is also legitimately used to resynchronize.
- **True-positive signature:** `35=4` with no `123=Y`, `36` set, arriving with no outstanding resend
  and no reconnect — an unsolicited counter jump.
- **False-positive sources:** legitimate administrative resync (e.g. start-of-day), or a peer using
  Reset mode instead of GapFill by convention.
- **Detector note (stateful):** flag `35=4 ∧ (123 absent or 123=N)`; score higher when
  `resend_in_progress == false`.
- **Direction:** inbound only.

#### D-GF-04 — CHAIN: too-high gap then GapFill papers it over to smuggle the queued message
- **Vector ID(s):** AV-SESS-SEQ-13
- **Category:** SESS / gapfill (headline sequencing chain)
- **Detection signal:** a **two-message correlation**: (1) an inbound app message at
  `MsgSeqNum(34)=N ≫ expected` (gets queued — D-SEQ-01), then (2) an inbound
  `SequenceReset(35=4)` with its own `34 == expected` (so it passes verify), `GapFillFlag(123)=Y`,
  and `NewSeqNo(36)=N` — i.e. the GapFill's `36` **equals the seqnum of the previously-queued
  forged message**. The engine then advances expected to N, clears the queue below N, and drains
  the forged message at N as genuine; the real owed messages (expected..N−1) are silently voided.
- **Statefulness:** STATEFUL. Must remember queued (too-high) seqnums and their messages, and match
  a later GapFill whose `36` equals a queued seqnum while its `34` equals current expected.
- **Severity/Confidence:** high / medium. Headline injection chain — turns the out-of-order queue
  into an injection channel; attacker-chosen message accepted at an arbitrary seqnum, intervening
  sequence voided. Confidence medium because it is a specific multi-step pattern that could, in
  rare recovery scenarios, resemble a legitimate GapFill-after-gap.
- **True-positive signature:** `∃` queued inbound msg at `34=N`; later inbound `35=4|34=expected|
  123=Y|36=N` (optionally with `43=Y`,`122≤52`); after it, the queued app message is processed and
  seqnums expected..N−1 are never delivered.
- **False-positive sources:** a legitimate GapFill that genuinely fills an admin gap up to a real
  pending message — but there `36` points past admin fillers, not at an attacker-planted app
  message that itself arrived out of order first. The ordering (forged app msg *first*, GapFill
  *second*, `36`=forged seqnum) is the discriminator.
- **Detector note (stateful):** maintain `queued = {seqnum: msg}`; on inbound `35=4 ∧ 123=Y`, if
  `34==expected_in` and `36 ∈ queued`, raise critical-chain alert and mark the drained message as
  injected.
- **Direction:** inbound only.

### 2.4 Replay (PossDup / PossResend / SendingTime)

#### D-RPL-01 — PossDup=Y replay/injection with OrigSendingTime anomaly
- **Vector ID(s):** AV-SESS-SEQ-12, SV-SESS-3, SV-SESS-10
- **Category:** SESS / replay
- **Detection signal:** inbound message with `PossDupFlag(43)=Y` and one of:
  (a) **no** `OrigSendingTime(122)` at all (QuickFIX-J default `requiresOrigSendingTime=false`
  silently accepts → forged-duplicate injection; C++ rejects `REQUIRED_TAG_MISSING`);
  (b) `122 > SendingTime(52)` (original "sent" after transmission → expect `373=10` + logout);
  (c) `122 == 52` set to now/future, or `122` far in the past (silent accept → replay window);
  **AND** critically the message lands at the session's **current expected seqnum** (not a
  too-low discarded dup) — i.e. a `43=Y` message that is *not* actually a replay of something we
  already processed is an injection, not a benign resend.
- **Statefulness:** STATEFUL. Need expected-inbound and the set of already-seen (seqnum, body)
  pairs to distinguish a genuine resend (matches a prior message) from a forged one (new content at
  expected seqnum). The 122-vs-52 chronology sub-check is stateless.
- **Severity/Confidence:** high / medium. Replay/injection primitive; the missing-122 Java path is a
  silent-accept gap.
- **True-positive signature:** `43=Y` at `34==expected_in` whose body does **not** match any
  previously-seen message with that seqnum (forged duplicate), especially with `122` absent or
  `122>52`.
- **False-positive sources:** **legitimate resends** are the dominant benign case — a real
  retransmission after a ResendRequest carries `43=Y` + `122`, and its body matches the original.
  Distinguish by (i) does `122` obey `122 ≤ 52`, and (ii) does the content match a prior message at
  that seqnum? A matching prior message = benign recovery.
- **Detector note (stateful):** keep `seen[seqnum] = hash(body)`; on `43=Y`, if `122` absent/`>52`
  OR the seqnum content doesn't match `seen`, flag. Sub-rule for `122>52` is a stateless hard flag.
- **Direction:** inbound only.

#### D-RPL-02 — SendingTime chronology / future-dating replay
- **Vector ID(s):** SV-SESS-11
- **Category:** SESS / replay / time
- **Detection signal:** `SendingTime(52)` far from the message's **receipt time** (log timestamp):
  far future (`52` years ahead) or far past, beyond any plausible tolerance (convention ≈ a few
  seconds to ~2 min).
- **Statefulness:** STATELESS per message **if** a trusted receipt clock (log/pcap timestamp) is
  available; becomes cross-message/STATEFUL if you instead compare `52` to neighboring messages'
  `52`.
- **Severity/Confidence:** medium / low. Many engines enforce no window; clock skew between
  counterparties is common and benign → high false-positive rate.
- **True-positive signature:** `|52 − receipt_time|` ≫ tolerance, especially a year/epoch value
  (`20991231-…`, `19700101-…`).
- **False-positive sources:** unsynchronized clocks, timezone/DST mistakes, batch replays in test
  environments, slow processing. Keep the window generous; only large deviations are high-value.
- **Detector note:** parse `52` (UTCTimestamp) → epoch; compare to receipt timestamp; alert on
  large delta. Treat `52` as attacker-controlled (don't trust it as the clock).
- **Direction:** inbound (outbound `52` is our own clock).

#### D-RPL-03 — PossResend(97)=Y application-layer replay
- **Vector ID(s):** SV-SESS-12
- **Category:** SESS / replay
- **Detection signal:** inbound business message (e.g. `35=D`) with `PossResend(97)=Y` and a
  **fresh** `MsgSeqNum(34)` (in-order, not a session dup). Correct handling requires the
  application to dedupe on business keys (`ClOrdID(11)`); a naive engine executes twice. Strong
  signal: `97=Y` with a `ClOrdID(11)` that was already seen on a prior order.
- **Statefulness:** STATELESS to flag `97=Y` on a fresh seqnum. STATEFUL to confirm replay (reused
  `ClOrdID(11)`/business key across different seqnums).
- **Severity/Confidence:** medium / medium. `97` explicitly shifts dedup to the application and is
  often unhandled.
- **True-positive signature:** `97=Y` on an in-order message whose `ClOrdID(11)` (or other business
  key) duplicates an earlier order's.
- **False-positive sources:** legitimate use of `97=Y` after a failover where the sender genuinely
  re-sends under new seqnums; dedupe handled correctly downstream.
- **Detector note (stateful enrichment):** maintain `seen_clordids`; flag `97=Y` and escalate on
  business-key reuse.
- **Direction:** inbound.

### 2.5 Framing / transport (framing)

> `[RAW-BYTES]` detectors below require the log to contain the exact received bytes
> (SOH-delimited), not a re-serialized/normalized form.

#### D-FRM-01 — BodyLength malformed (non-numeric / negative / zero / empty)
- **Vector ID(s):** AV-SESS-FRM-01, SV-SESS-27 (malformed sub-case)
- **Category:** SESS / framing
- **Detection signal:** `BodyLength(9)` value is non-numeric (`9=abc`), negative (`9=-5`), empty
  (`9=`), or `0`. In QuickFIX C++ a non-numeric/negative `9` throws and triggers
  `m_buffer.erase()` — a **full receive-buffer flush** that destroys pipelined messages.
- **Statefulness:** STATELESS (value of tag 9). The buffer-flush *collateral* (lost pipelined
  messages) is visible only as a downstream gap.
- **Severity/Confidence:** high / high. A numeric `9` is mandatory; `abc`/`-5`/empty is never
  legitimate. Note: the offending frame may itself fail to log; detect via a surviving fragment or
  via the `event.log` parse error plus a sudden gap.
- **True-positive signature:** `9=` value not matching `^[0-9]+$`, or `=0`.
- **False-positive sources:** none for non-numeric/negative. `9=0` could be a truncated/empty frame
  artifact.
- **Detector note (stateless):** regex the second field; `^9=([1-9][0-9]*)\x01` expected — anything
  else flags. Correlate a following gap as the flush effect.
- **Direction:** inbound only (QuickFIX recomputes `9` outbound).

#### D-FRM-02 — BodyLength value mismatch (over / under vs recomputed)
- **Vector ID(s):** AV-SESS-FRM-02, AV-SESS-FRM-07, SV-SESS-27 (over/under sub-case)
- **Category:** SESS / framing
- **Detection signal:** declared `BodyLength(9)` ≠ **recomputed** body length (byte count from the
  char after the `9=…\x01` up to and including the char before `10=`). Over-count → the engine
  stalls waiting for bytes (HOL stall); under-count → premature frame end / smuggling (see D-FRM-03).
- **Statefulness:** STATELESS `[RAW-BYTES]` (recompute from the logged frame).
- **Severity/Confidence:** medium / high. QuickFIX computes `9` exactly outbound and rejects
  mismatches inbound, so a logged inbound mismatch is an anomaly/attack or corruption.
- **True-positive signature:** `recompute(body) ≠ int(9)`.
- **False-positive sources:** a log that re-serialized the message (then `9` always matches — this
  detector is moot); truncated log lines; multi-byte charset counting differences (byte vs char) —
  account for UTF-8 in `Encoded*` fields.
- **Detector note (stateless):** implement the FIX BodyLength algorithm and diff; separate over
  (stall) from under (smuggling → hand to D-FRM-03).
- **Direction:** inbound only.

#### D-FRM-03 — Embedded SOH / message smuggling / non-DATA delimiter injection / DATA-length desync
- **Vector ID(s):** AV-SESS-FRM-03, AV-SESS-FRM-08, SV-SESS-29, SV-STRUCT-27 (SOH-in-non-data part);
  cross-ref SV-STRUCT-9 (D-LEN-01)
- **Category:** SESS / framing (+ STRUCT length/data)
- **Detection signal (several facets):**
  - A raw `SOH(0x01)` embedded **inside a non-DATA field value** (e.g. `Account(1)`, `Text(58)`),
    splitting one field into a spurious extra `tag=value` → expect `373=17
    NonDataValueIncludesFieldDelimiter`. Signal: after splitting on SOH, a "field" whose tag is
    unexpected/invalid in context, or an extra `=` inside a value.
  - A **second `\x0110=`** (fake CheckSum) appearing before the real one at/after the BodyLength
    offset → one frame carved into two (message smuggling); pairs with an under-counted `9`.
  - A length-prefixed **DATA field whose declared Length ≠ actual payload bytes** (see D-LEN-01):
    `RawDataLength(95)/RawData(96)`, `XmlDataLen(212)/XmlData(213)`,
    `EncodedTextLen(354)/EncodedText(355)`, `SecureDataLen(90)/SecureData(91)`,
    `SignatureLength(93)/Signature(89)` — a short/long Length makes an embedded SOH (mis)parse as a
    delimiter, smuggling tags in/out.
  - A raw `NUL(0x00)` in any value.
- **Statefulness:** STATELESS `[RAW-BYTES]`. Decidable from the one raw frame + the dictionary
  (which fields are DATA-typed, and each DATA field's paired Length tag).
- **Severity/Confidence:** critical / medium. Direct field-injection / validation-bypass / request-
  smuggling primitive. Confidence medium because DATA fields **legitimately** contain SOH, so the
  detector must use the dictionary to separate legal (DATA, length matches) from illegal (non-DATA,
  or DATA with length mismatch).
- **True-positive signature:** SOH inside a field the dictionary marks non-DATA; or a DATA field
  where `declared_len ≠ actual_bytes`; or `>1` `\x0110=` occurrence in a single frame.
- **False-positive sources:** correctly-formed DATA fields that contain SOH with a *matching*
  length (fully legitimate — do not flag); binary blobs in `RawData` with coincidental `0x01` bytes
  (legal when length matches).
- **Detector note (stateless):** tokenize the raw frame by SOH; for each DATA field use its Length
  tag to consume exactly N bytes (don't split on SOH inside it) and verify N matches; any SOH-split
  "field" outside a DATA region, or a Length/payload mismatch, flags. Count `\x0110=` occurrences.
- **Direction:** inbound only.

#### D-FRM-04 — BeginString not first / wrong value / leading garbage
- **Vector ID(s):** AV-SESS-FRM-04, SV-SESS-26
- **Category:** SESS / framing
- **Detection signal:** the raw frame does **not** begin with `8=`; or arbitrary bytes precede `8=`
  (QuickFIX does `find("8=")`+`erase`, silently stripping them and possibly latching a spurious
  `8=` inside garbage); or `BeginString(8)` value is unknown/mismatched (`8=FIX.9.9`, `8=FIXT.1.2`,
  empty, trailing spaces) vs the session's negotiated version; or `8` omitted.
- **Statefulness:** STATELESS `[RAW-BYTES]` for position/garbage; the version-mismatch check needs
  the session's negotiated `8` (config).
- **Severity/Confidence:** medium / medium. `8` is the sync word; mis-sync enables boundary
  confusion / IDS evasion.
- **True-positive signature:** frame offset 0 ≠ `8=`; or `8=` value ∉ {negotiated version}.
- **False-positive sources:** benign version negotiation differences in multi-version gateways;
  log-line concatenation artifacts (the "garbage" is actually the tail of the previous line).
- **Detector note (stateless):** assert the line starts with `8=<negotiated>\x01`; flag otherwise;
  scan for a second `8=` token mid-line.
- **Direction:** inbound only.

#### D-FRM-05 — Header fields out of order (8/9/35 not in positions 1/2/3)
- **Vector ID(s):** AV-SESS-FRM-05, SV-STRUCT-21; cross-ref SV-SESS-26 (ordering part)
- **Category:** SESS / framing (STRUCT ordering)
- **Detection signal:** the first three fields are not exactly `BeginString(8)`,
  `BodyLength(9)`, `MsgType(35)` in that order (e.g. `8,35,9` or `9` first or a body field before
  `8`). QuickFIX throws `InvalidMessage("Header fields out of order")`; strict engines reject
  (`373=14 TagSpecifiedOutOfRequiredOrder`). If `9` is not second the frame boundary is undefined.
- **Statefulness:** STATELESS (positional check of the first three tags).
- **Severity/Confidence:** medium / high. QuickFIX never reorders the header outbound, so an inbound
  out-of-order header is a clear anomaly; critical specifically when `9` is displaced (framing
  contract broken).
- **True-positive signature:** tag sequence of fields 1–3 ≠ `[8,9,35]`.
- **False-positive sources:** a lenient/custom peer encoder that emits a known-benign header order
  (rare); mostly a cross-implementation divergence oracle.
- **Detector note (stateless):** read the first three `tag=` tokens; compare to `[8,9,35]`.
- **Direction:** inbound only.

#### D-FRM-06 — CheckSum wrong / non-3-digit / missing / not last
- **Vector ID(s):** AV-SESS-FRM-06, SV-SESS-28, SV-STRUCT-22
- **Category:** SESS / framing (STRUCT trailer)
- **Detection signal:** recomputed modulo-256 checksum ≠ declared `CheckSum(10)`; or `10` value is
  not exactly 3 ASCII digits (`10=1`, `10=1234`, `10=-1`, `10=1x3`); or `10` is absent; or `10` is
  **not the last field** (a field follows it, or a trailer field `10`/`93`/`89` appears mid-message
  — which can cause a premature frame close and split the stream).
- **Statefulness:** STATELESS `[RAW-BYTES]` (recompute from the frame bytes).
- **Severity/Confidence:** medium / high. Deterministic recompute; QuickFIX always emits a correct,
  final, 3-digit `10`, so any deviation inbound is anomalous.
- **True-positive signature:** `checksum(bytes_up_to_10) mod 256 ≠ int(10)`; or `10` not matching
  `^[0-9]{3}$`; or content after `10=xxx\x01`.
- **False-positive sources:** a permissive gateway that doesn't enforce checksums (the peer may be
  habitually wrong — still a real integrity gap); re-serialized logs (checksum always matches →
  moot).
- **Detector note (stateless):** implement the FIX checksum; verify value, width, and terminal
  position.
- **Direction:** inbound only.

#### D-FRM-07 — Pipelining / oversized frame / MaxMessageSize(383)
- **Vector ID(s):** SV-SESS-30
- **Category:** SESS / framing
- **Detection signal:** a single logged unit containing **multiple** `8=…10=…` frames (pipelining
  stress), or a single message whose byte length **exceeds** the `MaxMessageSize(383)` the peer
  advertised at Logon; combined with an understated `9` + a trailing message (boundary smuggling —
  see D-FRM-02/03).
- **Statefulness:** STATEFUL — the `383` comparison needs the negotiated value captured from the
  Logon(`35=A`). Plain pipelining is usually not visible once the log splits per message.
- **Severity/Confidence:** medium / low. Real transports coalesce/fragment frames normally, so
  pipelining alone is benign; only oversize-vs-383 and smuggling combos are notable.
- **True-positive signature:** `len(message_bytes) > negotiated_383`; or >1 frame per logged unit.
- **False-positive sources:** normal TCP coalescing; large but legitimate messages (mass quote /
  big allocation) under a generous limit.
- **Detector note (stateful):** record `383` from each side's Logon; compare per-message size;
  flag oversize and multi-frame units.
- **Direction:** inbound (and note our own emits vs the peer's declared `383`).

### 2.6 State machine (Logon / Logout / Heartbeat / TestRequest)

#### D-STA-01 — Logon ResetSeqNumFlag(141)=Y (attacker-driven sequence reset)
- **Vector ID(s):** AV-SESS-STA-01, SV-SESS-15
- **Category:** SESS / state-machine
- **Detection signal:** inbound `Logon(35=A)` with `ResetSeqNumFlag(141)=Y`, resetting both
  sequences to 1 and wiping gap-based replay protection. Higher-severity variants: `141=Y`
  **mid-session** (not at session start), or repeated `141=Y` logons (erasing evidence).
- **Statefulness:** STATELESS to flag `35=A ∧ 141=Y`. STATEFUL to judge "unexpected" (mid-session /
  off-schedule / repeated) — needs logon state + a notion of the scheduled reset time.
- **Severity/Confidence:** high / medium. One flag annihilates sequence-gap replay protection and
  breaks the audit trail. But `141=Y` is a **legitimate, common** start-of-day / scheduled reset.
- **True-positive signature:** `141=Y` at an unexpected time (mid-session, or not at the agreed
  reset window), or an abnormal frequency of reset-logons.
- **False-positive sources:** scheduled daily/weekly sequence resets (very common); first logon of
  a session configured with `ResetOnLogon=Y`. A single `141=Y` at session start is usually benign —
  key on timing/frequency.
- **Detector note:** flag all `35=A ∧ 141=Y`; suppress/downgrade those at the configured reset
  window; escalate mid-session or repeated resets.
- **Direction:** inbound (an inbound reset is attacker-relevant; outbound is our own policy).

#### D-STA-02 — Logon flood / half-open logons
- **Vector ID(s):** AV-SESS-STA-02
- **Category:** SESS / state-machine
- **Detection signal:** many `Logon(35=A)` attempts / connection establishments per unit time
  (connection churn), or logons followed by silence until the logon-timeout (half-open),
  exhausting connection/thread/FD/session state.
- **Statefulness:** STATEFUL. Rate window over logon attempts / connection events (best sourced from
  `event.log` connect/disconnect lines, since many fail before a message is logged).
- **Severity/Confidence:** medium / medium. Availability; rate-bounded per attempt but not in
  aggregate.
- **True-positive signature:** logon-attempt rate ≫ baseline from one peer/IP; many
  connect→timeout→disconnect cycles with no completed session.
- **False-positive sources:** a flapping network or a mis-configured client retry loop (still an
  availability concern).
- **Detector note (stateful):** correlate `event.log` connection events + inbound `35=A` count in a
  sliding window.
- **Direction:** inbound.

#### D-STA-03 — Non-Logon before Logon / logon-ordering abuse
- **Vector ID(s):** AV-SESS-STA-03, SV-SESS-16
- **Category:** SESS / state-machine
- **Detection signal:** the **first** inbound message on a connection is not `Logon(35=A)` (e.g.
  `35=D`/`35=0`), i.e. a business/admin message arrives while `receivedLogon == false`; or a Logon
  with a `34` inconsistent with the pre-existing counter. Expect reject/disconnect; silent
  processing = pre-auth exposure.
- **Statefulness:** STATEFUL. Need per-connection logon state (have we seen the inbound Logon yet?).
- **Severity/Confidence:** medium / high. "First message must be Logon" is a hard gate; a
  business message before Logon is never legitimate.
- **True-positive signature:** inbound non-`A` message with `logged_on == false` for that session.
- **False-positive sources:** log window that starts mid-session (the Logon is simply before the
  log's first line) — anchor on actual connection-open events, not log start.
- **Detector note (stateful):** per session, set `logged_on` on inbound `35=A` accept; flag any
  earlier inbound non-Logon.
- **Direction:** inbound.

#### D-STA-04 — Double / spurious Logon on an established session
- **Vector ID(s):** AV-SESS-STA-04; cross-ref SV-SESS-16
- **Category:** SESS / state-machine
- **Detection signal:** a second inbound `Logon(35=A)` after the session is already logged on
  (`receivedLogon == true`), especially with mutated `HeartBtInt(108)`, `EncryptMethod(98)`, or
  `ResetSeqNumFlag(141)` → renegotiation/reset-without-reauth probe.
- **Statefulness:** STATEFUL. Need logon state.
- **Severity/Confidence:** medium / medium. Re-logon can be a legitimate reset handshake, so medium.
- **True-positive signature:** inbound `35=A` while `logged_on == true` with no intervening
  Logout/reconnect.
- **False-positive sources:** legitimate in-session sequence-reset handshakes; recovery re-logon
  after a half-close.
- **Detector note (stateful):** flag `35=A` with `logged_on == true`; enrich with changed 98/108/141.
- **Direction:** inbound.

#### D-STA-05 — TestRequest flood + TestReqID(112) echo abuse
- **Vector ID(s):** AV-SESS-STA-05, SV-SESS-19
- **Category:** SESS / state-machine
- **Detection signal:** high rate of inbound `TestRequest(35=1)` (each forces a 1:1 outbound
  `Heartbeat(35=0)` echoing `TestReqID(112)` → reflected amplification); and/or `112` values that
  are oversized (e.g. KBs), binary, SOH-adjacent, or empty (echo-path / log-injection probe).
- **Statefulness:** STATEFUL for the flood (rate window of `35=1`); STATELESS for the `112` payload
  anomaly (single-message).
- **Severity/Confidence:** medium / medium. TestRequests are normal; the flood/oversized-112 is the
  signal.
- **True-positive signature:** `35=1` rate ≫ baseline, or `len(112)` beyond a sane cap / containing
  control bytes.
- **False-positive sources:** legitimate liveness probing after idle periods; heartbeat-interval
  edge timing.
- **Detector note:** sliding-window count of inbound `35=1`; stateless length/charset check on `112`.
- **Direction:** inbound.

#### D-STA-06 — Logout abuse (premature / unsolicited / duplicate)
- **Vector ID(s):** AV-SESS-STA-06, SV-SESS-18
- **Category:** SESS / state-machine
- **Detection signal:** inbound `Logout(35=5)` at odd lifecycle points — mid-resend, before Logon
  completes, repeated, or followed immediately by more frames (post-logout acceptance probe). Tears
  down the victim session / interrupts in-flight resend.
- **Statefulness:** STATEFUL. Need lifecycle context (is a resend in progress? is the session even
  logged on? did more messages follow the Logout?).
- **Severity/Confidence:** medium / low. Logout is normal termination; the abuse is contextual, so
  low confidence without lifecycle correlation.
- **True-positive signature:** `35=5` while `logged_on == false`, or during an active resend, or
  followed by further inbound frames on the same connection.
- **False-positive sources:** normal end-of-day logout; orderly shutdown.
- **Detector note (stateful):** flag `35=5` whose context (pre-logon / mid-resend / followed-by-
  traffic) is abnormal.
- **Direction:** inbound.

#### D-STA-07 — Heartbeat spoofing / suppression
- **Vector ID(s):** SV-SESS-20
- **Category:** SESS / state-machine
- **Detection signal:** inbound `Heartbeat(35=0)` carrying a `TestReqID(112)` that was **never
  requested** by our outbound `TestRequest(35=1)` (unsolicited echo), or a cadence anomaly
  (heartbeats withheld until our TestRequest, then answered late).
- **Statefulness:** STATEFUL. Track outstanding TestReqIDs we issued, and heartbeat timing vs the
  negotiated `108`.
- **Severity/Confidence:** low / low. Mostly a liveness-state probe; heartbeats are ubiquitous.
- **True-positive signature:** `35=0` with `112` not matching any outbound TestReqID we sent.
- **False-positive sources:** race between our TestRequest and the peer's independent heartbeat;
  clock/timer jitter.
- **Detector note (stateful):** set `outstanding_testreqids`; flag heartbeat `112` not in the set.
- **Direction:** inbound.

### 2.7 Logon negotiation parameters

#### D-LGN-01 — EncryptMethod(98) out-of-range / downgrade
- **Vector ID(s):** SV-SESS-13
- **Category:** SESS / state-machine (logon negotiation)
- **Detection signal:** `Logon(35=A)` with `EncryptMethod(98)` outside the valid enum
  `{0,1,2,3,4,5,6}` (e.g. `98=7`, `98=99`, negative, non-numeric), or an unexpected value, probing
  enum validation / downgrade on the first (unauthenticated) message.
- **Statefulness:** STATELESS (enum check on one message).
- **Severity/Confidence:** medium / high. Out-of-range `98` is never legitimate; `98` is vestigial
  but mandatory on the first message.
- **True-positive signature:** `35=A` with `98` ∉ `{0..6}`.
- **False-positive sources:** none for out-of-range. A legitimate but unusual in-range value (e.g.
  a DES method) is not an attack.
- **Detector note (stateless):** validate `98` against the enum.
- **Direction:** inbound.

#### D-LGN-02 — HeartBtInt(108) = 0 / negative / huge
- **Vector ID(s):** SV-SESS-14
- **Category:** SESS / state-machine (logon negotiation)
- **Detection signal:** `Logon(35=A)` with `HeartBtInt(108)=0` (disables liveness detection → stale
  half-open peers never detected), `108<0`, or `108` extremely large (`2147483647` → effectively no
  heartbeats / possible timer overflow).
- **Statefulness:** STATELESS (value in one Logon).
- **Severity/Confidence:** medium / medium. `108=0` directly disables the only built-in liveness
  mechanism; but some deployments legitimately configure `0` (heartbeating off by policy).
- **True-positive signature:** `35=A` with `108 ∈ {0, negative, ≥ 2^31}`.
- **False-positive sources:** intentionally-configured `108=0` setups; very long intervals for
  low-traffic batch sessions.
- **Detector note (stateless):** range-check `108`; cross-check that both sides agreed (108 should
  match).
- **Direction:** inbound (and compare to our outbound Logon's `108`).

#### D-LGN-03 — NextExpectedMsgSeqNum(789) manipulation
- **Vector ID(s):** SV-SESS-17
- **Category:** SESS / state-machine (logon negotiation)
- **Detection signal:** `Logon(35=A)` with `NextExpectedMsgSeqNum(789)` set far **below** what we
  have sent (forces a large resend) or far **above** (makes us believe the peer saw messages we
  never sent → silent skip). Recovery driven at the least-validated moment.
- **Statefulness:** STATEFUL. Compare `789` to our `max_sent_out + 1` for that session.
- **Severity/Confidence:** high / medium. `789` drives recovery at logon; its algorithm is often
  hand-rolled.
- **True-positive signature:** `789` ≪ (our next outbound) → big resend; or `789` ≫ (our next
  outbound) → skip.
- **False-positive sources:** legitimate NextExpected-based recovery after a real gap/reconnect
  (that's its purpose) — key on the magnitude of the discrepancy and absence of a real gap.
- **Detector note (stateful):** on inbound `35=A` with `789`, diff against our sent history.
- **Direction:** inbound.

### 2.8 Identity & routing

#### D-ID-01 — SenderCompID/TargetCompID spoofing / swap / empty / overlong
- **Vector ID(s):** SV-SESS-21
- **Category:** SESS / state-machine (identity)
- **Detection signal:** inbound frames whose `SenderCompID(49)`/`TargetCompID(56)` do **not match
  the session's negotiated identity** (impersonation), `49`↔`56` swapped, `49==56`, empty, or
  abnormally long CompIDs; or two different identities seen across one TCP session. Expect
  `373=9 CompIDProblem` + logout if validated.
- **Statefulness:** STATEFUL. Need the session's bound (`49`,`56`) pair (from the accepted Logon /
  config) to detect mismatch. The structural sub-cases (`49==56`, empty, overlong) are STATELESS.
- **Severity/Confidence:** high / medium. CompID is the session's identity assertion; transport-
  unbound validation is a serious authz gap. Medium confidence because a mismatch can be a
  misconfiguration.
- **True-positive signature:** per-message `(49,56)` ≠ the session's bound pair; or a mid-session
  identity change.
- **False-positive sources:** multi-session muxes, onboarding/config errors, test harnesses reusing
  a connection. Establish the bound pair from the Logon that opened the session.
- **Detector note (stateful):** record `(49,56)` at Logon accept; compare every subsequent inbound
  message; stateless checks for `49==56`/empty/length.
- **Direction:** inbound.

#### D-ID-02 — OnBehalfOf/DeliverTo/HopGrp routing abuse
- **Vector ID(s):** SV-SESS-22
- **Category:** SESS / state-machine (routing)
- **Detection signal:** inbound frames populating `OnBehalfOfCompID(115)`, `DeliverToCompID(128)`,
  `OnBehalfOfSubID(116)`/`DeliverToSubID(129)`, `OnBehalfOfLocationID(144)`/`DeliverToLocationID(145)`,
  or `HopGrp` (`NoHops(627)`, `HopCompID(628)`, `HopSendingTime(629)`, `HopRefID(630)`) to route to
  third parties the session isn't authorized to reach; or a **mid-session change** of `115`/`116`;
  or synthesized HopGrp history disguising origin. Expect `380=7 DeliverTo firm not available`.
- **Statefulness:** STATELESS to flag presence of `115`/`128` (single message). STATEFUL to detect a
  mid-session identity/route change (needs prior-value tracking).
- **Severity/Confidence:** medium / low. These fields are legitimately used in hub / service-bureau
  topologies, so presence alone is low-confidence; the change-detection and forged HopGrp are the
  higher-value signals.
- **True-positive signature:** `115`/`128` pointing at an unauthorized firm; or `115` changing
  mid-session; or HopGrp entries inconsistent with the actual sender.
- **False-positive sources:** normal routed/hub traffic where `115`/`128` are expected.
- **Detector note:** flag `115`/`128` against an allowlist of authorized routes; track `115` per
  session for change-detection.
- **Direction:** inbound.

### 2.9 Throttle / rate

#### D-THR-01 — Throttle / inbound-rate abuse
- **Vector ID(s):** SV-SESS-23
- **Category:** SESS / throttle
- **Detection signal:** inbound application-message rate exceeding the agreed
  `ThrottleNoMsgs(1613)` per `ThrottleTimeInterval(1614)`/`ThrottleTimeUnit(1615)`; observe
  responses `BusinessMessageReject(35=j)` with `BusinessRejectReason(380)` ∈ {8 throttle exceeded,
  9 will-disconnect, 10 throttled-rejected} or a disconnect. Also messages of a `MsgType` **not**
  covered by `ThrottleMsgTypeGrp` used to bypass a type-scoped throttle; and "ride just under the
  limit" reconnaissance.
- **Statefulness:** STATEFUL. Rate window per session (and per MsgType); knowledge of the negotiated
  throttle params.
- **Severity/Confidence:** high / medium. Throttling is the primary app-flow DoS control; both
  enforcement and the "Queue" buffering are abusable.
- **True-positive signature:** inbound rate just over `1613`/interval, or sustained high rate with
  `380=8/9/10` responses; or a burst of an un-throttled MsgType.
- **False-positive sources:** legitimate high-frequency trading bursts within limits; market-open
  spikes.
- **Detector note (stateful):** sliding-window rate per (session, MsgType) vs negotiated limits;
  correlate `380` rejects and disconnects.
- **Direction:** inbound.

### 2.10 Application sequencing

#### D-APS-01 — ApplicationMessageRequest(BW) infinite / huge ApplSeqNum range
- **Vector ID(s):** SV-SESS-24
- **Category:** SESS / application-sequencing
- **Detection signal:** inbound `ApplicationMessageRequest(35=BW)` with `ApplEndSeqNum(1183)=0`
  (infinity) or a huge range, over an `ApplID`/`RefApplID(1355)` high-volume feed — forcing a bulk
  application-level re-stream (the app-layer analogue of D-RSD-01). Fields: `ApplReqType(1347)`,
  `ApplBegSeqNum(1182)`, `ApplEndSeqNum(1183)`.
- **Statefulness:** STATELESS to flag `35=BW ∧ 1183=0` (or huge). Amplification is stateful if you
  measure induced egress.
- **Severity/Confidence:** medium / medium. Single `BW` can demand very large re-streams; lower
  reach than session resend (opt-in feeds).
- **True-positive signature:** `35=BW` with `1183=0` or an enormous `1182..1183` span, repeated.
- **False-positive sources:** legitimate drop-copy / late-join replay of a feed.
- **Detector note (stateless + context):** flag the infinity sentinel / huge span; escalate on
  repetition.
- **Direction:** inbound.

#### D-APS-02 — ApplicationMessageReport(BY) reset + dual 1352/43 camouflage
- **Vector ID(s):** SV-SESS-25
- **Category:** SESS / application-sequencing
- **Detection signal:** inbound `ApplicationMessageReport(35=BY)` with `ApplReportType(1426)=0`
  (Reset) setting `ApplNewSeqNum(1399)` to rewind/advance an application counter independently of
  session `34`; or injected messages carrying **both** `ApplResendFlag(1352)=Y` and
  `PossDupFlag(43)=Y` to appear doubly-legitimate and slip past one layer's dedup.
- **Statefulness:** STATELESS to flag `35=BY ∧ 1426=0`, or the `1352=Y ∧ 43=Y` combo on one message.
  STATEFUL to detect the two-layer counter divergence (track both session `34` and app `1181`/`1399`).
- **Severity/Confidence:** medium / low. Documented ambiguity (app vs session independence) ripe for
  mishandling, but legitimately used during overlapping recovery → low confidence.
- **True-positive signature:** `35=BY|1426=0` unsolicited; or application messages with `1352=Y`
  **and** `43=Y` together.
- **False-positive sources:** genuine overlapping session+application recovery (the spec explicitly
  permits dual flags).
- **Detector note:** flag the reset and the dual-flag combo; enrich with app-counter tracking.
- **Direction:** inbound.

### 2.11 Time

#### D-TIM-01 — SendingTime precision / leap-second / format abuse
- **Vector ID(s):** SV-SESS-31
- **Category:** SESS / framing (time)
- **Detection signal:** `SendingTime(52)` (or any UTCTimestamp) with: 12-digit (picosecond)
  fractions sent to a low-precision peer; a leap-second value `…-23:59:60.nnn`; or structurally
  malformed timestamps (missing dash, wrong field widths, seconds=60 off a leap boundary, odd
  fraction widths not in {0,3,6,9,12}).
- **Statefulness:** STATELESS (format inspection of one field).
- **Severity/Confidence:** medium / low. Parser-robustness target; precision/leap handling varies and
  many benign encoders differ → low confidence.
- **True-positive signature:** `52` not matching `^\d{8}-\d{2}:\d{2}:\d{2}(\.\d{3,12})?$` with
  valid ranges (SS 00–60, leap only at 23:59:60), or fraction width ∉ {0,3,6,9,12}.
- **False-positive sources:** peers using higher precision than negotiated; legitimate leap seconds;
  nanosecond-capable venues.
- **Detector note (stateless):** strict UTCTimestamp regex + range check on all time fields
  (`52`, `60 TransactTime`, `122 OrigSendingTime`, etc.).
- **Direction:** inbound.

---

## 3. STRUCT detectors

> All STRUCT presence/validity detectors require the **DataDictionary** for the negotiated
> `BeginString(8)`. For each flagged message, apply the **reject-vs-silent-accept oracle** (§0.3):
> if no `Reject(35=3)`/`BusinessMessageReject(35=j)` follows, the message was silently accepted —
> elevate severity (the malformed structure reached the application/matching layer).

### 3.1 Required / conditional presence (required)

#### D-REQ-01 — Required body field omitted
- **Vector ID(s):** AV-STRUCT-01, SV-STRUCT-1
- **Category:** STRUCT / required
- **Detection signal:** a message is missing a field its MsgType marks `presence="required"` in the
  dictionary — e.g. `NewOrderSingle(35=D)` without `ClOrdID(11)` (also `55`/`54`/`60`/`38`/`40`).
  Reject-expected `373=1 RequiredTagMissing`.
- **Statefulness:** STATELESS (per-message, dictionary-driven).
- **Severity/Confidence:** high / high. Missing required field is unambiguous given the dictionary;
  silent accept (no `373=1`) corrupts order state (e.g. null ClOrdID breaks correlation).
- **True-positive signature:** for `msgType`, `required_fields(msgType) ⊄ fields_present`.
- **False-positive sources:** dictionary mismatch (wrong FIX version / custom dictionary where the
  field is optional); a legitimately customized venue dictionary. Use the exact negotiated dict.
- **Detector note (stateless):** per MsgType, set-difference required vs present (header-scope aware).
- **Direction:** inbound (outbound built by our engine, normally complete).

#### D-REQ-02 — Required header / trailer field omitted
- **Vector ID(s):** AV-STRUCT-02, SV-STRUCT-2, SV-STRUCT-4
- **Category:** STRUCT / required
- **Detection signal:** a required **header** field missing — `BeginString(8)`, `BodyLength(9)`,
  `MsgType(35)`, `MsgSeqNum(34)`, `SenderCompID(49)`, `TargetCompID(56)`, `SendingTime(52)` — or the
  required **trailer** `CheckSum(10)`. CompID omission → `373=9`; others → `373=1`; missing `10` is
  a framing fault (parser may stall — cross-ref D-FRM-06).
- **Statefulness:** STATELESS.
- **Severity/Confidence:** high / high. Missing CompID is routing/auth-adjacent; missing `10` stalls
  the receive loop.
- **True-positive signature:** any required header/trailer tag absent.
- **False-positive sources:** log truncation (line cut off before `10`); very old FIX versions with
  a different required set.
- **Detector note (stateless):** check the fixed header/trailer required set independent of MsgType.
- **Direction:** inbound.

#### D-REQ-03 — Conditionally-required field omitted
- **Vector ID(s):** AV-STRUCT-03, SV-STRUCT-5, SV-STRUCT-6, SV-STRUCT-7, SV-STRUCT-8
- **Category:** STRUCT / required (conditional)
- **Detection signal:** a trigger field/value is present but its **dependent** field is absent.
  Requires a **prose-derived conditional-rule table** (Orchestra `presence="required"` cannot
  express these). Key cases:
  - `OrdType(40)=3`(Stop)/`4`(Stop-limit) but no `StopPx(99)` — **SV-STRUCT-5, critical**.
  - `OrdType(40)` ∈ limit set {2,4,K,…} but no `Price(44)` — **SV-STRUCT-6, critical**.
  - In a `MDIncGrp` entry: `MDUpdateAction(279)=0` (New) with `MDEntryType(269)` ∈ {0,1,2,B,C} but
    no `MDEntrySize(271)`; or `269` not in {A,B,C}/=Q with no `MDEntryPx(270)` — **SV-STRUCT-7**.
  - An order-entry group entry with none of `OrderEntryID(2430)`, `ClOrdID(11)`, `OrderID(37)`
    ("at-least-one-of") — **SV-STRUCT-8**.
  Reject-expected `BusinessMessageReject(35=j)`, `BusinessRejectReason(380)=5 Conditionally
  Required Field Missing`.
- **Statefulness:** STATELESS (single-message, given the conditional table).
- **Severity/Confidence:** critical / medium. A priced order type with no price is economically
  dangerous and the spec explicitly names the gap. Medium confidence because the conditional table
  is prose-sourced and some conditions are venue-specific.
- **True-positive signature:** trigger value present ∧ dependent absent, per the table.
- **False-positive sources:** venue-specific conditional rules that differ; defaults applied
  downstream; mis-encoded trigger. Tune the table per venue.
- **Detector note (stateless):** implement a `(trigger field, value-set [, enclosing group]) →
  dependent field(s)` table; for "at-least-one-of", a set-presence rule.
- **Direction:** inbound.

#### D-REQ-04 — Required component present but all members omitted
- **Vector ID(s):** SV-STRUCT-20
- **Category:** STRUCT / required
- **Detection signal:** a message mandates a component (e.g. `Instrument` on orders) but **none** of
  its member fields appear (no `Symbol(55)`, `SecurityID(48)`, `SecurityIDSource(22)`, …) — a
  structurally empty required component (boundary is logical, not wire-delimited). Reject-expected
  `373=1` (component's own required member) or `35=j 380=5/2 Unknown Security`.
- **Statefulness:** STATELESS (dictionary expands the component to its members).
- **Severity/Confidence:** high / medium. An order with no instrument identification must not match.
- **True-positive signature:** required component's member-set ∩ fields_present = ∅.
- **False-positive sources:** instrument identified by an alternative/custom member not in the base
  dictionary; venue uses a different identification scheme.
- **Detector note (stateless):** recursively expand each `presence="required"` component to its
  members; flag when none present.
- **Direction:** inbound.

### 3.2 Unknown / foreign fields

#### D-FLD-01 — Undefined / unknown tag; reserved / UDF ranges
- **Vector ID(s):** AV-STRUCT-04, SV-STRUCT-26
- **Category:** STRUCT / unknown-field
- **Detection signal:** a tag number **not in the dictionary at all** (`9999999=…`); or a `tag ≤ 0`
  / non-numeric tag name; and range-bucketed probes: UDF `5000–9999`, bilateral `20000–39999`,
  internal `10000–19999`, and **`50000+` reserved ("should not be used")**. Reject-expected
  `373=3 UndefinedTag` or `373=0 InvalidTagNumber`; accept if `AllowUnknownMsgFields`/validation off.
- **Statefulness:** STATELESS (dictionary membership + range bucket).
- **Severity/Confidence:** medium / medium. Engines commonly pass through unknown tags (benign
  leniency), so confidence is medium; a `50000+` reserved tag is the stronger signal.
- **True-positive signature:** tag ∉ dictionary; `tag ≤ 0`; tag in the 50000+ reserved range.
- **False-positive sources:** widespread legitimate UDF usage (5000–9999, 20000–39999); venue
  private fields. Treat UDF ranges as low/info, reserved-50000+ and `tag≤0` as higher.
- **Detector note (stateless):** parameterize by range bucket; label the spec-expected disposition
  per bucket; apply the accept/reject oracle for fingerprinting.
- **Direction:** inbound.

#### D-FLD-02 — Tag defined but not valid for this MsgType (foreign field)
- **Vector ID(s):** AV-STRUCT-05, SV-STRUCT-25
- **Category:** STRUCT / unknown-field
- **Detection signal:** a real, well-formed field that is **not in this MsgType's structure** —
  e.g. `StopPx(99)` in a `Heartbeat(0)`, `MDEntryType(269)` in a `NewOrderSingle(D)`, `LegPrice(566)`
  in a plain NOS body. Reject-expected `373=2 TagNotDefinedForThisMessageType`.
- **Statefulness:** STATELESS (dictionary: is `tag ∈ valid_fields(msgType)`?).
- **Severity/Confidence:** medium / medium. Silent acceptance of out-of-type fields is a common
  leniency and a smuggling surface; a stray field may be mistaken for a conditional trigger.
- **True-positive signature:** `tag ∈ dictionary` but `tag ∉ valid_fields(msgType)`.
- **False-positive sources:** venue extensions adding fields to a message beyond the base dictionary;
  group member fields misattributed by a naive flat check (scope-aware parsing required).
- **Detector note (stateless):** per-MsgType allowed-field set from the dictionary, scope-aware for
  groups/components.
- **Direction:** inbound.

#### D-FLD-03 — Tag present with empty value
- **Vector ID(s):** SV-STRUCT-27 (empty-value facet; SOH facet is in D-FRM-03)
- **Category:** STRUCT / unknown-field
- **Detection signal:** a field present with no value — `38=` (empty `OrderQty`), `58=`, etc.
  Reject-expected `373=4 TagSpecifiedWithoutAValue`; empty values may be silently defaulted.
- **Statefulness:** STATELESS.
- **Severity/Confidence:** medium / medium. Empty-valued required/economic fields are anomalous;
  some engines default them silently.
- **True-positive signature:** a `tag=` immediately followed by SOH (zero-length value).
- **False-positive sources:** fields where an empty value is conventionally tolerated; benign for a
  handful of optional string fields.
- **Detector note (stateless):** detect zero-length values; weight by whether the field is required
  or economically significant (qty/price/side).
- **Direction:** inbound.

### 3.3 Field & region ordering (ordering)

#### D-ORD-01 — Body / intra-group field order (C++ silently sorts)
- **Vector ID(s):** AV-STRUCT-17, SV-STRUCT-16
- **Category:** STRUCT / ordering
- **Detection signal:** body fields (or group members after the delimiter) not in the
  dictionary-defined order — e.g. NOS body scrambled, or within a Parties entry `452` before `447`
  when the dict defines `448,447,452`. QuickFIX C++ **silently sorts** body fields post-parse
  (divergence from strict engines); reject-expected on strict engines `373=15` (group) / `373=14`.
- **Statefulness:** STATELESS (order check vs dictionary sequence).
- **Severity/Confidence:** low / low. Leniency here is common and usually benign; mainly a
  cross-implementation divergence oracle and a way to smuggle past order-sensitive middleboxes.
- **True-positive signature:** field order ≠ dictionary order (delimiter fixed for groups).
- **False-positive sources:** very common — many engines and senders are lenient on body order; QFJ
  vs C++ differ. Low confidence by design; use mainly for fingerprinting.
- **Detector note (stateless):** compare the observed tag sequence to the dictionary's defined order
  per scope.
- **Direction:** inbound.

#### D-ORD-02 — Header field in body / body field in header (region swap)
- **Vector ID(s):** AV-STRUCT-16, SV-STRUCT-23
- **Category:** STRUCT / ordering
- **Detection signal:** a header field (e.g. `SendingTime(52)`, `MsgSeqNum(34)`,
  `OnBehalfOfCompID(115)`) appearing **after** body fields have begun, or a body field (e.g.
  `OrderQty(38)`) interleaved **inside** the header region (between `35` and `49`). QuickFIX C++
  sets `m_validStructure=false`; reject-expected `373=14`. Routing/sequence header fields placed
  late may be silently lost → mis-delivery.
- **Statefulness:** STATELESS (header-set vs body-set partition from the dictionary).
- **Severity/Confidence:** medium / medium. Silently lost routing fields (e.g. `115`) cause
  mis-delivery; strict vs lenient engines diverge.
- **True-positive signature:** a StandardHeader-member tag positioned after the first non-header
  body tag, or vice versa.
- **False-positive sources:** header fields "embedded within encrypted data section" (spec allows),
  muddying strict positional checks; custom header extensions.
- **Detector note (stateless):** partition fields into header-set (StandardHeader members) vs body;
  detect cross-placement.
- **Direction:** inbound.

### 3.4 Duplicate tags (duplicate)

#### D-DUP-01 — Duplicate scalar tag (first-wins / last-wins parameter pollution)
- **Vector ID(s):** AV-STRUCT-06, SV-STRUCT-24
- **Category:** STRUCT / duplicate
- **Detection signal:** the same **non-group** tag appears **twice (or more) in the same scope** with
  (especially) **different values** — e.g. `38=100 … 38=1000000`, or two `44`(Price), or a
  duplicated `55`. Reject-expected `373=13 TagAppearsMoreThanOnce`. If not rejected, which value
  binds is unspecified across implementations → engine and risk system can disagree (smuggling).
- **Statefulness:** STATELESS (count tag occurrences within one message scope).
- **Severity/Confidence:** critical / high. Classic parameter pollution; two endpoints parsing the
  same bytes to different economic values is a spoofing/smuggling primitive. Rarely benign.
- **True-positive signature:** a scalar (non-group-member) tag occurring >1 time in the same scope,
  divergent values being the high-severity case.
- **False-positive sources:** legitimate **repeating-group member** fields (which recur by design) —
  the detector must be group-aware and only flag true scalars. Duplicate with identical values is a
  lower-severity redundancy.
- **Detector note (stateless):** parse scope-aware (group members excluded); for each scalar tag,
  count occurrences; record first vs last value divergence. Also flag a duplicated **count field**
  (`NoXXX`).
- **Direction:** inbound (outbound is engine-serialized, single-valued).

#### D-DUP-02 — Duplicate delimiter / repeated member within one group entry
- **Vector ID(s):** AV-STRUCT-07
- **Category:** STRUCT / duplicate (group)
- **Detection signal:** within a single group entry a member field (or the delimiter) is repeated
  before the next entry begins — e.g. `NoPartyIDs(453)=1` with `448=X 448=Y 452=1` (two `448` in one
  entry). QuickFIX C++ starts a **new** entry on an already-set field → entry-count desync vs the
  declared `453`.
- **Statefulness:** STATELESS (intra-group parse vs declared count).
- **Severity/Confidence:** medium / medium. Group desync / party/allocation confusion.
- **True-positive signature:** a group member appears twice within what should be one entry, or the
  parsed entry count ≠ declared `NoXXX` due to repeats.
- **False-positive sources:** legitimately multiple entries where the delimiter recurs correctly
  (that's a new entry, not a repeat) — the detector must track entry boundaries precisely.
- **Detector note (stateless):** parse the group; detect a member re-appearing before a delimiter
  that would start a new entry; compare parsed-entry count to `NoXXX`.
- **Direction:** inbound.

### 3.5 Repeating-group count & desync (group-desync)

#### D-GRP-01 — NoXXX count > actual entries (under-population / absorption)
- **Vector ID(s):** AV-STRUCT-08, SV-STRUCT-10
- **Category:** STRUCT / group-desync
- **Detection signal:** declared `NoXXX` (e.g. `453=3`) exceeds the number of entries actually
  present (e.g. 1). The parser expecting more delimiters may **absorb following body/trailer
  fields** into phantom entries. Reject-expected `373=16 IncorrectNumInGroupCountForRepeatingGroup`.
- **Statefulness:** STATELESS (declared count vs parsed entries, dictionary-driven).
- **Severity/Confidence:** high / high. A single integer edit cascades into message mis-parse / trailer
  absorption.
- **True-positive signature:** `int(NoXXX) > parsed_entry_count`.
- **False-positive sources:** a dictionary mismatch on what the group's members are (miscount);
  otherwise rare.
- **Detector note (stateless):** parse the group per the dictionary; compare parsed entries to the
  declared count.
- **Direction:** inbound.

#### D-GRP-02 — NoXXX count < actual entries (over-population / truncation)
- **Vector ID(s):** AV-STRUCT-09, SV-STRUCT-11
- **Category:** STRUCT / group-desync
- **Detection signal:** declared `NoXXX` (e.g. `453=1`) is less than the entries present (e.g. 2+).
  The parser closes the group after the declared count, then meets a delimiter tag where a body
  field is expected → reject (`373=16`/`373=14`) **or silent truncation** (the extra entries are
  dropped — a correctness/compliance hazard).
- **Statefulness:** STATELESS.
- **Severity/Confidence:** high / high. Silent truncation drops data the sender believes it sent.
- **True-positive signature:** `int(NoXXX) < parsed_entry_count` (delimiter tag recurs after the
  group should have closed).
- **False-positive sources:** dictionary mismatch; rare otherwise.
- **Detector note (stateless):** same group parse; detect the delimiter re-appearing beyond the
  declared count.
- **Direction:** inbound.

#### D-GRP-03 — NoXXX = 0 (or count>0 with empty body) with/without entries
- **Vector ID(s):** AV-STRUCT-11, SV-STRUCT-12, SV-STRUCT-19
- **Category:** STRUCT / group-desync
- **Detection signal:** `NoXXX=0` followed by a delimiter tag (orphan entry → the member fields
  become out-of-context body tags); or `NoXXX=0` with nothing (possible zero-count reject); or
  `NoXXX>0` with **no delimiter at all** following (count present but body empty → the parser
  absorbs unrelated sibling fields, e.g. `453=2` then `54=1|38=100`).
- **Statefulness:** STATELESS.
- **Severity/Confidence:** medium / medium. Cross-implementation divergence (is present `NoXXX=0`
  legal?) and field-misattribution risk.
- **True-positive signature:** `NoXXX=0` with a following group-delimiter tag; or `NoXXX>0` with the
  delimiter absent.
- **False-positive sources:** some engines/venues legitimately allow a present `NoXXX=0`; harmless
  empties.
- **Detector note (stateless):** emit the triple {absent, 0-no-entries, 0-with-entries} distinction;
  flag count>0 with no delimiter.
- **Direction:** inbound.

#### D-GRP-04 — NoXXX negative / non-numeric / empty
- **Vector ID(s):** AV-STRUCT-12, SV-STRUCT-14
- **Category:** STRUCT / group-desync
- **Detection signal:** a `NoXXX` (NUMINGROUP) count value that is negative (`453=-1`), non-numeric
  (`453=abc`/`1X`), whitespace, or empty (`453=`). Reject-expected `373=6
  IncorrectDataFormatForValue` (or `373=4` for empty). `-1` is a classic under/overflow trigger
  (signed → huge unsigned loop bound in a weak parser).
- **Statefulness:** STATELESS (value format of the count field).
- **Severity/Confidence:** high / high. Never legitimate; combines data-format + loop-count fault.
- **True-positive signature:** `NoXXX` value not matching `^[0-9]+$`.
- **False-positive sources:** essentially none.
- **Detector note (stateless):** identify count fields via the dictionary (NUMINGROUP type); regex
  the value.
- **Direction:** inbound.

#### D-GRP-05 — NoXXX huge → pre-allocation OOM **[REFUTED on QuickFIX]**
- **Vector ID(s):** AV-STRUCT-10, SV-STRUCT-13
- **Category:** STRUCT / group-desync
- **Detection signal:** a very large `NoXXX` (`453=2000000000`, `INT_MAX`, `10^18`) with few/no
  actual entries.
- **Statefulness:** STATELESS (flag the huge value) — collapses to the count-desync signal D-GRP-01.
- **Severity/Confidence:** **info / low. REFUTED:** per orchestrator source review, QuickFIX C++
  `setGroup` **never reads the count value** (allocates per parsed entry), and QuickFIX-J
  `getGroupCount` = actual `groupList.size()` (compare-only). So on both engines there is **no
  pre-allocation OOM** — only a count-mismatch reject. **Do NOT raise a memory-DoS alert.** Emit at
  most an `info` robustness probe (some non-QuickFIX engines *do* pre-allocate; the real queue-OOM
  lives at the session layer — D-SEQ-02).
- **True-positive signature:** huge `NoXXX` ≫ parsed entries — but report as a count-desync
  (D-GRP-01), not OOM.
- **False-positive sources:** n/a (this is the documented tested-and-closed negative; retaining it
  as an info probe preserves scanner credibility).
- **Detector note (stateless):** if a target is known to pre-allocate, raise; otherwise fold into
  D-GRP-01 and label `info`.
- **Direction:** inbound.

#### D-GRP-06 — Missing delimiter / wrong first member in an entry
- **Vector ID(s):** AV-STRUCT-13, SV-STRUCT-3, SV-STRUCT-15
- **Category:** STRUCT / group-desync
- **Detection signal:** a group entry that does **not begin with the group's designated delimiter
  (first) field** — e.g. an entry starting with `MDEntryPx(270)` instead of `MDEntryType(269)`, or
  `PartyRole(452)` before `PartyID(448)`, or `NoPartyIDs(453)=1` whose entry never emits the `448`
  delimiter at all. Reject-expected `373=15 RepeatingGroupFieldsOutOfOrder` (or `373=1`). A
  delimiter-keyed parser may fail to open the entry → group ends early / desync.
- **Statefulness:** STATELESS (dictionary gives each group's delimiter/first member).
- **Severity/Confidence:** high / high. Delimiter is the structural anchor; wrong/absent first
  member is the canonical and subtlest group desync.
- **True-positive signature:** first field of an entry ≠ the group's delimiter tag.
- **False-positive sources:** dictionary disagreement on the delimiter; otherwise rare.
- **Detector note (stateless):** for each group, know the delimiter; verify every entry starts with it.
- **Direction:** inbound.

#### D-GRP-07 — Interleaved / overlapping groups
- **Vector ID(s):** AV-STRUCT-14, SV-STRUCT-18
- **Category:** STRUCT / group-desync
- **Detection signal:** a field belonging to **group B** injected inside an open **group A** entry —
  e.g. `NoTargetPartyIDs(1461)` or `NoMDEntries(268)` appearing mid-`NoPartyIDs(453)` entry before
  that entry's members complete. Reject-expected `373=15`/`373=14`; or cross-group contamination
  (A absorbs B's tag, or A silently closes) → two corrupted groups.
- **Statefulness:** STATELESS (dictionary: which tags belong to which group; detect boundary
  violation).
- **Severity/Confidence:** medium / medium. Weaponizes tag-validity overlap between adjacent groups.
- **True-positive signature:** a second group's delimiter/member appearing before the current
  group's entry is structurally complete.
- **False-positive sources:** legitimately **nested** groups (B nested inside A by the dictionary) —
  must not be flagged (that is D-NST-01 territory, structurally valid).
- **Detector note (stateless):** scope-aware parse; flag a foreign group's tag opening inside an
  unterminated sibling group entry (distinct from defined nesting).
- **Direction:** inbound.

### 3.6 Nesting (nesting)

#### D-NST-01 — Deep nested repeating groups + nested count mismatch
- **Vector ID(s):** AV-STRUCT-15, SV-STRUCT-17
- **Category:** STRUCT / nesting
- **Detection signal:** (a) **depth/breadth**: groups nested to (or beyond) the dictionary's maximum
  legitimate depth with maximal entry counts (e.g. `NoLegs → NoLegStipulations`, `NoPartyIDs →
  NoPartySubIDs`) — a recursion/stack-growth probe; (b) **nested count mismatch**: an inner
  `NoXXX` (e.g. `NoPartySubIDs(802)=2`) not matching its actual sub-entries, mis-scoping the
  remainder of the OUTER entry. Reject-expected `373=16` at the nested level.
- **Statefulness:** STATELESS (depth count + per-level count check within one message).
- **Severity/Confidence:** low / low. On QuickFIX, nesting is **bounded by the dictionary**, so
  stack exhaustion is unlikely (needs dynamic verification; venues with custom deep dictionaries
  differ). The nested count-mismatch facet is the more reliable signal (reuse D-GRP-01/02 per level).
- **True-positive signature:** nesting depth at/over dictionary max; or inner `NoXXX ≠ actual` at any
  level.
- **False-positive sources:** legitimately deep multileg/allocation messages within limits.
- **Detector note (stateless):** recursive group parse tracking depth; apply D-GRP-01/02/04 at each
  level; flag depth beyond the dictionary's structural max.
- **Direction:** inbound.

### 3.7 Length / DATA field desync (length)

#### D-LEN-01 — Length/DATA field desync (absent / wrong / non-adjacent)
- **Vector ID(s):** SV-STRUCT-9 (structural lens of the framing signal in D-FRM-03)
- **Category:** STRUCT / length-data (framing-adjacent)
- **Detection signal:** for each length-prefixed DATA pair, the Length field is **absent**, its value
  **≠ the actual byte count** of the data field, or it does **not immediately precede** the data
  field. Pairs: `RawDataLength(95)/RawData(96)`, `XmlDataLen(212)/XmlData(213)`,
  `EncodedTextLen(354)/EncodedText(355)`, `SecureDataLen(90)/SecureData(91)`,
  `SignatureLength(93)/Signature(89)`, `EncodedSecurityDescLen(350)/EncodedSecurityDesc(351)`, and
  the FpML `XMLDATA` family. A wrong/absent length makes the parser read past or short of the real
  boundary → embedded SOH reinterpreted as delimiters (injection/desync). Reject-expected `373=6`/
  `373=1`.
- **Statefulness:** STATELESS `[RAW-BYTES]` (recompute payload bytes vs declared Length, check
  adjacency).
- **Severity/Confidence:** critical / medium. Direct injection/desync primitive (same class as the
  CPP-C1 over-read). Medium confidence because DATA fields legitimately contain SOH — the check must
  be exact-byte.
- **True-positive signature:** `declared_len ≠ measured_payload_bytes`; or the Length tag absent /
  not immediately before its data tag.
- **False-positive sources:** correct DATA fields (length matches, even with embedded SOH — benign);
  byte-vs-char counting for UTF-8 encoded fields (count **bytes**, not characters).
- **Detector note (stateless):** this IS the structural face of D-FRM-03; implement once and map both
  IDs. Use the dictionary's DATA↔Length pairing.
- **Direction:** inbound.

### 3.8 MsgType (msgtype)

#### D-MSG-01 — Unknown / empty / multi-char MsgType(35)
- **Vector ID(s):** AV-STRUCT-20, SV-STRUCT-28 (a,b,c)
- **Category:** STRUCT / msgtype
- **Detection signal:** `MsgType(35)` value is undefined (`35=ZZ`), empty (`35=`), or an
  unexpected multi-char/aliased value (`35=DD`, lowercase confusion). Reject-expected `373=11
  InvalidMsgType` (undefined), `373=4` (empty), or `35=j 380=3 Unsupported Message Type` (valid but
  unsupported — a message-set enumeration oracle).
- **Statefulness:** STATELESS (dictionary membership of the `35` value).
- **Severity/Confidence:** high / high. `35` drives the entire parse/validate/dispatch path; an
  undefined value is unambiguous.
- **True-positive signature:** `35` value ∉ defined MsgTypes for the negotiated dictionary; or empty.
- **False-positive sources:** venue custom MsgTypes not in the base dictionary (UDF message types);
  newer FIX message types under an older dictionary. Use the exact negotiated dict.
- **Detector note (stateless):** validate `35` against the dictionary's MsgType set; bucket
  undefined vs valid-unsupported via the reject oracle.
- **Direction:** inbound.

#### D-MSG-02 — MsgType valid but body borrowed from another type
- **Vector ID(s):** AV-STRUCT-19, SV-STRUCT-28 (d)
- **Category:** STRUCT / msgtype
- **Detection signal:** `35` is a valid type (e.g. `D`) but the body is populated with another
  message's field set (e.g. MarketDataRequest fields `262`,`263`,`264`,`267` in a `35=D`). Produces
  a cascade of `373=2` (tag-not-for-this-type) + `373=1` (missing required) — or, worse, required-
  field checks for the **declared** type run against the **wrong** body (silent mis-dispatch).
- **Statefulness:** STATELESS (compare the field set to the declared MsgType's structure).
- **Severity/Confidence:** medium / medium. Probes how the gateway routes on `35` vs body.
- **True-positive signature:** a high fraction of body fields invalid for the declared MsgType while
  matching another type's structure.
- **False-positive sources:** heavily customized/extended message bodies; overlapping common fields.
- **Detector note (stateless):** score the body's field set against the declared type's structure and
  against other types'; flag when another type is a much better fit.
- **Direction:** inbound.

### 3.9 Meta

#### D-META-01 — Validation-posture probe (accept-vs-reject oracle)
- **Vector ID(s):** AV-STRUCT-18
- **Category:** STRUCT / meta
- **Detection signal:** this is the **umbrella correlation** that gates whether the whole STRUCT
  class is live on a deployment. For messages flagged by any STRUCT detector (D-REQ-*, D-FLD-*,
  D-DUP-*, D-GRP-*, D-MSG-*), observe whether the local side **rejected** them (`35=3` with the
  expected `373=…`, or `35=j`) or **silently accepted** them (session proceeds, no reject). A
  pattern of malformed structures accepted without reject ⇒ `UseDataDictionary=N` / `Validate*=N`
  ⇒ the entire structural-injection surface reaches the application unchecked.
- **Statefulness:** STATEFUL. Correlate each flagged inbound message with the subsequent outbound
  reject (by `RefSeqNum(45)`), aggregated per session to infer validation posture.
- **Severity/Confidence:** high / meta. Not a single-vector alert; it is the posture fingerprint
  that **raises the confidence and severity of every other STRUCT finding** when it shows silent
  accept.
- **True-positive signature:** ≥K structurally-invalid inbound messages with **no** corresponding
  reject and continued session flow.
- **False-positive sources:** rejects delayed/batched; business-layer rejects that don't look like
  `35=3`; a dictionary mismatch making SAFIX over-flag (which would also suppress real rejects).
- **Detector note (stateful):** maintain per session a tally of {flagged, rejected, silently
  accepted}; emit a posture verdict (strict / relaxed / off) and feed it back as a severity
  multiplier for D-REQ-*/D-FLD-*/D-DUP-*/D-GRP-*/D-MSG-*.
- **Direction:** correlates inbound (the probe) with outbound (the reject).

---

## 4. STATE MODEL NEEDED

A stateful SAFIX engine must maintain the following **per FIX session** (keyed by the
`(BeginString, SenderCompID, TargetCompID)` triple, direction-aware). Stateless detectors need
none of this; the variables below back the 29 stateful vectors.

**Session identity & lifecycle**
- `begin_string` — negotiated `BeginString(8)` → selects the DataDictionary. (D-FRM-04, all STRUCT)
- `local_comp_id`, `peer_comp_id` — bound `(49,56)` pair captured at the accepted Logon; used for
  direction inference and spoof/swap detection. (D-ID-01, direction)
- `logon_state` ∈ {disconnected, awaiting_logon, logged_on, logout_in_progress}; `received_logon`
  bool; `sent_logon` bool. (D-STA-01/02/03/04/06)
- Connection events (from `event.log`): connect/disconnect timestamps, logon-timeout events.
  (D-STA-02 logon flood/half-open)

**Sequence numbers**
- `expected_in` — next expected inbound `MsgSeqNum(34)`. (D-SEQ-01/02/03, D-GF-01/02/03/04, D-RPL-01)
- `max_sent_out` / `next_out` — highest outbound seqnum we have emitted. (D-RSD-03 out-of-history,
  D-LGN-03 NextExpected)
- `seen_in_seqnums` — set (or bitmap) of inbound seqnums already processed, plus
  `seen_in_body_hash[seqnum]` to distinguish a genuine resend from a forged duplicate. (D-SEQ-03
  duplicate, D-RPL-01)
- `outstanding_queued` — map `{seqnum: message}` of too-high inbound messages held pending a gap
  fill; its size/growth is the OOM signal and its membership powers the smuggling-chain match.
  (D-SEQ-02, D-GF-04)

**Resend / recovery**
- `resend_in_progress` bool + the pending resend range we requested; and inbound ResendRequests seen
  (for flood counting). (D-GF-03 outside-recovery, D-RSD-02)
- `outstanding_resend_requests` — ResendRequests we have issued but not yet seen satisfied.
  (D-GF-03, correlation)

**Replay / time**
- `seen_clordids` (and other business keys) — for PossResend/duplicate-order detection. (D-RPL-03)
- Trusted `receipt_clock` per message (log/pcap timestamp) — for SendingTime-window and all rate
  windows; `SendingTime(52)` kept separately and treated as untrusted inbound. (D-RPL-02, D-TIM-01)

**Negotiated session parameters (captured at Logon `35=A`)**
- `heartbt_int` — `HeartBtInt(108)` (both sides' agreed value). (D-LGN-02, D-STA-07 timing)
- `encrypt_method` — `EncryptMethod(98)`. (D-LGN-01)
- `max_message_size` — `MaxMessageSize(383)`. (D-FRM-07)
- `throttle_params` — `ThrottleNoMsgs(1613)`, `ThrottleTimeInterval(1614)`, `ThrottleTimeUnit(1615)`,
  `ThrottleType(1612)`, `ThrottleAction(1611)`, and `ThrottleMsgTypeGrp` scope. (D-THR-01)
- `reset_schedule` — the configured/agreed sequence-reset window (to suppress benign `141=Y`).
  (D-STA-01)

**Test-request / heartbeat pairing**
- `outstanding_testreqids` — `TestReqID(112)` values we issued, pending a Heartbeat echo. (D-STA-07)
- inbound `TestRequest(35=1)` rate window. (D-STA-05)

**Identity / routing**
- `current_onbehalf` / `current_deliverto` — last-seen `115`/`128` for mid-session change detection;
  an allowlist of authorized routes. (D-ID-02)
- authorized `(49,56)` / route allowlist. (D-ID-01, D-ID-02)

**Application-sequencing (if the feed is used)**
- per-`RefApplID(1355)` application counters (`ApplBegSeqNum`/`ApplEndSeqNum` ranges requested,
  `ApplNewSeqNum(1399)`), tracked independently of session `34`. (D-APS-01, D-APS-02)

**Rate windows (generic sliding-window counters per session, per MsgType where noted)**
- Logon `35=A` attempts (D-STA-02); ResendRequest `35=2` (D-RSD-02); TestRequest `35=1` (D-STA-05);
  application-message rate per MsgType (D-THR-01); too-high-seqnum arrival rate (D-SEQ-02).

**Validation-posture accumulator (meta)**
- per session: counts of {STRUCT-flagged, rejected-with-373, business-rejected, silently-accepted},
  plus a derived posture verdict used as a severity multiplier. (D-META-01)

---

## 5. Appendix — reference

### 5.1 SessionRejectReason(373) codes (for the accept-vs-reject oracle)
`0` InvalidTagNumber · `1` RequiredTagMissing · `2` TagNotDefinedForThisMessageType ·
`3` UndefinedTag · `4` TagSpecifiedWithoutAValue · `5` ValueIsIncorrect ·
`6` IncorrectDataFormatForValue · `9` CompIDProblem · `10` SendingTimeAccuracyProblem ·
`11` InvalidMsgType · `13` TagAppearsMoreThanOnce · `14` TagSpecifiedOutOfRequiredOrder ·
`15` RepeatingGroupFieldsOutOfOrder · `16` IncorrectNumInGroupCountForRepeatingGroup ·
`17` NonDataValueIncludesFieldDelimiter. BusinessRejectReason(380): `3` Unsupported Message Type,
`5` Conditionally Required Field Missing, `7` DeliverTo firm not available, `8/9/10` throttle.

### 5.2 Key tag quick-reference used by detectors
Framing/header: `8` BeginString, `9` BodyLength, `35` MsgType, `34` MsgSeqNum, `49` SenderCompID,
`56` TargetCompID, `52` SendingTime, `10` CheckSum, `43` PossDupFlag, `97` PossResend,
`122` OrigSendingTime, `115` OnBehalfOfCompID, `128` DeliverToCompID, `627-630` HopGrp.
Session admin: `A` Logon (`98` EncryptMethod, `108` HeartBtInt, `141` ResetSeqNumFlag,
`789` NextExpectedMsgSeqNum, `383` MaxMessageSize), `0` Heartbeat / `1` TestRequest (`112` TestReqID),
`2` ResendRequest (`7` BeginSeqNo, `16` EndSeqNo), `4` SequenceReset (`123` GapFillFlag,
`36` NewSeqNo), `5` Logout (`1409` SessionStatus, `58` Text), `3` Reject (`45` RefSeqNum,
`373` SessionRejectReason), `j` BusinessMessageReject (`380` BusinessRejectReason).
DATA/Length pairs: `95/96`, `90/91`, `93/89`, `212/213`, `354/355`, `350/351`.
Groups cited: `453` NoPartyIDs (delim `448` PartyID; `447`,`452`; nested `802` NoPartySubIDs,
`523`/`803`), `268` NoMDEntries (delim `269`; `270`,`271`,`279`), `1461` NoTargetPartyIDs.
Order: `11` ClOrdID, `37` OrderID, `41` OrigClOrdID, `40` OrdType, `44` Price, `99` StopPx,
`38` OrderQty, `54` Side, `55` Symbol, `60` TransactTime.
App-sequencing: `BW` ApplicationMessageRequest, `BY` ApplicationMessageReport, `1182/1183`
ApplBeg/EndSeqNum, `1347` ApplReqType, `1355` RefApplID, `1352` ApplResendFlag, `1399` ApplNewSeqNum,
`1426` ApplReportType.

### 5.3 Coverage ledger (all 106 source IDs → detector)
- **AV-SESS-SEQ-01..13** → D-SEQ-01, D-SEQ-02, D-SEQ-03, D-SEQ-04, D-RSD-01, D-RSD-02, D-RSD-03,
  D-GF-01, D-GF-02, D-GF-01(huge), D-GF-03, D-RPL-01, D-GF-04.
- **AV-SESS-FRM-01..08** → D-FRM-01, D-FRM-02, D-FRM-03, D-FRM-04, D-FRM-05, D-FRM-06, D-FRM-02,
  D-FRM-03.
- **AV-SESS-STA-01..06** → D-STA-01, D-STA-02, D-STA-03, D-STA-04, D-STA-05, D-STA-06.
- **AV-STRUCT-01..20** → D-REQ-01, D-REQ-02, D-REQ-03, D-FLD-01, D-FLD-02, D-DUP-01, D-DUP-02,
  D-GRP-01, D-GRP-02, D-GRP-05, D-GRP-03, D-GRP-04, D-GRP-06, D-GRP-07, D-NST-01, D-ORD-02, D-ORD-01,
  D-META-01, D-MSG-02, D-MSG-01.
- **SV-SESS-1..31** → D-SEQ-01, D-SEQ-03, D-RPL-01, D-SEQ-04, D-RSD-01, D-RSD-03, D-GF-01, D-GF-02,
  D-GF-03, D-RPL-01, D-RPL-02, D-RPL-03, D-LGN-01, D-LGN-02, D-STA-01, D-STA-03/04, D-LGN-03,
  D-STA-06, D-STA-05, D-STA-07, D-ID-01, D-ID-02, D-THR-01, D-APS-01, D-APS-02, D-FRM-04/05,
  D-FRM-01/02, D-FRM-06, D-FRM-03, D-FRM-07, D-TIM-01.
- **SV-STRUCT-1..28** → D-REQ-01, D-REQ-02, D-GRP-06, D-REQ-02, D-REQ-03, D-REQ-03, D-REQ-03,
  D-REQ-03, D-LEN-01, D-GRP-01, D-GRP-02, D-GRP-03, D-GRP-05, D-GRP-04, D-GRP-06, D-ORD-01, D-NST-01,
  D-GRP-07, D-GRP-03, D-REQ-04, D-FRM-05, D-FRM-06, D-ORD-02, D-DUP-01, D-FLD-02, D-FLD-01,
  D-FRM-03/D-FLD-03, D-MSG-01/02.

*End of SESS & STRUCT detection specifications.*
