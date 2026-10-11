# SAFIX Scanner Architecture: Design Lessons from Established Security Tooling

> Research brief for **SAFIX** — a security scanner for the FIX trading protocol
> ("the Snort/Semgrep/Sigma of FIX message logs"). Python core, CLI + rich web UI,
> scans QuickFIX-format FIX logs, emits false-positive-aware alerts.
>
> Author: SAFIX architecture research · Date: 2026-10-11
> Scope: study Sigma, Snort/Suricata, Zeek, YARA, Semgrep, SARIF (+ Wireshark FIX
> dissector, ClamAV, osquery, CVSS) and distill concrete, transferable design
> recommendations.

---

## 0. TL;DR

- Adopt a **Sigma-style declarative YAML rule format**, specialized for FIX (tag-aware
  operators, `msg_types`, `direction`, `fix_versions`, `timeframe`/`count` correlation,
  `false_positives`, `confidence`, vector-ID references).
- Architect the engine as a **pipeline of clean layers**: parse → normalize → stateless
  match → stateful/correlation → aggregate/dedup/suppress → report. This is Zeek's "parse
  protocol into events, write policy in scripts" separation.
- Support **two detector kinds** behind one registry: (1) declarative YAML rules for the
  common case, (2) built-in Python detectors for complex stateful logic (order-book
  reconstruction, spoofing/layering, sequence-number state machines).
- Emit **SARIF 2.1.0** as the interchange format (plus native JSON and a human report).
- Control false positives with a layered model: **severity + confidence**, suppressions/
  allowlists, baseline/learning mode, thresholds, alert-vs-info tiers, and fingerprint dedup.

---

## 1. Tool-by-tool design lessons

### 1.1 Sigma — the declarative detection-as-code analogue (closest model for SAFIX)

**What it is.** Sigma is a vendor-agnostic YAML format for describing detections over log
data; a converter (`sigma`/pySigma) compiles rules into backend queries (Splunk, Elastic,
etc.). It is the single closest analogue to what SAFIX's rule format should be.

**Rule anatomy** (official SigmaHQ docs, https://sigmahq.io/docs/basics/rules.html):

- `title` — short summary (no "Detects when..." prefix).
- `id` — globally unique, recommended UUIDv4.
- `status` — one of `stable`, `test`, `experimental`, `deprecated`, `unsupported`.
- `description` — why the rule exists, when it fires.
- `references` — URL(s) / text.
- `author`, `date`, `modified` (ISO 8601), `license` (SPDX).
- `tags` — framework mappings: `attack.*` (MITRE ATT&CK), `car.*`, `cve.*`, `tlp.*`.
- `logsource` — `{category, product, service}` (+ optional `definition`). Describes the
  **kind** of data the rule targets.
- `detection` — one or more **named selections** + a `condition`.
- `falsepositives` — a human-readable list of known benign triggers. Note: converters do
  **not** parse this field; real exclusion must be done with filters in `detection`.
- `level` — `informational`, `low`, `medium`, `high`, `critical`. Guidance: info/low/medium
  are for display/charting; high/critical should raise a dedicated alert.

**Detection semantics (the important part):**
- A **map** of field→value pairs inside one selection is **AND**-linked.
- A **list of maps** is **OR**-linked.
- A **list of values** under one field is **OR** (e.g. `EventID: [4728,4729,4730]`).
- A plain `keywords` list is a field-agnostic OR search over the raw log.
- `condition` combines selection names with boolean logic, e.g.
  `(selection_one or selection_two) and not filter`. "selection and not filter" is the
  canonical allowlist idiom.
- **Modifiers** attach to a field with a pipe: `|contains`, `|startswith`, `|endswith`,
  `|re` (regex, disables wildcard parsing), `|all` (switch value-list from OR to AND),
  `|cidr`, `|base64`, `|wide`, `|windash`, `|exists`, and numeric `|gt`/`|gte`/`|lt`/`|lte`.

**Correlation / stateful counting** lives in a **separate correlation rule** (Sigma v2),
not in base detection rules (Sekoia docs, https://docs.sekoia.io/xdr/features/detect/sigma;
SigmaHQ correlation spec). A correlation rule references base rule(s) and adds:
- `type`: `event_count`, `value_count`, `temporal`, `temporal_ordered`.
- `group-by`: fields defining separate occurrence scopes.
- `timespan`: window (integer + unit suffix `s/m/h/d/w/M/y`).
- `condition`: threshold with `gte/gt/lte/lt/eq` (and `field` for `value_count`).
- Correlations can reference correlations → chains.
  Example: brute-force = base `failed_login` rule + `type: event_count`,
  `group-by: User`, `timespan: 5m`, `condition: {gte: 5}`.

**Lessons for SAFIX:**
1. Use named selections + a boolean `condition` string — it is expressive and readable.
2. Keep `false_positives` as documentation **and** give real `filter` selections so the
   author can encode exclusions declaratively.
3. Put stateful counting/sequence logic in a dedicated correlation construct with
   `timeframe`/`count`/`group-by`, separate from the stateless field-match block.
4. Status + level fields drive rule lifecycle and triage; keep them.
5. FIX-specialize the modifiers (tag-aware, datatype-aware) rather than inventing a
   generic text DSL.

### 1.2 Snort / Suricata — rate-based detection, thresholding, suppression, rule IDs

**Rule shape.** `action proto src sport -> dst dport ( options )`. Actions: `alert`,
`drop`, `block`, `reject`, `pass`. Body is `;`-separated options. Identity is the
**`gid:sid:rev`** triplet (Snort 3 docs, https://docs.snort.org/rules/options/general/):
GID = generating component (1 = text rules), SID = signature id (local rules start at
1,000,000 by convention), REV = revision (bump on every edit). General (metadata) options:
`msg`, `reference` (CVE/URL), `classtype` (maps to a default `priority`), `priority`,
`metadata` (arbitrary key/values), `service`. `flow` (e.g. `flow:established,to_server`)
constrains stateful connection direction/state.

**Thresholding / rate control** (Suricata docs,
https://docs.suricata.io/en/latest/rules/thresholding.html) — the richest rate model worth
copying:
- Rule-keyword **`threshold`**: `type <limit|threshold|both|backoff>, track <by_src|by_dst|
  by_rule|by_both|by_flow>, count N, seconds T`.
  - `limit` — alert at most N times per window (rate-limit noisy rules).
  - `threshold` — alert only once N matches occur within the window (burst detection);
    counter resets and can alert again.
  - `both` — N matches within window, then at most once (combine).
  - `backoff` — alert on matches 1, M, M², … (multiplier), good for log-scaled noise.
- Rule-keyword **`detection_filter`**: `track …, count N, seconds T` — suppress the first N
  matches, then alert on **every** subsequent match in the window (opposite of `limit`).
- **Global** config (`threshold.config`): `event_filter` (sensor-wide version of
  `threshold`) and `suppress` (silence a gid:sid, optionally scoped `track by_src`, address).
- **`rate_filter`** changes a rule's **action** when match rate crosses a threshold, for a
  `timeout` — a dynamic escalation mechanism.
- Caveat: flowbits/flowints and drop/reject still act on **every** match, independent of the
  alert threshold — i.e. detection vs. alerting are decoupled.

**Lessons for SAFIX:**
1. Give every rule a stable id + revision (SAFIX rule `id` + `revision`/`modified`).
2. `classtype → priority` is a clean two-level taxonomy: a rule's category sets a default
   severity the author can override.
3. Implement **both** rate idioms: `limit`-style noise suppression AND `threshold`/
   `detection_filter`-style burst detection, each scoped by a tracking key (by session, by
   SenderCompID, by symbol).
4. Provide **suppression** at config level (by rule, by comp-id, by value) separate from
   rules themselves — operators tune without editing rule files.
5. Separate "did it match" from "do we alert" (dedup/threshold layer sits after matching).

### 1.3 Zeek — "parse protocol into events, write policy in scripts" + Notice framework

**Analyzer/scripting split.** Zeek's protocol analyzers turn packets into typed events;
detection policy is written in scripts that react to those events. This clean separation of
**parsing** from **policy** is the single most important architectural lesson for SAFIX.

**Notice framework** (official docs, https://docs.zeek.org/en/lts/frameworks/notice.html):
- Analysis scripts **flag** activity by calling `NOTICE` with a `Notice::Info` record; they
  do **not** decide severity/response. `Notice::Info` is the carrier record, not a level.
- Each notice has a `Notice::Type` (the kind of activity); scripts extend the enum with
  their own types.
- The **site** decides action via `Notice::policy` hooks: log, email, ignore, etc. Shortcut
  sets exist: `Notice::ignored_types`, `Notice::emailed_types`, `Notice::not_suppressed_types`.
- **Automatic suppression** via the `identifier` field: identical notices sharing an
  identifier are suppressed for `suppress_for` (default 1 hr; `0secs` disables). Events
  `Notice::begin_suppression` and `Notice::suppressed` report it.

**Lessons for SAFIX:**
1. Detectors **raise findings**; a separate **policy/triage layer** decides severity,
   suppression, and routing. Do not bake disposition into detector code.
2. Copy the **identifier-based auto-suppression** idea directly: each finding computes a
   stable fingerprint; repeats within a window collapse (with a running count) instead of
   flooding. This is SAFIX's primary noise control.
3. Keep stateful connection tracking in the engine (Zeek tracks connections; SAFIX tracks
   FIX **sessions** — SenderCompID/TargetCompID/session identity, seq-num state, order book).

### 1.4 YARA — stateless pattern/signature matching

**Rule shape** (yara.readthedocs.io): `rule Name { meta: … strings: … condition: … }`.
- `meta` — arbitrary key/value documentation (author, description, severity).
- `strings` — named `$x = "…"` text, `{ AA BB ?? }` hex (with wildcards/jumps), or `/regex/`.
- String modifiers: `nocase`, `wide` (two-byte/UTF-16-LE interleaved), `ascii`, `xor`,
  `base64`. Combinable (e.g. `ascii wide`).
- `condition` — boolean logic over strings plus `N of them`, `any of ($a*)`, offsets,
  `filesize`, etc.

**Lessons for SAFIX:**
1. YARA is the model for **stateless field/value signatures** — "this tag contains/matches
   this pattern." SAFIX stateless detectors map directly onto the Sigma selection idiom, so
   SAFIX does not need a second DSL; it needs YARA-style **modifiers** (`contains`, `re`,
   `nocase`) on FIX tags.
2. `N of them` / `any of` is a useful condition primitive for "any of these suspicious tags
   present" rules.

### 1.5 Semgrep — rule metadata, severity, autofix, developer ergonomics

**Rule shape** (https://docs.semgrep.dev/writing-rules/rule-syntax): top-level `rules:` list,
each with required `id`, `message`, `severity`, `languages`, and one match key
(`pattern`/`patterns`/`pattern-either`/`pattern-regex`); optional `metadata`, `fix`,
`options`, `paths`, `min-version`/`max-version`.
- `severity`: `LOW|MEDIUM|HIGH|CRITICAL` (legacy `INFO/WARNING/ERROR` = LOW/MEDIUM/HIGH).
- `message` should explain **why** it matched and **how to remediate** — authored to be
  read by the engineer who sees the finding.
- `metadata` is a free-form bag (CWE, references, owner) that does not affect matching — the
  standard place for mappings and provenance.
- `fix` is a simple search/replace **autofix**; previewable with `--dryrun`.
- Rules ship from a **registry** and are referenced by id.

**Lessons for SAFIX:**
1. Make the finding `message` carry remediation ("fix the fix"): what the operator should do.
2. Put extensible mappings (regulatory refs, vector IDs, CWE-like codes) in a `metadata`/
   `references` bag that never affects matching.
3. SAFIX's analogue of `fix` is **remediation guidance** (config/control changes); FIX logs
   are read-only evidence so there is no code autofix, but a structured `remediation` field
   is valuable.
4. Plan a **rule registry/pack** model from day one (built-in packs + user packs).

### 1.6 SARIF 2.1.0 — the output interchange format SAFIX should emit

OASIS spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html.

**Minimal structure SAFIX needs:**
```
{ "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [ {
    "tool": { "driver": {
      "name": "SAFIX", "version": "x.y.z", "informationUri": "...",
      "rules": [ <reportingDescriptor>, ... ] } },
    "results": [ <result>, ... ],
    "artifacts": [ { "location": { "uri": "session.messages.log" } } ]
  } ] }
```

**reportingDescriptor (a rule, §3.49):** `id`, `name`, `shortDescription.text`,
`fullDescription.text`, `helpUri`, `help.text`, `defaultConfiguration` (a
reportingConfiguration §3.50 with `enabled`, `level`, `rank`), `properties` (bag; put
`security-severity` numeric score + `tags[]` here), `relationships`.

**result (§3.27):** key fields for SAFIX:
- `ruleId` (+ optional `ruleIndex` into `rules[]`).
- `level`: `error | warning | note | none`. If omitted, inherits the rule's
  `defaultConfiguration.level`. **Gotcha to avoid:** CI gates that read only `result.level`
  miss severity when it's inherited — SAFIX should emit `level` explicitly on every result.
- `kind`: `pass | fail | open | review | notApplicable | informational`.
- `message.text` (human finding text; supports `message.arguments` + `messageStrings`).
- `locations[]` → `physicalLocation` → `artifactLocation.uri` + `region`
  (`startLine`, `startColumn`, `endLine`, `endColumn`, `snippet.text`). For a FIX log, the
  region = the line / byte offset of the offending message.
- `partialFingerprints` / `fingerprints`: versioned hierarchical keys (e.g.
  `safixFingerprint/v1`) used to track the **same finding across runs** → baseline/dedup.
- `suppressions[]` (§3.35): `kind` (`inSource` | `external`), `status`
  (`accepted` | `underReview` | `rejected`), `justification`, `location`, `guid`.
- `baselineState`: `new | unchanged | updated | absent` — exactly what a CI diff needs.
- `rank`: 0–100 numeric priority; `taxa` link to taxonomies (CWE-like / regulatory).

**Lessons for SAFIX:**
1. Emit SARIF 2.1.0 as the machine format; it already models rules, results, locations,
   fingerprints, suppressions and baseline state — SAFIX's internal finding should map 1:1.
2. Always write `result.level` explicitly; also publish a numeric `security-severity`
   (0.0–10.0, CVSS-like) in `properties` for tools that rank by score.
3. Use `partialFingerprints` for dedup/baseline and `baselineState` for CI diffs.
4. Represent suppressed-but-reported findings via `suppressions[]` (don't silently drop).

### 1.7 Brief notes — Wireshark FIX dissector, ClamAV, osquery, CVSS/confidence, allowlists

- **Wireshark FIX dissector** — mature reference for **FIX parsing**: field = `tag=value`
  separated by SOH (`0x01`); it resolves tag numbers to names and enum values to labels via a
  data dictionary, handles `BodyLength`(9)/`CheckSum`(10), repeating groups, and FIX session
  vs. application layers. *Lesson:* SAFIX's parser should be **data-dictionary-driven**
  (per FIX version), surfacing both numeric tag and resolved name/enum so rules can be
  written against either, and tolerating malformed/partial messages (report, don't crash).
- **ClamAV** — signature DB + engine split; signatures are versioned and distributed
  (freshclam); supports multiple signature types (hash, body-based, logical). *Lesson:*
  ship **versioned rule packs** that update independently of the engine binary; support a
  rule-DB update command.
- **osquery** — scheduled queries + differential results (report only what changed since
  last run) + a results schema. *Lesson:* support **scheduled/continuous scanning** of
  rolling log files and **differential** output (only new findings) — directly useful for
  tailing live QuickFIX logs.
- **CVSS-like severity + confidence** — CVSS gives a 0.0–10.0 base score and qualitative
  bands (None/Low/Medium/High/Critical); threat-intel conventions (e.g. STIX, MISP) carry an
  orthogonal **confidence** (0–100 or Low/Med/High). *Lesson:* SAFIX should keep **severity**
  (impact if real) and **confidence** (likelihood it's a true positive) as **separate**
  axes and combine them into a triage priority (see §6).
- **Allowlist / baseline / suppression patterns across tools** — recurring idioms worth
  copying: (a) Sigma `and not filter` in-rule exclusion; (b) Suricata `suppress`/
  `event_filter` out-of-band tuning by sid + address; (c) Zeek identifier-based time-windowed
  auto-suppression; (d) SARIF `suppressions[]` + `baselineState` for "known/accepted"
  findings; (e) ClamAV-style `.ign`/allowlist files; (f) osquery baseline/diff. SAFIX should
  offer all four scopes: by rule, by session/CompID, by field value, and a time-window dedup.

---

## 2. SAFIX detection rule format (proposed YAML schema)

Sigma-inspired, FIX-specialized. One YAML document = one rule (multi-doc files allowed).

```yaml
# ---- identity & metadata -------------------------------------------------
id: 7b1f0c2a-6d4e-4a9b-9f2c-0e8a1b2c3d4e   # UUIDv4, stable
title: Cleartext password in Logon
status: stable                              # stable|test|experimental|deprecated
revision: 3                                 # bump on every edit (Snort rev idiom)
modified: 2026-10-11
author: safix-core
description: >
  Logon (35=A) carries a populated Password(554) while EncryptMethod(98)=0,
  i.e. credentials sent with no FIX-level encryption.
references:
  - https://www.onixs.biz/fix-dictionary            # FIX dictionary
  - AV-0012                                          # SAFIX attack-vector catalog id
  - SV-0003                                          # SAFIX surveillance-vector id
tags: [fix.session, credential-exposure, mitre.t1552]
regulatory: [FINRA-4370, MiFIDII-RTS6]               # regulatory refs
cwe: 319                                              # Cleartext Transmission

# ---- applicability -------------------------------------------------------
severity: high                              # informational|low|medium|high|critical
confidence: high                            # low|medium|high (likelihood of TP)
category: session-security                  # classtype -> default severity/priority
fix_versions: ["FIX.4.2","FIX.4.4","FIXT.1.1"]   # [] / omitted = all
msg_types: ["A"]                            # restrict to MsgType(35) values
logsource:
  product: quickfix
  direction: inbound                        # inbound|outbound|any (relative to app)

# ---- stateless detection (Sigma selection idiom, FIX-tag-aware) ---------
detection:
  logon:
    tag.35: "A"
  cleartext:
    tag.554|exists: true                    # Password present
    tag.98: 0                               # EncryptMethod = None
  tls_filter:                               # allowlist: sessions already on TLS
    session.transport: tls
  condition: logon and cleartext and not tls_filter

# ---- disposition & tuning ------------------------------------------------
false_positives:
  - Session is wrapped in mTLS at the transport layer (set session.transport=tls)
  - Internal test harness on localhost
remediation: >
  Require EncryptMethod!=0 or mandate transport TLS; rotate exposed credentials.
```

**FIX-aware operator conventions**
- `tag.<N>` addresses a FIX field by number; `name.<Name>` by dictionary name
  (`name.MsgType`). Values compare against the resolved enum or raw value.
- Modifiers (YARA/Sigma-style): `|contains`, `|startswith`, `|endswith`, `|re`, `|exists`,
  `|in` (value list), `|gt`/`|gte`/`|lt`/`|lte` (numeric), `|datatype` (assert the tag's
  value conforms to its dictionary datatype, e.g. INT/PRICE/UTCTIMESTAMP), `|notindict`
  (tag/enum not defined for this FIX version).
- `session.*` and `message.*` pseudo-fields expose normalized context (`session.sender_comp`,
  `session.target_comp`, `session.transport`, `message.seq_num`, `message.sending_time`,
  `message.byte_offset`).

### 2.1 Stateful / correlation rules

Separate block (Sigma-v2 correlation + Suricata thresholding), referencing base rules or
defining its own base selection:

```yaml
correlation:
  type: rate                 # rate | event_count | value_count | sequence | temporal
  base: [<rule-id or inline selection>]
  group_by: [session.sender_comp, tag.55]   # scope (Symbol per session)
  timeframe: 1s
  count: {gte: 100}          # threshold condition
  track: by_session          # by_session|by_comp|by_symbol|by_rule
  filter: limit              # limit|threshold|both (Suricata semantics)
```

### 2.2 Four worked example rules

**(a) Stateless datatype check — malformed quantity.**
```yaml
id: 1a2b3c4d-0001-4000-8000-000000000001
title: OrderQty is not a valid integer
status: stable
severity: medium
confidence: high
category: protocol-integrity
msg_types: ["D","G"]            # NewOrderSingle, OrderCancelReplace
logsource: {product: quickfix, direction: inbound}
detection:
  bad_qty:
    tag.38|datatype: INT        # fails if 38 (OrderQty) is not a clean integer
    condition: "not bad_qty"    # fire when datatype assertion FAILS
false_positives:
  - Non-standard custom dictionary redefines tag 38
remediation: Reject message; investigate client encoder producing malformed QTY.
references: [AV-0021]
```

**(b) Stateless field-signature — dangerous admin command injection attempt.**
```yaml
id: 1a2b3c4d-0002-4000-8000-000000000002
title: Suspicious shell/SQL pattern in free-text field
status: test
severity: high
confidence: medium
category: injection
msg_types: ["D","8","B","C"]    # order, exec report, news, email
logsource: {product: quickfix, direction: any}
detection:
  text_fields:
    - tag.58|re: "(?i)(\\bunion\\s+select\\b|/bin/sh|\\$\\(|;rm\\s)"   # Text(58)
    - tag.147|re: "(?i)(<script|\\.\\./)"                                # Subject(147)
  condition: text_fields
false_positives:
  - Legitimate free-text containing the word "select"
remediation: Treat as potential injection against downstream OMS/GUI; sanitize sinks.
references: [AV-0030, SV-0009]
```

**(c) Stateful rate/sequence — logon brute-force / sequence-reset abuse.**
```yaml
id: 1a2b3c4d-0003-4000-8000-000000000003
title: Repeated Logon attempts (possible credential brute force / session churn)
status: stable
severity: high
confidence: medium
category: session-security
msg_types: ["A"]
logsource: {product: quickfix, direction: inbound}
detection:
  logon:
    tag.35: "A"
  condition: logon
correlation:
  type: rate
  base: [logon]
  group_by: [session.sender_comp]
  timeframe: 60s
  count: {gte: 5}
  track: by_comp
  filter: threshold            # alert once 5 logons occur within 60s, per comp
false_positives:
  - Flaky network causing legitimate reconnect storms (baseline this comp)
remediation: Enforce logon rate limit + lockout; verify SenderCompID allowlist.
references: [AV-0005]
regulatory: [SEC-17a-4]
```

**(d) App-layer threshold — spoofing/layering via rapid place-then-cancel.**
```yaml
id: 1a2b3c4d-0004-4000-8000-000000000004
title: High order-to-cancel ratio within short window (layering/spoofing)
status: experimental
severity: critical
confidence: low                # needs analyst review; market-abuse inference
category: market-abuse
msg_types: ["D","F"]           # NewOrderSingle, OrderCancelRequest
logsource: {product: quickfix, direction: inbound}
detection:
  new_order: {tag.35: "D"}
  cancel:    {tag.35: "F"}
  condition: new_order or cancel
correlation:
  type: event_count
  base: [new_order, cancel]
  group_by: [session.sender_comp, tag.55]   # per trader, per symbol
  timeframe: 2s
  # custom ratio condition evaluated by the built-in detector hook:
  condition_expr: "cancel_count / max(new_order_count,1) >= 0.9 and new_order_count >= 20"
  track: by_symbol
false_positives:
  - Legitimate market-making with high quote turnover (allowlist the market-maker CompID)
remediation: Route to surveillance; correlate with order-book imbalance.
references: [SV-0001, AV-0040]
regulatory: [MAR-Art12, MiFIDII-RTS6]
```
> Rule (d) shows the hand-off: the YAML declares scope/window/grouping, but the ratio
> predicate (`condition_expr`) is evaluated by a **built-in Python detector** registered
> under the same id — see §3.4.

---

## 3. Engine architecture

A one-way pipeline with clean layer boundaries (Zeek's parse/policy split applied to FIX):

```
          ┌─────────────┐  raw lines    ┌──────────────┐  Message objects
 log file │  (a) Parser  │ ───────────▶ │ (b) Normalizer│ ──────────────┐
 / stream │  + Dictionary│               │ (session id, │               │
          └─────────────┘               │  seq, offset) │               ▼
                                         └──────────────┘        ┌───────────────┐
                                                                 │ (c) Stateless │ findings
                                                      ┌────────▶ │   Matcher     │ ───┐
                                                      │          │ (YARA/Sigma)  │    │
                                            Message   │          └───────────────┘    │
                                            stream ───┤                               ▼
                                                      │          ┌───────────────┐ ┌──────────────┐
                                                      └────────▶ │ (d) Stateful/ │ │ (e) Aggregator│
                                                                 │  Correlation  │▶│ dedup/suppress│
                                                                 │ (sessions,    │ │  /baseline    │
                                                                 │  orderbook,   │ └──────┬────────┘
                                                                 │  rate windows)│        │ findings
                                                                 └───────────────┘        ▼
                                                                                   ┌──────────────┐
                                                                                   │ (f) Reporters │
                                                                                   │ SARIF/JSON/   │
                                                                                   │ HTML/CLI/UI   │
                                                                                   └──────────────┘
```

### 3.1 (a) Parser + (b) Normalizer — FIX into a normalized event/message model
- **Dictionary-driven** (like Wireshark): load the FIX data dictionary for the declared
  version(s); resolve tag numbers ↔ names and enum values ↔ labels; know each tag's
  datatype and which message types it is valid in.
- Parse QuickFIX log format: each line = `timestamp : <raw FIX with SOH>`; split on SOH
  (`0x01`), build ordered `(tag, value)` fields, handle repeating groups, validate
  `BodyLength`(9)/`CheckSum`(10) **non-fatally** (a checksum error is itself a finding).
- Emit an immutable **`Message`** object: `fix_version`, `msg_type`, ordered fields +
  tag→value index (first & all occurrences), `raw_bytes`, `byte_offset`, `line_no`,
  `timestamp`, and a derived **session identity** `(begin_string, sender_comp, target_comp)`
  with direction. The Normalizer attaches session + sequence context and pseudo-fields
  (`session.*`, `message.*`) that rules reference.
- Tolerate partial/garbled input: a malformed message becomes a `Message` with a
  `parse_errors[]` list rather than aborting the scan.

### 3.2 (c) Stateless rule matcher
- Pure function `(Message) -> [Finding]`. No cross-message state.
- Compiles each YAML rule's selections into predicate trees once (startup), indexed by
  `msg_type` and `fix_version` so only applicable rules run per message (Sigma/Snort
  pre-filtering by logsource).
- Handles all field operators/modifiers (§2). This is where YARA-style signatures and
  Sigma-style selections live.

### 3.3 (d) Stateful / correlation engine
- Maintains per-session state keyed by session identity:
  - **Session state machine**: logon/logout, `HeartBtInt`, expected vs. actual
    `MsgSeqNum`(34), `ResetSeqNumFlag`(141), `PossDupFlag`(43)/`PossResend`(97) — detect
    gaps, replays, resets, desync.
  - **Order book / order lifecycle**: track ClOrdID(11)→OrderID(37) state across
    New/Replace/Cancel/ExecutionReport for layering, wash-trade, self-match, fat-finger.
  - **Rate windows**: sliding-window counters per `group_by` key implementing Suricata
    `limit`/`threshold`/`both` + `event_count`/`value_count`/`sequence`/`temporal`.
- Consumes the YAML `correlation` block; complex predicates (ratios, order-book geometry)
  delegate to a registered built-in detector (§3.4).
- Deterministic and replayable: feeding the same log twice yields identical findings
  (important for baseline diffs).

### 3.4 Plugin/registry pattern + YAML-vs-Python coexistence
- A central **`DetectorRegistry`**. Three registration paths, all producing the same
  `Finding` objects, so downstream layers are detector-agnostic:
  1. **Declarative YAML rules** — loaded from rule packs; compiled into stateless matcher
     predicates and/or correlation configs. Covers the majority of detections.
  2. **Built-in Python detectors** — subclass a `Detector` base
     (`class SpoofingLayeringDetector(StatefulDetector)`), register via a decorator
     (`@register("1a2b3c4d-0004-…")`) or entry-point plugin. For logic too complex for YAML
     (order-book reconstruction, statistical baselines, the ratio predicate in rule (d)).
  3. **Hybrid** — a YAML rule's `correlation.condition_expr` names a registered Python
     predicate; YAML owns scope/window/metadata, Python owns the hard computation. Keeps
     metadata/tuning uniform while allowing arbitrary logic.
- Detectors declare `msg_types`/`fix_versions`/`stateful?` so the engine schedules them
  correctly. Third-party packs load via Python entry points (osquery/ClamAV extensibility
  model) and signed/versioned rule packs (ClamAV freshclam model).

### 3.5 (e) Aggregation / dedup / suppression / baseline
- Compute each finding's **fingerprint** (§4) and collapse duplicates within a time window
  (Zeek identifier suppression), keeping a running `occurrence_count` and first/last seen.
- Apply **suppressions/allowlists** (by rule, session, CompID, field value) → mark
  `suppressed=true` with a reason (do not delete; SARIF `suppressions[]`).
- Apply **baseline**: compare fingerprints to a stored baseline → set `baselineState`
  (`new|unchanged|absent`). Learning mode writes the baseline instead of alerting.
- Apply rate thresholds that are cross-cutting (global `event_filter` equivalents).

### 3.6 (f) Reporters
- Pluggable sinks consuming the final finding list: **SARIF 2.1.0**, native **JSON**, a
  human **HTML/Markdown report**, terminal table, and a UI/websocket stream for live scan.
- A reporter never mutates findings — formatting only.

---

## 4. Finding (alert) object & output mapping

### 4.1 Internal `Finding` object
```python
@dataclass
class Finding:
    id: str                 # uuid of this finding instance
    rule_id: str            # SAFIX rule / detector id
    rule_revision: int
    vector_ids: list[str]   # AV-*/SV-* catalog references
    title: str
    message: str            # human text incl. remediation hint
    severity: str           # informational|low|medium|high|critical
    confidence: str         # low|medium|high
    priority: int           # derived triage score 0-100 (see §6)
    category: str           # classtype
    # evidence / location
    session: SessionId      # (begin_string, sender_comp, target_comp, direction)
    msg_seq: int | None     # MsgSeqNum(34)
    msg_type: str | None    # MsgType(35)
    raw_message: str        # offending raw FIX (SOH shown as |)
    byte_offset: int
    line_no: int
    location: FileRegion    # uri, startLine, startColumn, endLine, snippet
    # classification / routing
    tags: list[str]
    regulatory_refs: list[str]
    cwe: int | None
    # disposition
    suppressed: bool
    suppression_reason: str | None
    baseline_state: str     # new|unchanged|absent
    occurrence_count: int
    first_seen: datetime
    last_seen: datetime
    fingerprint: str        # stable dedup/baseline key
```

**Fingerprint recipe:** stable hash of `(rule_id, session identity, msg_type, and the
salient matched field values)` — **excluding** volatile data (timestamps, seq numbers)
so the same logical issue dedups across messages/runs. Emit as SARIF `partialFingerprints`
under a versioned key `safix/v1`.

### 4.2 Mapping to outputs

| Finding field        | SARIF 2.1.0                                   | Native JSON        | Human report              |
|----------------------|-----------------------------------------------|--------------------|---------------------------|
| `rule_id`            | `result.ruleId` (+ `ruleIndex`)               | `rule_id`          | rule id + title header    |
| `title`              | rule `shortDescription.text`                  | `title`            | finding heading           |
| `message`            | `result.message.text`                         | `message`          | body paragraph            |
| `severity`           | `result.level` (crit/high→error, med→warning, low/info→note) + `properties.security-severity` (0–10) | `severity` | colored badge |
| `confidence`         | `result.properties.confidence`                | `confidence`       | badge                     |
| `priority`           | `result.rank` (0–100)                          | `priority`         | sort key                  |
| `location`/`byte_offset` | `locations[].physicalLocation.{artifactLocation.uri, region{startLine,startColumn,snippet}}` | `location` | `file:line` + snippet |
| `raw_message`        | `region.snippet.text`                          | `raw_message`      | code block (SOH as `|`)   |
| `vector_ids`/`cwe`   | `result.taxa` / rule `properties.tags`         | arrays             | reference list            |
| `regulatory_refs`    | rule `properties.tags` / `taxa`                | array              | compliance callout        |
| `fingerprint`        | `partialFingerprints["safix/v1"]`              | `fingerprint`      | (hidden)                  |
| `suppressed`         | `result.suppressions[]` (kind/status/justification) | `suppressed`  | "suppressed" tag          |
| `baseline_state`     | `result.baselineState`                         | `baseline_state`   | new/known marker          |
| `occurrence_count`   | `result.occurrenceCount`                       | `occurrence_count` | "×N" counter              |

Rules themselves map to `tool.driver.rules[]` (reportingDescriptor) with
`defaultConfiguration.level`, `helpUri`, and `properties.security-severity`.

---

## 5. False-positive control mechanisms

SAFIX ships all of these; together they are the product's main differentiator:

1. **Two independent axes — severity × confidence.** Low-confidence detections (e.g. the
   layering heuristic) default to a **review/info** tier rather than a hard alert, so
   analysts aren't flooded by inferential rules.
2. **Alert vs. info tiers.** `critical`/`high` → alert; `medium` → warning; `low`/
   `informational` → logged for context/charting only (Sigma level guidance; SARIF
   `kind: review|informational`).
3. **Suppressions / allowlists** at four scopes, out-of-band from rule files
   (Suricata `suppress`/`event_filter` idiom):
   - by **rule id** (disable/downgrade a noisy rule),
   - by **session** `(sender/target CompID)`,
   - by **CompID** (e.g. allowlist known market-maker for the layering rule),
   - by **field value** (specific Symbol, Account, IP).
   Suppressed findings are **retained and marked**, not deleted (SARIF `suppressions[]`).
4. **In-rule exclusion filters.** Sigma `condition: selection and not filter` lets authors
   encode known benign cases declaratively (rule (a)'s `tls_filter`).
5. **Baseline / learning mode.** A learning pass records the fingerprints of findings on a
   known-good log as a baseline; subsequent scans set `baselineState` and only surface
   `new` findings (osquery diff model). Baselines are per-environment files.
6. **Fingerprint dedup + time-window collapse.** Identical findings collapse into one with
   `occurrence_count` (Zeek identifier suppression) — kills repetition noise.
7. **Rate thresholds.** `limit`-style caps on how often a rule may alert per window; burst
   `threshold`/`detection_filter` to only alert on abnormal volume (Suricata).
8. **Per-rule enable/disable + tuning.** Config overrides a rule's `enabled`, `severity`,
   `confidence`, and correlation `count`/`timeframe` without editing the rule
   (SARIF `defaultConfiguration`).
9. **Status gating.** `experimental`/`test` rules can be excluded from CI gates by default;
   only `stable` rules fail a build unless opted in.
10. **Documented `false_positives` + `remediation`** on every rule so a triager can judge
    quickly (Semgrep message ergonomics).

---

## 6. Severity & confidence model

Two orthogonal scales, combined into a single triage **priority**.

- **Severity** (impact if the finding is a true positive) — qualitative band + CVSS-like
  numeric for ranking:
  | Band          | numeric (SARIF security-severity) | SARIF level |
  |---------------|-----------------------------------|-------------|
  | critical      | 9.0–10.0                          | error       |
  | high          | 7.0–8.9                           | error       |
  | medium        | 4.0–6.9                           | warning     |
  | low           | 0.1–3.9                           | note        |
  | informational | 0.0                               | none/note   |
- **Confidence** (likelihood the detection is a true positive, given rule precision):
  `high` = 1.0, `medium` = 0.6, `low` = 0.3.
- **Triage priority** (SARIF `result.rank`, 0–100):
  `priority = round( severity_numeric * 10 * confidence_weight )`,
  optionally boosted by `occurrence_count` and regulatory tags. Example: critical (9.5) ×
  low confidence (0.3) → 28.5 → **review queue**; high (8.0) × high confidence (1.0) → 80 →
  **immediate alert**. This prevents a flashy-but-uncertain rule from outranking a solid one.
- UI sorts and filters by priority by default; CI `--fail-on` compares against the severity
  band (not priority) so gating is predictable.

---

## 7. CLI & UI feature expectations

### 7.1 CLI (modeled on semgrep / suricata / snort / yara / clamscan)
```
safix scan <log...> [--format sarif|json|html|table] [--out FILE]
                    [--rules DIR/PACK...] [--version FIX.4.4] [--dict FILE]
                    [--baseline FILE] [--suppress FILE]
                    [--fail-on high]            # CI gate by severity band
                    [--only-stable] [--enable ID] [--disable ID]
                    [--diff-baseline]           # only new findings
                    [--tail]                    # live/continuous scan of rolling logs
safix validate <rules...>          # lint rule YAML (schema + dict/tag/enum checks)
safix rules list [--category ...] [--severity ...] [--status ...]
safix rules show <id>              # full rule detail incl. references/remediation
safix rules test <rule> <sample-log>   # rule unit test (expect match/no-match)
safix baseline create <log> --out baseline.json
safix baseline update <log> --baseline baseline.json
safix report <results.sarif> --format html   # render a prior scan
safix dict list | show FIX.4.4     # inspect loaded data dictionaries
safix version
```
Key flags echo established tools: `--fail-on <severity>` (CI exit-code gate, like semgrep),
`--format` with SARIF/JSON/HTML, rule pack selection, dictionary/version selection,
baseline + suppression files, `--only-stable`/`--enable`/`--disable` tuning, `--tail` for
continuous scanning.

### 7.2 Rich web UI
- **Scan runner / live view**: drop or point at a log, pick FIX version + dictionary + rule
  packs, watch findings stream in (osquery/live-tail feel); progress + parse-error count.
- **Finding triage board**: sortable/filterable by priority, severity, confidence,
  category, session/CompID, rule, baseline state; each finding shows the raw message with
  the offending tag(s) highlighted, byte offset/line, references, regulatory refs, and
  remediation.
- **Rule management**: browse/search rule packs; per-rule enable/disable; inline tuning of
  severity/confidence and correlation `count`/`timeframe`/`group_by`; view
  `false_positives`/`references`; rule test runner.
- **Suppressions & allowlists manager**: create/edit suppressions by rule/session/CompID/
  field value with justification; see what each has silenced.
- **Baseline management**: create/update/compare baselines; mark findings accepted (feeds
  SARIF suppression `status`).
- **Thresholds & global settings**: dictionary/version selection, input format, rate-limit
  defaults, dedup window.
- **Dashboards**: findings by severity/category/CompID over time; top noisy rules (tuning
  candidates); regulatory coverage view.
- **Export**: SARIF / JSON / HTML / CSV; shareable per-scan report link.

---

## 8. Source references

- Sigma rule basics — https://sigmahq.io/docs/basics/rules.html ; correlations —
  https://docs.sekoia.io/xdr/features/detect/sigma
- Suricata thresholding — https://docs.suricata.io/en/latest/rules/thresholding.html ;
  global thresholds — https://docs.suricata.io/en/latest/configuration/global-thresholds.html
- Snort 3 general rule options — https://docs.snort.org/rules/options/general/ ; guide —
  https://docs.snort.org/
- Zeek Notice framework — https://docs.zeek.org/en/lts/frameworks/notice.html
- YARA writing rules — https://yara.readthedocs.io/en/latest/writingrules.html
- Semgrep rule syntax — https://docs.semgrep.dev/writing-rules/rule-syntax
- SARIF 2.1.0 (OASIS) — https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
- FIX security background — https://www.darkreading.com/cyber-risk/-hacking-capitalism- ;
  https://b2bits.atlassian.net/wiki/spaces/B2BITS/pages/6067803/FIXEdge+Security+Assurance
- CVSS (severity bands/scoring) — https://www.first.org/cvss/

*Quotes from sources are kept to a few words; all substance is synthesized and attributed by URL.*
