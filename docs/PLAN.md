# SAFIX — Static Analyzer for FIX
## Product & Engineering Plan (v1)

> **SAFIX** is a security scanner for the **FIX trading protocol**. It ingests FIX message
> logs (QuickFIX format and other common serializations), reconstructs session and order
> state, and raises **true-positive-aware alerts** for protocol attacks, abuse, and
> policy/regulatory violations — the "Snort/Semgrep/Sigma of FIX logs."
>
> First-of-its-genre: there is no existing security scanner dedicated to FIX log forensics.
> This plan is grounded in a 262-vector attack-vector catalogue (`C:\temp\LLM\fix`) and the
> design patterns of established security tooling (Sigma, Snort/Suricata, Zeek, YARA,
> Semgrep, SARIF).

---

## 1. Goals & non-goals

### Goals (v1)
- **Batch log scanning**: scan existing FIX logs/captures offline → findings + reports.
- **Broad, accurate detection** across all 5 attack categories (SESS, TYPE, STRUCT, APP, ENC),
  each traced to the source vector IDs (`AV-*`, `SV-*`) and, where applicable, to
  **SEC Rule 15c3-5** and **MiFID II RTS 6** controls.
- **QuickFIX compatibility**: parse QuickFIX `messages.log`/`event.log`, FileStore bodies, and
  load QuickFIX data dictionaries (FIX 4.0–5.0SP2 + FIXT 1.1).
- **False-positive control** as a first-class feature: severity×confidence, benign-case
  modeling, suppressions/allowlists, baselining, dedup.
- **Rich local web UI** (FastAPI + browser) to configure every setting, triage findings, tune
  rules/thresholds, manage suppressions and baselines, and view reports/dashboards.
- **CLI** for scripting/CI (`scan`, `validate`, `rules`, `baseline`, `report`, `serve`), with
  `--fail-on <severity>` for pipelines.
- **Extensive, measurable tests**: a ground-truth attack/benign corpus with precision/recall
  metrics per category, plus unit/integration/golden tests.
- Output in **SARIF 2.1.0**, JSON/JSONL, self-contained HTML, console, and JUnit (CI).

### Non-goals (v1 — architected for, not built)
- Live/streaming IDS mode and a standalone REST service (hooks left in place).
- Active probing/exploitation (SAFIX is read-only/defensive; the offensive tooling lives in
  the `fix` repo's `fixfuzz-plus`, which we only use to **generate test data**).
- Deep decoding of non-tag=value encodings (SBE/FAST/GPB) — flagged out-of-scope; FIXML/XML
  signatures *are* in scope.

---

## 2. Stack

- **Language**: Python 3.14 (only fully-available runtime; matches `simplefix`/`fixfuzz-plus`).
- **Parsing**: custom **lenient** tag=value parser (a security scanner must never reject a
  malformed message — it must parse what it can and record every anomaly). `simplefix` studied;
  verdict in research. Dictionary model adapted from `fixfuzz-plus/fixdict.py`.
- **CLI**: `typer` + `rich`.
- **Web**: `FastAPI` + `uvicorn`; static frontend (vanilla JS + charting via pinned CDN libs —
  no Node build step).
- **Rules**: YAML (Sigma-inspired) + registered Python detectors for stateful logic.
- **Validation/config**: `pydantic` v2.
- **Tests**: `pytest`; corpus generated via `fixfuzz-plus` mutators.
- Dependencies kept lean and pinned; everything installable with `pip`.

---

## 3. Architecture

Five-layer pipeline (Zeek-style "parse → events → policy", Sigma-style declarative rules,
Snort-style rate/suppression):

```
 INPUT  ──▶  PARSE  ──▶  NORMALIZE  ──▶  DETECT  ──▶  TRIAGE  ──▶  REPORT
 files/     lenient      FixMessage      stateless +   suppress/    SARIF/JSON/
 stdin      lexer +      + session/      stateful      dedup/       HTML/console/
 (auto-     framing      order model     detectors     baseline     JUnit + Web UI
  detect)   anomalies                    (+ YAML)
```

### Package layout
```
safix/
  cli.py                 CLI (scan/validate/rules/baseline/report/serve)
  config.py              Pydantic config: dict version, thresholds, enabled rules, suppressions
  model/
    message.py           FixField(tag,value,raw,offset), FixMessage (ordered, keeps duplicates)
    session.py           SessionKey (BeginString+Sender+Target), SessionState
    finding.py           Finding, Severity, Confidence, Priority
  parsing/
    lexer.py             Lenient tokenizer (SOH / pipe / autodetect); emits framing anomalies
    framing.py           BodyLength(9)/CheckSum(10) verify; DATA length-prefix handling
    formats.py           Input autodetect (raw SOH, pipe, QuickFIX messages.log ts+direction)
    logreader.py         Message iterator w/ metadata (ts, direction, source line, byte offset)
  dictionary/
    spec.py              FixSpec (fields/types/enums/groups/required, Len/Data pairs, dataTag-1)
    loader.py            QuickFIX dict XML → FixSpec (+ FIXT merge for FIX5)
    datatypes.py         Datatype grammar validators (regex table from research)
  engine/
    context.py           ScanContext: per-session state, order book, rate windows, baselines
    registry.py          Detector plugin registry (decorator-registered)
    stateless.py         Per-message rule matcher (YAML + stateless detectors)
    stateful.py          Correlation engine (session state machine, order ownership, rate)
    baseline.py          Baseline learning (per-instrument price/qty stats)
    runner.py            Orchestrator: parse→stateless→stateful→aggregate→suppress
  detectors/
    framing.py           SESS-FRM: BodyLength/CheckSum/SOH smuggling
    session_seq.py       SESS-SEQ/STA: seqnum/gap/resend/gapfill/logon state machine
    datatype.py          TYPE: grammar violations, Len/Data desync, dataTag-1 (AV-TYPE-11)
    structure.py         STRUCT: required/order/dup/group-count desync/nesting/msgtype
    encoding.py          ENC: XXE/entity/XInclude signatures in XMLData/EncodedText
    app_order.py         APP: fat-finger, OrigClOrdID BOLA, wash/self-trade, spoofing, throttle
  rules/
    schema.py            YAML rule schema (pydantic) + validation
    loader.py            Load/merge rule packs
    builtin/             sess.yml type.yml struct.yml app.yml enc.yml
  suppress/
    suppressions.py      Allowlist/suppression match + fingerprint dedup
  reporting/
    sarif.py jsonl.py html.py console.py junit.py
  web/
    app.py api.py        FastAPI app + REST endpoints
    static/              Rich frontend (settings, triage, dashboards, rule tuning)
```

### Normalized message model (lenient, security-preserving)
`FixMessage` = ordered list of `FixField(tag:int|raw, value:bytes, raw:bytes, offset:int)`,
preserving **field order, duplicate tags, and raw bytes**, plus parse-time `anomalies[]`
(bad BodyLength, checksum mismatch, embedded SOH in DATA, non-numeric tag, leading-zero tag
aliasing, etc.). Nothing is silently normalized away — anomalies are evidence.

### State model (built while scanning, for stateful detectors)
- **Per session** (`BeginString`+`SenderCompID`+`TargetCompID`, directional): expected/last
  `MsgSeqNum(34)`, outstanding `ResendRequest(2)` ranges, logon/logout state, `TestRequest(1)`
  counts, PossDup/OrigSendingTime seen set, rate windows (msgs/logons/resends per interval).
- **Order book** (APP): `ClOrdID(11)` → owning session + `Symbol(55)`/instrument + side + qty +
  price + order state; `OrigClOrdID(41)` ownership checks (BOLA); party map (`NoPartyIDs`).
- **Baselines** (APP): per-instrument price/qty running stats for fat-finger / anomaly bands.

---

## 4. Detection content (from the 262-vector catalogue + research)

| Area | Vectors | v1 detector | Statefulness | Notes |
|------|--------:|-------------|--------------|-------|
| **SESS** | ~58 | `framing.py`, `session_seq.py` | mostly **stateful** | seqnum/gap/resend/gapfill/logon state machine; framing is stateless |
| **TYPE** | ~70 | `datatype.py` | **stateless** | datatype grammar regex table; Len/Data desync; dataTag-1 bug; MonthYear regex defect |
| **STRUCT** | ~48 | `structure.py` | stateless (+dict) | required/order/dup/group-count/nesting/msgtype; needs dictionary |
| **APP** | ~42 | `app_order.py` | **stateful + baseline + config** | fat-finger, BOLA, wash, spoofing, throttle; regulatory-tagged; highest FP risk |
| **ENC** | ~44 | `encoding.py` | stateless | XXE/entity/XInclude/CDATA signatures in XML-bearing fields; SBE/FAST/GPB out-of-scope |

Each detector emits `Finding` objects carrying the source **vector IDs**, severity, confidence,
**benign-case notes**, remediation, and (APP) regulatory refs. The precise per-vector detection
specs, datatype regex table, and regulatory mapping come from the 5 research files in
`docs/research/` (in progress) and are catalogued in `docs/DETECTORS.md`.

**Headline high-value log-detectable vectors** (lead with these): AV-SESS-SEQ-13 (gap→GapFill
smuggling), AV-SESS-STA-01 (ResetSeqNumFlag reset), AV-SESS-FRM-01/03 (BodyLength abuse),
AV-TYPE-1/3/11 (Len/Data desync + dataTag-1), AV-APP-05 (OrigClOrdID BOLA), AV-ENC-01/02 (XXE /
external-DTD), AV-APP-17 (wash/self-trade), AV-APP-01/02 (fat-finger).

---

## 5. Rule format (Sigma-inspired, FIX-specialized)

Declarative YAML for stateless checks; Python detectors (registry) for stateful logic. Sketch:

```yaml
id: SAFIX-TYPE-0001
title: Price field contains non-numeric / malformed FLOAT
vector_ids: [AV-TYPE-15, SV-TYPE-12]
category: TYPE
severity: medium
confidence: high
status: stable
fix_versions: ["*"]
msg_types: ["*"]
direction: received            # attacks are in received messages
detection:
  field:
    tag: 44                    # Price
    datatype_violation: PRICE  # fails the PRICE grammar
  condition: field
false_positives:
  - "Venue-specific non-standard price encodings (allowlist the session)."
references: ["AV-TYPE-15"]
remediation: "Reject per SessionRejectReason(373)=6 (incorrect data format)."
```

Stateful rules add `timeframe`/`count` (rate) or reference a named Python detector. Worked
examples for all four shapes (datatype, field-signature, rate/sequence, app-threshold) ship in
`docs/RULES.md`. Final schema from the architecture research.

---

## 6. False-positive control (first-class)

- **Severity (critical/high/medium/low/info) × Confidence (high/medium/low)** → triage priority.
- **Benign-case notes** on every finding (what legitimate activity looks identical).
- **Suppressions/allowlists**: by rule id, session, CompID, field value, or fingerprint; stored
  in config, editable in the UI.
- **Baselining / learn mode**: build per-instrument price/qty baselines from a known-good log;
  APP thresholds derive from baselines + config instead of hard-coding.
- **Dedup**: stable per-finding `fingerprint` (rule+session+salient fields).
- **Tiers**: `alert` vs `info`; refuted vectors (e.g. AV-STRUCT-10 huge-count OOM) ship as
  low-confidence `info` probes, not alarms.
- **Per-rule enable/disable + tuning** via config and UI.

---

## 7. CLI

```
safix scan <paths...> [--format auto|soh|pipe|quickfix] [--fix-version FIX44]
     [--dict <path>] [--rules <dir>] [--config safix.yml] [--baseline <file>]
     [--out report.sarif] [--report html|json|sarif|console|junit]
     [--severity-min low] [--fail-on high] [--suppress <file>]
safix validate <paths...>        # pure FIX conformance (dictionary) view
safix rules list|show|lint       # inspect/validate rule packs
safix baseline build <good.log>  # learn baselines
safix report <findings.json>     # re-render a report in another format
safix serve [--host --port]      # launch the web UI
```

---

## 8. Web UI (rich settings + triage)

FastAPI serving a static frontend. Panels:
- **Scan**: pick files/dirs, format, FIX version/dictionary, rule packs, baseline → run → live
  progress → results.
- **Findings triage**: filter/sort by severity/confidence/category/session/vector; expand to see
  the raw message with the offending field highlighted, benign-case note, remediation,
  regulatory refs; suppress/allowlist in one click; export (SARIF/JSON/HTML).
- **Rules**: browse the rule catalogue; enable/disable; edit thresholds; lint.
- **Settings**: dictionary/version, input format, thresholds (fat-finger qty/price, rate
  limits, staleness), suppressions, baseline management.
- **Dashboard**: counts by category/severity over the scanned log; session overview; timeline.

---

## 9. Test strategy (measurable)

- **Unit**: lexer/framing (incl. adversarial inputs), dictionary loader, datatype validators,
  each detector in isolation, reporters (golden files).
- **Ground-truth corpus** (the headline): `fixfuzz-plus` `mutators.py` generates **labeled
  attack messages** (each tagged with its `AV-*` vector + area) and **valid seed messages**.
  - *Recall/detection-rate test*: every attack message must produce a finding mapping to its
    expected vector/category.
  - *Precision/false-positive test*: valid seed messages must produce **no** alert (info-tier
    allowed).
  - A `pytest` report prints **precision/recall per category** and gates CI on thresholds.
- **Integration**: end-to-end scans of synthetic QuickFIX `messages.log` files containing
  planted attack sequences (multi-message session/APP scenarios).
- **Regression**: golden SARIF/HTML for fixed sample logs.

---

## 10. Phasing

- **P0 — Scaffold**: `pyproject.toml`, package skeleton, test harness, sample data dir, research
  landed in `docs/research/`.
- **P1 — Parse**: lenient lexer + framing + input-format autodetect + QuickFIX log reader + model.
- **P2 — Dictionary**: QuickFIX XML loader (+FIXT merge) + datatype validators.
- **P3 — Core engine + reporters**: Finding model, rule schema + loader, stateless matcher,
  console/JSON/SARIF reporters, CLI `scan`/`validate`.
- **P4 — STRUCT + TYPE detectors** (stateless, dictionary-driven) + YAML rule packs.
- **P5 — Stateful engine + SESS detectors** (seqnum/resend/gapfill/framing/logon state machine).
- **P6 — ENC detectors** (XML/XXE signatures).
- **P7 — APP engine + detectors** (order book, baselines, rate windows) + regulatory tagging.
- **P8 — Triage**: suppressions, baseline build, config, dedup, severity gating, HTML/JUnit.
- **P9 — Tests**: ground-truth corpus harness + precision/recall gates + integration/goldens.
- **P10 — Web UI**: FastAPI + rich frontend (all settings, triage, dashboard).
- **P11 — Docs/packaging**: README, rule-authoring guide, detector catalogue, sample logs, `pip`.

---

## 11. Reused assets from `C:\temp\LLM\fix`
- **Attack-vector catalogue** (262 vectors, 5 categories) → detector content + vector IDs.
- **QuickFIX dictionaries** (`quickfix/spec/*.xml`, also bundled in `fixfuzz-plus/dictionaries/`)
  → shipped with SAFIX for validation.
- **`fixfuzz-plus/fixdict.py`** → dictionary model reference (Len/Data pairs, dataTag-1).
- **`fixfuzz-plus/mutators.py` + `generators.py`** → ground-truth test corpus generator.
- **Regulatory docs** (`references/docs/regulatory-*.md`) → 15c3-5 / RTS 6 mapping.
```
