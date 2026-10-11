# SAFIX — Static Analyzer for FIX

**SAFIX** is a security scanner for the **FIX trading protocol**. It ingests FIX message logs
(QuickFIX-compatible and other common serializations), reconstructs session and order state, and
raises **true-positive-aware alerts** for protocol attacks, abuse, and policy/regulatory
violations — think of it as the *Snort / Semgrep / Sigma of FIX logs*.

It is grounded in a 262-vector FIX attack-vector catalogue spanning five categories, and is
cross-validated against an independent FIX fuzzer (`fixfuzz-plus`): **97% single-message
detection recall with zero high/critical false positives on benign traffic** (see
`tests/integration/test_detection_rate.py`).

| Category | What it covers |
|----------|----------------|
| **SESS** | Session & framing: sequence numbers, resend / gap-fill smuggling, BodyLength / CheckSum, logon & replay abuse |
| **TYPE** | Datatype grammar violations, Len/Data desync, the `dataTag-1` over-read bug, enum/magnitude/calendar checks |
| **STRUCT** | Required / ordering / duplicate fields, repeating-group count desync, unknown / foreign tags |
| **APP** | Order/trade abuse: fat-finger, `OrigClOrdID` BOLA, escalation-on-replace, wash/self-trade, throttle, mass-cancel |
| **ENC** | XXE / entity-expansion / XInclude / CDATA signatures in XML-bearing fields and whole-FIXML payloads |

Every finding carries a severity, a confidence, the source attack-vector ID(s), the benign
activity that looks identical, and (for APP) the SEC 15c3-5 / MiFID II RTS 6 control it tests.

## Install

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate       Linux/macOS:  source .venv/bin/activate
pip install -e ".[web,dev]"
```

## CLI

```bash
# scan a log (format, delimiter, and FIX version are auto-detected)
safix scan path/to/messages.log

# rich reports; fail a CI pipeline on anything high or above
safix scan logs/ --report sarif --out findings.sarif --fail-on high
safix scan logs/ --report html  --out report.html

# force a dictionary, add custom rules, seed a price baseline, raise the floor
safix scan app.log --fix-version FIX.4.4 --rules ./my-rules/ --baseline base.json --severity-min medium

# live monitoring — passively tail the engine's log and alert in real time
safix watch /path/to/FIX.4.4-CLIENT-SERVER.messages.log --from-start
tail -f messages.log | safix watch - --report jsonl --out alerts.jsonl   # fully off-host

safix validate app.log          # conformance view only (TYPE+STRUCT+FRAMING+SESS)
safix baseline logs/good/ -o base.json    # learn per-instrument price baselines
safix rules                     # list detectors + built-in YAML rules
safix dict FIX.4.4              # describe a bundled dictionary
safix serve                     # launch the web UI (http://127.0.0.1:8375)
```

Try it on the bundled samples:

```bash
safix scan src/safix/data/samples/attack_session.messages.log
```

## Web UI

`safix serve` opens a rich browser UI with three tabs:

- **Scan** — paste or upload a log, set every option (dictionary version, delimiter, severity
  floor, per-detector thresholds, suppressions), run a scan, and triage findings: filter by
  category/severity/text, expand any finding for its vectors/evidence/remediation/benign notes,
  and **download** the report as SARIF / JSON / HTML / JUnit.
- **Live** — point it at a server-side log file and watch findings **stream in real time** (via
  Server-Sent Events) as the engine writes the log, newest on top, with a live severity summary.
  Same zero-impact passive tailing as `safix watch`.
- **Rules** — write your own detection rules by hand in a YAML editor (saved on the server and
  applied to every scan), with a built-in operator reference and an "insert example" button;
  and **hide** any rule or whole detector you don't want with a checkbox. See
  [`docs/RULES.md`](docs/RULES.md) for the rule format.

## Live monitoring with zero engine impact

`safix watch` tails a live FIX log and alerts in real time. It is designed to add **zero latency
to the trading engine**, because it is strictly **out-of-band and passive** — the same principle
a network IDS uses by tapping a span port instead of sitting inline:

- **Never in the message path.** SAFIX does not proxy, hook, or wrap the FIX engine. It only
  reads the log file the engine already writes.
- **Read-only, no locks.** The file is opened read-only and closed again on every poll, so SAFIX
  never holds a handle that could block the engine writing or rotating its log (important on
  Windows). It is rotation-aware (detects truncation and replaced files).
- **Decoupled.** SAFIX runs as a separate process — and, via `watch -` reading stdin, can run on
  a **different host** entirely (e.g. `tail -f log | ssh monitor safix watch -`), so nothing runs
  on the trading host at all. If SAFIX falls behind or crashes, the engine is unaffected.
- **Streaming + bounded memory.** Findings are emitted per message as they occur; session/order
  state is kept for stateful detection but trimmed periodically so a long run stays flat.

```bash
safix watch FIX.4.4-CLIENT-SERVER.messages.log            # follow new messages
safix watch messages.log --from-start --severity-min high  # backfill, then follow, high+ only
tail -f messages.log | safix watch - --report jsonl --out alerts.jsonl   # off-host → SIEM
```

## How it works

```
 INPUT  ──▶  PARSE  ──▶  NORMALIZE  ──▶  DETECT  ──▶  TRIAGE  ──▶  REPORT
 files/     lenient      FixMessage      stateless +   suppress/    SARIF/JSON/
 stdin      lexer +      + session/      stateful +    dedup/       HTML/console/
 (auto-     framing      order model     YAML rules    baseline     JUnit + Web UI
  detect)   anomalies
```

- **Lenient parser** — never rejects adversarial input; records every anomaly with a byte
  offset so a finding can point at the exact malicious bytes.
- **Dictionary-aware** — loads bundled QuickFIX dictionaries (FIX 4.0–5.0SP2 + FIXT 1.1) for
  field/datatype/enum/group validation.
- **Hybrid detectors** — stateful Python detectors (session state machine, order ownership,
  Len/Data, XML signatures) plus a declarative **YAML rule layer** for custom stateless checks.
- **False positives are first-class** — severity×confidence triage, per-finding benign notes,
  suppressions/allowlists, baseline learn-mode, and fingerprint dedup.

## Documentation

- [`docs/PLAN.md`](docs/PLAN.md) — the full engineering plan.
- [`docs/DETECTORS.md`](docs/DETECTORS.md) — the detector catalogue (rules → vectors).
- [`docs/RULES.md`](docs/RULES.md) — writing custom YAML rules.
- [`docs/research/`](docs/research/) — the detection research that seeds the detectors.

## Tests

```bash
pytest -q                                   # full unit + integration suite
pytest tests/integration -s                 # prints the recall / false-positive report
```

## License

SAFIX is licensed under the **GNU AGPL-3.0-or-later** — see [`LICENSE`](LICENSE). In short: you
may use, modify, and redistribute it, but if you modify it or run it as a network service, you
must make your source available under the AGPL.

A **separate commercial license** is available for organizations that cannot accept the AGPL's
terms (e.g. embedding SAFIX in a closed-source product or offering it as a hosted service without
releasing changes). Contact boringllm58@gmail.com.

Third-party components are attributed in [`NOTICE`](NOTICE): the bundled QuickFIX data
dictionaries (QuickFIX Software License) and the vendored `RAW_DATA` table from
[simplefix](https://github.com/da4089/simplefix) (MIT, © David Arnold).

Contributions are welcome under the dual-license model — see [`CONTRIBUTING.md`](CONTRIBUTING.md)
and [`CLA.md`](CLA.md).
