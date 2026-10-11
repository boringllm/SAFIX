# Writing SAFIX rules

SAFIX has two kinds of detectors:

1. **Built-in Python detectors** — stateful or complex logic (session state machine, order
   ownership/BOLA, Len/Data desync, datatype grammar, XML signatures). These live in
   `safix/detectors/` and are always on. See [`DETECTORS.md`](DETECTORS.md) for the catalogue.
2. **Declarative YAML rules** — stateless, single-message field/signature checks that anyone can
   add without writing Python. This page is about those.

## Where rules live

- Built-in YAML packs ship in `safix/rules/builtin/*.yml` and are always loaded.
- Your own packs: point a scan at a directory with `safix scan … --rules ./my-rules/`
  (or set `rules_path:` in the config file). Every `*.yml` / `*.yaml` file in it is loaded.

## Rule shape

```yaml
rules:
  - id: SAFIX-CUSTOM-0001          # unique id (used for suppression, dedup, enable/disable)
    title: Market order with FOK time-in-force
    message: "OrdType=Market with TimeInForce=FOK"   # optional; defaults to title
    category: APP                  # SESS | TYPE | STRUCT | APP | ENC | CUSTOM
    severity: medium               # critical | high | medium | low | info
    confidence: medium             # high | medium | low
    status: stable                 # stable | experimental (free-form)
    vector_ids: [AV-APP-04]        # source attack-vector IDs this realises
    regulatory_refs: ["MiFID II RTS 6 Art.15"]
    msg_types: ["D", "G"]          # restrict to these MsgType(35) values; omit = all
    direction: any                 # received | sent | any  (needs our_comp_ids to resolve)
    match: all                     # all = AND of conditions; any = OR
    when:
      - {tag: 40, equals: "1"}     # OrdType = Market
      - {tag: 59, equals: "4"}     # TimeInForce = FOK
    benign: ["Some venues permit market FOK."]
    remediation: "Review market FOK orders."
    references: [AV-APP-04]
```

A top-level file may be `{rules: [...]}`, a bare list of rules, or a single rule mapping.

## Condition operators

Each entry in `when:` targets one `tag:` and uses **one** operator. A condition is true if **any**
occurrence of the tag matches (duplicates are considered). With no operator, a bare `{tag: N}`
means "field present".

| Operator | Meaning | Example |
|----------|---------|---------|
| `equals` | value == | `{tag: 40, equals: "2"}` |
| `not_equals` | no occurrence equals | `{tag: 54, not_equals: "1"}` |
| `contains` | substring present | `{tag: 58, contains: "DROP TABLE"}` |
| `regex` | Python regex search | `{tag: 11, regex: "^SEQ[0-9]+$"}` |
| `in` | value in list | `{tag: 40, in: ["3", "4"]}` |
| `gt` / `lt` | numeric compare | `{tag: 38, gt: 100000}` |
| `exists` | field present / absent | `{tag: 99, exists: false}` |
| `datatype_violation` | fails its FIX datatype grammar (needs dictionary) | `{tag: 44, datatype_violation: true}` |
| `enum_violation` | value not in the dictionary code-set | `{tag: 54, enum_violation: true}` |

## Testing a rule

```bash
safix scan sample.log --rules ./my-rules/ --report console
safix rules            # lists built-in detectors + built-in YAML rules
```

## Tuning & false positives

- Set `severity` / `confidence` honestly — triage priority = severity × confidence.
- Always fill `benign:` with the legitimate activity that looks identical.
- Disable a noisy rule with `disabled_rules: [SAFIX-CUSTOM-0001]` in the config, or suppress by
  rule/session/comp-id/value with a `suppressions:` entry.
- Thresholds for the built-in APP/SESS/ENC detectors live under `thresholds:` in the config —
  see `safix/config.py` for the full set and defaults.
