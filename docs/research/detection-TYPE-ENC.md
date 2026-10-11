# SAFIX Detection Specifications — DATATYPE-GRAMMAR (TYPE) & ENCODING (ENC)

Scope: convert the TYPE and ENC attack-vector catalogues into **log-observable detection
specifications** for a QuickFIX **tag=value log scanner**. `<SOH>` (0x01) is rendered `|`;
an *embedded* SOH inside a value is written `^A`.

Source catalogues consolidated here:
- `fix-attack-vectors/raw-agent-reports/TYPE.md` — engine-grounded (quickfix C++ / quickfixj), IDs `AV-TYPE-1..33`
- `fix-attack-vectors/raw-agent-reports/ENC.md` — engine-grounded encodings, IDs `AV-ENC-1..30`
- `fix-attack-vectors/spec-derived/TYPE.md` + skill `vectors.md` — spec-derived datatype grammar, IDs `SV-TYPE-1..37`
- `fix-attack-vectors/spec-derived/ENC.md` + skill `vectors.md` — spec-derived encoding, IDs `SV-ENC-1..14`

**How to read scope.** A tag=value log scanner sees the raw SOH-delimited wire bytes of each
message. It can therefore observe: every datatype lexical violation, every Len/Data desync,
tag-grammar/enum/framing anomalies, and XML-attack *string signatures* carried inside
XmlData/SecurityXML/EncodedText-type fields. It **cannot** see live binary decoder state
(SBE/FAST/GPB), JSON gateway behaviour, WebSocket/TLS framing, or an engine's classpath — those
are OUT-OF-SCOPE and flagged as needing a live decoder or environment check.

**Statefulness.** Every in-scope TYPE and ENC-tag=value vector in this document is **STATELESS /
single-message** — each is decided from the bytes of one FIX message with no cross-message
history. (The only stateful encoding vector, FAST operator-dictionary desync `AV-ENC-20`, is
out-of-scope.) This is called out per family below and is the default unless a row says otherwise.

---

## 1. Summary tables (all vectors)

Severity = impact if the parser/consumer is vulnerable. Confidence = how reliably a tag=value log
scanner can assert the finding with low false-positives. Scope = observable in a tag=value log?

### 1a. DATATYPE-GRAMMAR — engine-grounded (`AV-TYPE-*`)

| ID | Name | Sev | Conf | In-scope (tag=value log)? |
|----|------|-----|------|---------------------------|
| AV-TYPE-1 | DATA length > actual bytes (over-read, CPP-C1) | High | High | Yes |
| AV-TYPE-2 | DATA length negative (reversed-iterator UB) | High | High | Yes |
| AV-TYPE-3 | DATA length huge / INT_MAX (crash vs quadratic DoS) | High | High | Yes |
| AV-TYPE-4 | DATA length < actual (trailing bytes re-tokenized / injection) | High | High | Yes |
| AV-TYPE-5 | DATA length = 0 with non-empty value | Med | Med | Yes |
| AV-TYPE-6 | DATA length-driven field absorption (Java) | High | Med | Yes |
| AV-TYPE-7 | DATA carries SOH+`=`/embedded frame at correct length | High | Med | Yes |
| AV-TYPE-8 | DATA present, Length absent (or vice-versa) | Med | High | Yes |
| AV-TYPE-9 | Length field lexically malformed | Med | High | Yes |
| AV-TYPE-10 | Signature(89)/SignatureLength(93) off-convention probe | Med | Med | Yes |
| AV-TYPE-11 | FpML DATA length tag ≠ data−1 (cross-field OOB) | High | Med | Yes |
| AV-TYPE-12 | INT sign/zero/overflow boundary grammar | Med | High | Yes |
| AV-TYPE-13 | SEQNUM/LENGTH/NUMINGROUP signedness & width divergence | Med | Med | Yes |
| AV-TYPE-14 | FLOAT/PRICE/QTY/AMT… exponent notation | Med | High | Yes |
| AV-TYPE-15 | FLOAT special values / commas / multiple dots / unary plus | Med | High | Yes |
| AV-TYPE-16 | CHAR empty / multi-char / embedded multibyte | Low-Med | High | Yes |
| AV-TYPE-17 | BOOLEAN anything but Y/N | Low | High | Yes |
| AV-TYPE-18 | UTCTIMESTAMP out-of-range components | High | High | Yes |
| AV-TYPE-19 | UTCTIMESTAMP fractional-second length grammar | Med | High | Yes |
| AV-TYPE-20 | UTCTIMEONLY out-of-range + coercion | Med | High | Yes |
| AV-TYPE-21 | UTCDATEONLY / LOCALMKTDATE calendar & format | High | Med | Yes |
| AV-TYPE-22 | MONTHYEAR unvalidated despite strict grammar | Med-High | Med | Yes |
| AV-TYPE-23 | CURRENCY no ISO-4217 enforcement | Med | Med | Yes |
| AV-TYPE-24 | COUNTRY no ISO-3166 enforcement | Med | Med | Yes |
| AV-TYPE-25 | EXCHANGE no ISO-10383 MIC enforcement | Med | Med | Yes |
| AV-TYPE-26 | TZTIMESTAMP / TZTIMEONLY no TZ-grammar validation | Med | Med | Yes |
| AV-TYPE-27 | MULTIPLECHARVALUE Java-regex vs C++-unvalidated | Med | Med | Yes |
| AV-TYPE-28 | MULTIPLEVALUESTRING / MULTIPLESTRINGVALUE delimiter grammar | Low-Med | Med | Yes |
| AV-TYPE-29 | STRING embedded non-printable control chars | Med-High | High | Yes |
| AV-TYPE-30 | Enum off-by-one / case / canonicalization | Med (High for sec-enums) | High* | Yes |
| AV-TYPE-31 | TAGNUM 0/negative/overflow/leading-zeros/non-numeric | Med-High | High | Yes |
| AV-TYPE-32 | DATA/XMLDATA/STRING overlong (honest-length) | Med | High | Yes |
| AV-TYPE-33 | LANGUAGE / XID / DAYOFMONTH unvalidated string types | Low-Med | Med | Yes |

\* AV-TYPE-30 confidence is High **only** when the scanner has the dictionary's enum code-sets loaded.

### 1b. DATATYPE-GRAMMAR — spec-derived (`SV-TYPE-*`)

| ID | Name | Sev | Conf | In-scope? |
|----|------|-----|------|-----------|
| SV-TYPE-1 | TagNum with leading zeros | Med | High | Yes |
| SV-TYPE-2 | TagNum / int non-numeric, sign, spaces, empty | High | High | Yes |
| SV-TYPE-3 | int carrying decimal / comma / exponent | Med | High | Yes |
| SV-TYPE-4 | SeqNum / NumInGroup zero or negative | High | High | Yes |
| SV-TYPE-5 | NumInGroup / Length huge magnitude (allocation bomb) | High | High | Yes |
| SV-TYPE-6 | Length / TagNum = 0 (XSD vs prose contradiction) | Med | High | Yes |
| SV-TYPE-7 | decimal with exponent / scientific notation | High | High | Yes |
| SV-TYPE-8 | decimal NaN / Infinity / special tokens | High | High | Yes |
| SV-TYPE-9 | decimal exceeding 15 significant digits | Med-High | Med | Yes |
| SV-TYPE-10 | decimal degenerate forms (lone sign/dot, multi-dot) | Med | High | Yes |
| SV-TYPE-11 | DayOfMonth out of 1..31 (XSD has no range) | Low-Med | Med | Yes |
| SV-TYPE-12 | Reserved100/1000/4000Plus below reserved floor | Med | Med | Yes |
| SV-TYPE-13 | UTCTimestamp component out of range | High | High | Yes |
| SV-TYPE-14 | UTCTimestamp leap second (SS=60) / illegal SS=61 | Med | Med | Yes |
| SV-TYPE-15 | UTCTimestamp xs:dateTime (ISO `T`/`Z`) vs FIX form | High | High | Yes |
| SV-TYPE-16 | UTCTimestamp sub-second precision abuse (ps / bare dot) | High | High | Yes |
| SV-TYPE-17 | UTCTimeOnly 24:00:00 / no date context | Med | Med | Yes |
| SV-TYPE-18 | UTCDateOnly / LocalMktDate semantic confusion | Med | Low | Yes (advisory) |
| SV-TYPE-19 | TZTimestamp / TZTimeOnly offset abuse (+13/+14, SS=60) | Med | Med | Yes |
| SV-TYPE-20 | Year 0000 / all-zero date components | Med | Med | Yes |
| SV-TYPE-21 | MonthYear month 00 / 13-19 (regex `(0\|1)\d` defect) | Med-High | High | Yes |
| SV-TYPE-22 | MonthYear day 00/32-39, week w0/w6-9, uppercase W | Med-High | High | Yes |
| SV-TYPE-23 | Country `.{2}` — any two bytes | Med | Med | Yes |
| SV-TYPE-24 | Currency `.{3}` — any three bytes / case | Med-High | Med | Yes |
| SV-TYPE-25 | Exchange `.*` — every string incl. empty | High | Med | Yes |
| SV-TYPE-26 | char ≠1 char / empty / delimiter / control | Med-High | High | Yes |
| SV-TYPE-27 | Boolean outside `[YN]` | High | High | Yes |
| SV-TYPE-28 | MultipleCharValue delimiter abuse | Med-High | High | Yes |
| SV-TYPE-29 | MultipleStringValue `.+(\s.+)*` token abuse | Med | Med | Yes |
| SV-TYPE-30 | data value containing SOH and `=` (len is only boundary) | High | High | Yes |
| SV-TYPE-31 | Length > actual data bytes (over-read) | High | High | Yes |
| SV-TYPE-32 | Length < actual data bytes (truncation / re-parse) | High | High | Yes |
| SV-TYPE-33 | Length = 0 / negative / non-numeric / huge | High | High | Yes |
| SV-TYPE-34 | XMLData accepted as plain string (XXE feed) | High | Med | Yes (signature) |
| SV-TYPE-35 | Enum value outside the defined codeSet | High | High* | Yes |
| SV-TYPE-36 | SettlType union (codeSet ∪ Tenor) cross-grammar | Med-High | Med | Yes |
| SV-TYPE-37 | CheckSum(10) / BodyLength(9) datatype looseness | High | High | Yes |

\* SV-TYPE-35 confidence is High only with the dictionary enum code-sets loaded.

### 1c. ENCODING — engine-grounded (`AV-ENC-*`)

| ID | Name | Sev | Conf | In-scope (tag=value log)? |
|----|------|-----|------|---------------------------|
| AV-ENC-1 | FIXML XXE file-read via SYSTEM general entity | High | Med | **Partial** — content signature inside XML-bearing field |
| AV-ENC-2 | FIXML external-DTD SSRF | High | Med | **Partial** — content signature |
| AV-ENC-3 | FIXML billion-laughs / nested entity expansion | High | Med | **Partial** — content signature |
| AV-ENC-4 | FIXML blind XXE via parameter entities | High | Med | **Partial** — content signature |
| AV-ENC-5 | FIXML XInclude content injection | Med | Med | **Partial** — content signature |
| AV-ENC-6 | FIXML quadratic entity blow-up | Med | Low | **Partial** — content signature |
| AV-ENC-7 | FIXML deeply-nested elements (stack exhaustion) | Med | Low | **Partial** — content signature |
| AV-ENC-8 | FIXML encoding-decl mismatch (UTF-7/16/BOM smuggling) | Med | Low | **Partial** — byte-level heuristic |
| AV-ENC-9 | FIXML schemaLocation / namespace poisoning | Med | Med | **Partial** — content signature |
| AV-ENC-10 | FIXML CDATA / oversized-text abuse | Med | Med | **Partial** — content signature |
| AV-ENC-11 | XML parser-selection hardening bypass (classpath) | High | n/a | **No** — environment/SBOM check, not a wire observable |
| AV-ENC-12 | SBE blockLength over-read | High | — | No — binary, needs live decoder |
| AV-ENC-13 | SBE short-message / blockLength under-read | High | — | No — binary |
| AV-ENC-14 | SBE template/schema/version mismatch | High | — | No — binary |
| AV-ENC-15 | SBE repeating-group dimension overflow | High | — | No — binary |
| AV-ENC-16 | SBE var-length length-prefix vs buffer (CPP-C1 class) | High | — | No — binary |
| AV-ENC-17 | SBE null/absent presence-encoding abuse | Med | — | No — binary |
| AV-ENC-18 | FAST presence-map (PMAP) bit manipulation | High | — | No — binary stream |
| AV-ENC-19 | FAST stop-bit continuation overflow | High | — | No — binary stream |
| AV-ENC-20 | FAST operator state desync (STATEFUL) | High | — | No — binary stream, cross-message |
| AV-ENC-21 | FAST decimal exponent/mantissa & ByteVector overflow | Med-High | — | No — binary stream |
| AV-ENC-22 | JSON duplicate-key divergence | High | — | No — JSON gateway |
| AV-ENC-23 | JSON deep nesting / huge number / precision | High | — | No — JSON gateway |
| AV-ENC-24 | JSON type confusion / NaN / escape / trailing data | High | — | No — JSON gateway |
| AV-ENC-25 | GPB unknown field numbers & wire-type confusion | Med | — | No — protobuf transport |
| AV-ENC-26 | GPB length-delimited overflow & nested-depth DoS | Med-High | — | No — protobuf transport |
| AV-ENC-27 | WebSocket text-vs-binary frame-type confusion | High | — | No — WS transport |
| AV-ENC-28 | WebSocket masking & control-frame abuse | Med | — | No — WS transport |
| AV-ENC-29 | SOH/delimiter confusion across encodings | High | Med | **Partial** — tag=value side = Len/Data (see AV-TYPE-1/4) |
| AV-ENC-30 | Encoding-length-prefix desync via TLS fragmentation | Med-High | — | No — transport/record layer |

### 1d. ENCODING — spec-derived (`SV-ENC-*`)

| ID | Name | Sev | Conf | In-scope? |
|----|------|-----|------|-----------|
| SV-ENC-1 | data/XMLData length-vs-delimiter (core framing rule) | High | High | Yes |
| SV-ENC-2 | Length prefix negative / huge / non-numeric | High | High | Yes |
| SV-ENC-3 | SOH / `=` injection into a non-data field value | Med-High | High | Yes |
| SV-ENC-4 | CheckSum / BodyLength integrity not in grammar | Med | High | Yes |
| SV-ENC-5 | MessageEncoding(347) / charset confusion | Med | Med | Yes |
| SV-ENC-6 | Missing final SOH / repeated SOH / empty field | Low-Med | High | Yes |
| SV-ENC-7 | Oversized message / unbounded repetition | Med | High | Yes |
| SV-ENC-8 | FIXML XMLData carries unrestricted content → XXE feed | High | Med | Yes (signature) |
| SV-ENC-9 | FIXML DOCTYPE / entity-expansion (billion laughs) | High | Med | Yes (signature) |
| SV-ENC-10 | FIXML schemaLocation / namespace poisoning | Med | Med | Yes (signature) |
| SV-ENC-11 | FIXML deep nesting / oversized document | Med | Low | Partial (signature) |
| SV-ENC-12 | Cross-encoding representation divergence (tag=value↔FIXML) | Med-High | Low | No — translating gateway |
| SV-ENC-13 | FIXML abbreviated-name / union-type ambiguity | Low-Med | Low | No — FIXML parse |
| SV-ENC-14 | Field-order reliance in tag=value | Low-Med | High | Yes |

### 1e. In-scope vs out-of-scope at a glance

- **IN-SCOPE (fully observable in a tag=value log):** all `AV-TYPE-1..33`, all `SV-TYPE-1..37`;
  `SV-ENC-1..7`, `SV-ENC-14`; the tag=value half of `AV-ENC-29`.
- **IN-SCOPE as content signature only** (the XML lives inside a tag=value DATA/XMLDATA field; the
  scanner flags the signature, the exploit fires in a downstream XML parser):
  `AV-ENC-1..10` (partial), `SV-ENC-8..11`, `SV-TYPE-34`.
- **OUT-OF-SCOPE (needs a live decoder / environment check):** `AV-ENC-11` (classpath/SBOM);
  SBE `AV-ENC-12..17`; FAST `AV-ENC-18..21`; JSON `AV-ENC-22..24`; GPB `AV-ENC-25..26`;
  WebSocket `AV-ENC-27..28`; TLS-framing `AV-ENC-30`; `SV-ENC-12..13` (translating/FIXML gateways).

---

## 2. THE DATATYPE GRAMMAR TABLE (primary deliverable)

One row per FIX datatype → validating regex/rule → example VALID → example INVALID. These become
the scanner's datatype validators. Conventions:

- Regexes are **PCRE**, anchored (`^…$`), applied to the **raw field value bytes** between `=` and
  the terminating SOH. The scanner is **byte-oriented** unless noted (matters for CHAR / multibyte).
- `enforced-free` = the FIX engines (quickfix C++ `StringConvertor`/typedef; quickfixj
  `DataDictionary.checkValidFormat` empty-`break`) apply **no** lexical check even with
  `UseDataDictionary=Y`; the grammar below is the *declared* (spec) grammar the scanner should
  enforce, and any mismatch is a "declared-strict / enforced-free" advisory finding.
- Numeric magnitude (32/64-bit overflow) is a **secondary** check layered on top of the regex, not
  expressible in the regex itself.

| Datatype | Validating regex / rule | Example VALID | Example INVALID | Notes / source IDs |
|----------|-------------------------|---------------|-----------------|--------------------|
| **INT** | `^-?[0-9]+$` (single optional `-`; no `+`, no space, no `.`/`,`/`e`; leading zeros tolerated by engines) | `34`, `-1`, `007` | `+5`, ` 5`, `3 4`, `3.0`, `1e5`, `` | `0x`/hex rejected. Overflow: flag `|value| > 2^31-1` as 32-bit-risk. AV-TYPE-12, SV-TYPE-2/3 |
| **LENGTH** | `^[0-9]+$` and value ≥ 1 (XSD allows 0; prose "must be positive") | `8`, `100` | `-5`, `12A`, `+8`, ` 8`, (`0` = soft flag) | Drives Len/Data; see §3. Leading zeros `0008`→8 accepted. AV-TYPE-9, SV-TYPE-6/33 |
| **TAGNUM** | `^[1-9][0-9]*$` (positive, **no leading zeros** per prose) | `35`, `108` | `0035`, `0`, `-1`, `1A`, `` (empty tag) | `007`≡`7` aliasing risk. AV-TYPE-31, SV-TYPE-1/2 |
| **SEQNUM** | `^[0-9]+$` and value ≥ 1 | `1`, `34` | `0`, `-1` | C++ u64 vs Java i32: `(2^31, 2^63]` diverges (Java rejects, C++ accepts). AV-TYPE-13, SV-TYPE-4 |
| **NUMINGROUP** | `^[0-9]+$` and value ≥ 1 | `1`, `3` | `0`, `-1`, `2000000000` | Negative/zero/huge drive group loops → DoS. AV-TYPE-13, SV-TYPE-4/5 |
| **FLOAT / QTY / PRICE / AMT / PERCENTAGE / PRICEOFFSET** | `^-?(?:[0-9]+\.?[0-9]*|\.[0-9]+)$` (optional single `-`; one optional `.`; no `e`/`E`, no `+`, no comma) | `12.5`, `-3`, `23.`, `.5`, `0.00` | `1e5`, `+3.14`, `1,000.5`, `NaN`, `Inf`, `1.2.3`, `.`, `-`, `` | Secondary: flag >15 significant digits (precision). `23.`/`.5` accepted by both engines. AV-TYPE-14/15, SV-TYPE-7/8/9/10 |
| **CHAR** | `^.$` (exactly one **byte**) | `1`, `Y`, `A` | `` (empty), `12`, `€` (multibyte → >1 byte) | Java counts UTF-16 units, C++ bytes → multibyte differential. AV-TYPE-16, SV-TYPE-26 |
| **BOOLEAN** | `^[YN]$` (case-sensitive) | `Y`, `N` | `y`, `n`, `T`, `1`, `0`, `true`, `YN`, `` | Security flags (43/123/141/97) are high-value. AV-TYPE-17, SV-TYPE-27 |
| **STRING** | `^[^\x00-\x08\x0A-\x1F\x7F]*$` (printable; no NUL/ESC/CR/LF/BS/DEL; SOH is the delimiter so cannot appear in a token) | `ACME`, `Order #5` | `A\x00B`, `A\x1B[2J`, `line1\x0Aline2` | Flag echo-to-log fields (Text 58, ClOrdID 11) hardest. AV-TYPE-29, SV-TYPE (control-char) |
| **MULTIPLECHARVALUE** | `^[A-Za-z0-9]( [A-Za-z0-9])*$` (single ASCII space between single alnums) | `A B C` | `A  B`, ` A`, `A `, `AB CD`, `A\tB`, `` | XSD `\s` is looser (tab/NL) → engine differential. AV-TYPE-27, SV-TYPE-28 |
| **MULTIPLEVALUESTRING / MULTIPLESTRINGVALUE** | `^\S+( \S+)*$` (space-delimited non-empty tokens; strict form) | `FOO BAR` | `A  B` (empty token), ` A`, `A ` | Engines are no-op here (free-form). Advisory. AV-TYPE-28, SV-TYPE-29 |
| **UTCTIMESTAMP** | `^\d{4}(0[1-9]\|1[0-2])(0[1-9]\|[12]\d\|3[01])-([01]\d\|2[0-3]):[0-5]\d:([0-5]\d\|60)(\.\d{3}\|\.\d{6}\|\.\d{9}\|\.\d{12})?$` | `20231130-09:30:00`, `20231130-09:30:00.123`, `19981231-23:59:60` | `20231301-00:00:00`, `20231130-25:00:00`, `...09:30:61`, `2023-11-30T09:30:00Z`, `...09:30:00.` (bare dot), `...09:30:00.1` (1-digit frac) | SS=60 allowed (leap). **Add calendar post-check** (Feb-31, Apr-31, non-leap Feb-29). Non-std fraction length = soft flag. AV-TYPE-18/19, SV-TYPE-13/14/15/16 |
| **UTCTIMEONLY** | `^([01]\d\|2[0-3]):[0-5]\d:([0-5]\d\|60)(\.\d{3}\|\.\d{6}\|\.\d{9}\|\.\d{12})?$` | `09:30:00`, `23:59:60` | `24:00:00`, `25:61:61`, `:30:00` | `xs:time` allows `24:00:00`, FIX prose caps HH≤23. AV-TYPE-20, SV-TYPE-17 |
| **UTCDATEONLY** | `^\d{4}(0[1-9]\|1[0-2])(0[1-9]\|[12]\d\|3[01])$` | `20231130` | `20231301`, `20230231` (calendar), `2023-11-30`, `2025011` | Add calendar post-check. AV-TYPE-21, SV-TYPE-13/20 |
| **LOCALMKTDATE** | *declared* same as UTCDATEONLY: `^\d{4}(0[1-9]\|1[0-2])(0[1-9]\|[12]\d\|3[01])$` — **enforced-free** | `20231130` | `BANANA`, `99999999`, `2025/01/01` | Engines accept ANY string → high-value logic-bypass on settlement/maturity fields. AV-TYPE-21, SV-TYPE-18 |
| **MONTHYEAR** | prose-strict: `^\d{4}(0[1-9]\|1[0-2])((0[1-9]\|[12]\d\|3[01])\|w[1-5])?$` — **enforced-free** | `202312`, `20231215`, `202312w3` | `202300`, `202313`, `20231232`, `202312w6`, `202312W3` | XSD regex `\d{4}(0\|1)\d([0-3wW]\d)?` is **defective** (admits mo 00/13-19, wk w0/w6-9, upper-W). AV-TYPE-22, SV-TYPE-21/22 |
| **CURRENCY** | `^[A-Z]{3}$` (ISO-4217 shape) — **enforced-free**; optional ISO allow-list | `USD`, `JPY` | `usd`, `ZZ`, `US1`, `123`, `` | `ZZZ`/`XXX` pass the shape but aren't real codes (allow-list catches). AV-TYPE-23, SV-TYPE-24 |
| **COUNTRY** | `^[A-Z]{2}$` (ISO-3166 shape) — **enforced-free**; optional ISO allow-list | `US`, `GB` | `USA`, `zz`, `U1`, `1`, `` | AV-TYPE-24, SV-TYPE-23 |
| **EXCHANGE** | `^[A-Z0-9]{4}$` (ISO-10383 MIC shape) — **enforced-free**; XSD declares `.*` | `XNAS`, `XLON` | `` (empty), `NOTAMIC`, `' OR 1=1`, `../../etc`, multi-KB | `.*` = free-form injection slot. AV-TYPE-25, SV-TYPE-25 |
| **TZTIMESTAMP** | `^\d{4}(0[1-9]\|1[0-2])(0[1-9]\|[12]\d\|3[01])-([01]\d\|2[0-3]):[0-5]\d:[0-5]\d(\.\d+)?(Z\|[+-](0[1-9]\|1[0-2])(:[0-5]\d)?)$` — **enforced-free** | `20231130-09:30:00+05:00`, `...00Z` | `...+14:00`, `...+99:99`, `...+9`, `...:59:60+00` | SS max 59 here (no leap, unlike UTCTimestamp). Offset hh 01-12 (real +13/+14 exist → spec-illegal). AV-TYPE-26, SV-TYPE-19 |
| **TZTIMEONLY** | `^([01]\d\|2[0-3]):[0-5]\d(:[0-5]\d)?(Z\|[+-](0[1-9]\|1[0-2])(:[0-5]\d)?)$` — **enforced-free** | `09:30Z`, `09:30:00-05:00` | `25:00+99:99`, `12:00ZZZ`, `12:00+9` | AV-TYPE-26, SV-TYPE-19 |
| **TENOR** | `^[DMWY][0-9]+$` with quantity > 0 | `D3`, `M6`, `W2`, `Y1` | `D0` (prose >0), `W`, `3D`, `M007` | XSD `[DMWY](\d)+` permits `0`/leading-zeros. SV-TYPE-36 |
| **DAYOFMONTH** | `^([1-9]\|[12]\d\|3[01])$` (1-31) — **enforced-free** | `1`, `31` | `0`, `32`, `-1`, `99` | XSD has no range facet. AV-TYPE-33, SV-TYPE-11 |
| **LANGUAGE** | `^[a-z]{2}$` (ISO-639) — **enforced-free** | `en`, `ja` | `english`, `zz`, `EN`, `` | AV-TYPE-33 |
| **Reserved100Plus** | `^[0-9]+$` and value ≥ 100 | `100`, `150` | `99`, `-1` | SV-TYPE-12 |
| **Reserved1000Plus** | `^[0-9]+$` and value ≥ 1000 | `1000` | `999` | SV-TYPE-12 |
| **Reserved4000Plus** | `^[0-9]+$` and value ≥ 4000 | `4000` | `3999` | SV-TYPE-12 |
| **DATA** | opaque bytes — **no lexical grammar**; validated only by the Len/Data pair algorithm (§3) | (any bytes of declared length) | (declared-len ≠ actual-len) | May legally contain SOH/`=`. AV-TYPE-1..8, SV-TYPE-30..33 |
| **XMLDATA** | opaque bytes (`xs:string`, "no content restrictions"); Len/Data algorithm (§3) **plus** XML-signature scan (§5) | `<FIXML>…</FIXML>` | content containing `<!DOCTYPE`, `<!ENTITY`, `SYSTEM`, `file://`, `<xi:include` | AV-TYPE-32, SV-TYPE-34, SV-ENC-8/9 |
| **SettlType** (union) | match **either** SettlTypeCodeSet enum **or** TENOR `^[DMWY][0-9]+$` (qty>0) | `0`, `1`, `W2` | `D0`, `W00`, `Y999999999`, undefined enum | Union doubles grammar surface. SV-TYPE-36 |
| **CheckSum(10)** | datatype is String, but session rule: `^[0-9]{3}$` and 000 ≤ value ≤ 255 | `001`, `255` | `0`, `1`, `256`, `999`, `abc`, `00000000000` | Datatype-only validation cannot catch forged checksum; recompute to verify. SV-TYPE-37, SV-ENC-4 |
| **BodyLength(9)** | `^[0-9]+$`; integrity = value must equal counted body bytes (8…=…SOH after 9 up to and incl. SOH before 10) | matches actual body | huge, or ≠ counted body | Frame-level Len; apply §3 over/under/huge logic at message scope. SV-TYPE-37, SV-ENC-4 |

**Table size: 30 datatype rows** (28 distinct FIX datatypes + the two framing fields CheckSum/BodyLength
carried as explicit rows; LOCALMKTDATE/LOCALMKTTIME, TZ* and the three Reserved*Plus are enumerated
individually). Every `enforced-free` row is a "declared-strict / enforced-free" advisory: the engine
will **not** reject it, so the scanner is the only line of defence for those types.

---

## 3. Len/Data pair detection (CPP-C1 family — the second key deliverable)

Covers `AV-TYPE-1..11`, `SV-TYPE-30..33`, `SV-ENC-1..2`, and the tag=value side of `AV-ENC-29`.
**Stateless / single-message.**

### 3.1 The pair table

A DATA field's byte length is given by a preceding LENGTH field. Both engines compute the length
tag as `dataTag − 1` (quickfix `Message.cpp:588-589`, quickfixj `Message.java:948`), **except**
Signature(89) whose length is SignatureLength(93) (hard special-case). The scanner must carry an
explicit `(LenTag → DataTag)` table built from the dictionary rather than trusting `data−1`.

**FIX44 / shared session base (16 pairs):**

```
93  -> 89    SignatureLength -> Signature        [SPECIAL: 89-1=88 is NOT the len tag]
90  -> 91    SecureDataLen -> SecureData
95  -> 96    RawDataLength -> RawData
212 -> 213   XmlDataLen -> XmlData
348 -> 349   EncodedIssuerLen -> EncodedIssuer
350 -> 351   EncodedSecurityDescLen -> EncodedSecurityDesc
352 -> 353   EncodedListExecInstLen -> EncodedListExecInst
354 -> 355   EncodedTextLen -> EncodedText
356 -> 357   EncodedSubjectLen -> EncodedSubject
358 -> 359   EncodedHeadlineLen -> EncodedHeadline
360 -> 361   EncodedAllocTextLen -> EncodedAllocText
362 -> 363   EncodedUnderlyingIssuerLen -> EncodedUnderlyingIssuer
364 -> 365   EncodedUnderlyingSecurityDescLen -> EncodedUnderlyingSecurityDesc
445 -> 446   EncodedListStatusTextLen -> EncodedListStatusText
618 -> 619   EncodedLegIssuerLen -> EncodedLegIssuer
621 -> 622   EncodedLegSecurityDescLen -> EncodedLegSecurityDesc
```

**FIX50SP2 additional "well-behaved" pairs (LenTag = DataTag−1):** 1184→1185, 1578→1579,
1277→1278, 1280→1281, 1282→1283, 1397→1398, 1401→1402, 1403→1404, 1468→1469, 1620→1621,
1664→1665, 1733→1734, 1871→1872, 1874→1875, 2072→2073, 2074→2075, 2111→2112, 2351→2352,
2481→2482, 2637→2638, 2651→2652, 2665→2666, 2715→2716, 2718→2719, 2721→2722, 2797→2798,
42171→42172, plus the 40004/40008/40978/40980/40982/40984/40986/40988 and 41083/41101/41107/
41256/41320/41324/41458/41476/41482/41653/41710/41806/41811/41873/41969/42025 blocks, and
2179→2180, 2287→2288. (Total DATA-typed fields: 13 in FIX44 "wire", 70+ in FIX50SP2.)

**FIX50SP2 pairs where the engine's `data−1` heuristic is FACTUALLY WRONG (AV-TYPE-11):** the
engine reads an unrelated neighbour as the length. The scanner must flag these specially because
the "length" the engine uses is a semantically unrelated field a defender never watches.

```
Len(1525)  -> Data(1527)  EncodedDocumentationText   ; data-1=1526 = UnderlyingPriceQuoteCurrency (CURRENCY)
Len(1678)  -> Data(1697)  EncodedOptionExpirationDesc ; data-1=1696 = PartyDetailSubIDType (INT)
Len(42451) -> Data(42486) LegPaymentStreamFormula     ; data-1=42485 = NoLegPaymentStreamFormulas (NUMINGROUP)
Len(42652) -> Data(42684) PaymentStreamFormula        ; data-1=42683 = NoPaymentStreamFormulas (NUMINGROUP)
Len(42947) -> Data(42982) UnderlyingPaymentStreamFormula; data-1=42981 = NoUnderlyingPaymentStreamFormulas (NUMINGROUP)
```
Plus the "Len-after-Data" (class B) convention fields where data−1 points at the previous
(unrelated) field: data tags 2371, 2493, 2521, 2801, 2808, 2814 (their spec Len is Data+1, but the
engine still reads Data−1).

### 3.2 The algorithm (per message, byte-accurate)

```
INPUT: raw message bytes (SOH = 0x01)
Build fields[] by scanning tag '=' value SOH, BUT handle DATA length-aware:

for each field (tag,valueStart) in order:
    if tag is a known LenTag (from §3.1 table):
        declaredLen = parse_int(value_of(tag))           # may fail / be negative / huge
        dataTag     = pairTable[tag]
        # locate the data field value: next field must be dataTag '='
        pos      = byte offset immediately after "dataTag="
        nextSOH  = offset of first 0x01 at/after pos      # naive delimiter end
        actualLen= nextSOH - pos
        bufEnd   = end of message bytes

        # ---- classify ----
        if declaredLen parse failed (non-digit/sign/space):      -> AV-TYPE-9  / SV-TYPE-33  (malformed length)
        elif declaredLen < 0:                                    -> AV-TYPE-2  / SV-TYPE-33  (negative -> UB/underflow)
        elif declaredLen == 0 and actualLen > 0:                 -> AV-TYPE-5             (zero-len, non-empty)
        elif declaredLen >= 2^31 or (pos+declaredLen) > bufEnd:  -> AV-TYPE-3  / SV-TYPE-31 (huge/over-read beyond buffer)
        elif declaredLen > actualLen:                            -> AV-TYPE-1/6/SV-TYPE-31 (over-read; swallows following fields)
        elif declaredLen < actualLen:                            -> AV-TYPE-4  / SV-TYPE-32 (under-read; tail re-tokenized)
        else (declaredLen == actualLen):                         -> OK at the framing layer, but:
             if value_bytes[0..declaredLen) contains 0x01 or '=' -> AV-TYPE-7 / SV-TYPE-30 (embedded frame / SOH smuggling)

        # ---- advance length-aware (mirror the engine) ----
        consume exactly declaredLen bytes as the data value; resume parsing at pos+declaredLen+1

    if dataTag seen with NO preceding LenTag in this FieldMap:   -> AV-TYPE-8             (orphan data field)
    if LenTag seen with its dataTag absent:                      -> AV-TYPE-8             (orphan length field)

    # heuristic-misfire overlay (AV-TYPE-11):
    if dataTag in FpML_mismatch_set and (dataTag-1) is present and numeric:
        -> AV-TYPE-11  (engine would read the data-1 neighbour (CURRENCY/INT/NUMINGROUP) as the length)
```

**Sub-class severities / signals:**
- `declaredLen > actualLen` and `pos+declaredLen > bufEnd` → **over-read past buffer** (C++ SIGSEGV /
  heap disclosure). **High.** True-positive signature: `354=1000000|355=A|` with only 1 byte present.
- `declaredLen > actualLen` but still inside the message → **field absorption** (AV-TYPE-6, Java
  swallows following `tag=value|` fields). **High.** Signature: declaredLen equals the summed byte
  length of several following fields.
- `declaredLen < actualLen` → **trailing-byte re-parse / smuggling** (AV-TYPE-4). **High.** Scan the
  leaked tail `value[declaredLen .. nextSOH)` for `^?\x01?\d{1,7}=` (looks like an injected field);
  signature `95=3|96=AAA35=D|`.
- `declaredLen == actualLen` but value contains SOH/`=` → **embedded-frame smuggling** (AV-TYPE-7 /
  SV-TYPE-30). **High** (second-order: log/DB/IDS injection). Signature `212=19|213=8=FIX.4.4|35=5||`.
- `declaredLen == 0, actualLen > 0` → **zero-length ambiguity** (AV-TYPE-5). **Med.**
- negative / non-numeric / ≥2^31 → **memory-safety / DoS** (AV-TYPE-2/3/9, SV-TYPE-33). **High.**
- Signature(89): verify the length came from **93**, not 88; flag a present `88=` decoy or a
  93-vs-89 byte desync inside the trailer (AV-TYPE-10). **Med.**

**False-positive sources for §3:** (a) a legitimately large, honest-length DATA payload (declared ==
actual, no embedded control) is **not** a finding — only desync or embedded-control is; (b) a DATA
value that *legitimately* contains SOH at the correct length is spec-legal — flag it only as an
informational "embedded-control carried in DATA" unless it parses as a full `tag=value` frame;
(c) logs that render SOH as a printable `|`/`^A` must be read in their true byte form or actualLen
is miscounted — the scanner must know the log's SOH rendering.

---

## 4. Per-family detection specs (in-scope datatype & framing)

Each family below is **stateless / single-message**. The datatype table (§2) is the validator; this
section adds the true-positive signature, false-positive sources, and detector note per family.

### 4.1 Numeric grammar — INT / LENGTH / SEQNUM / NUMINGROUP / TAGNUM
*(AV-TYPE-12/13/31, SV-TYPE-1..6)* — Category: datatype lexical (integer family).
- **Signal:** field value fails its integer regex (§2), or magnitude crosses a width boundary.
- **True-positive signature:** `108=30.0` (int with decimal), `34=0`/`34=-1` (seqnum), `268=-1`
  (numingroup), `0035=D` (leading-zero tag → `007`≡`7` aliasing), `9=` non-matching body length.
- **Detector note:** apply the regex; then a magnitude check — flag `> 2^31-1` (Java i32 reject vs
  C++ accept for SEQNUM), `> 2^63-1`, and ≥20-digit magnitudes (allocation-bomb class, SV-TYPE-5).
  For TAGNUM, additionally normalize-and-compare: if `atoi(tag)` of a leading-zero tag collides with
  another tag present in the same FieldMap → **duplicate-via-alias** flag.
- **False positives:** leading-zero integers are *accepted* by both engines (canonicalize to int) —
  flag as Low-confidence advisory, not a reject-class finding, except for TAGNUM where leading zeros
  are a prose violation and an aliasing primitive. Very large but legitimate quantities on QTY/notional
  fields are a FLOAT concern, not INT.

### 4.2 Decimal grammar — FLOAT / PRICE / QTY / AMT / PERCENTAGE / PRICEOFFSET
*(AV-TYPE-14/15, SV-TYPE-7/8/9/10)* — Category: datatype lexical (decimal family).
- **Signal:** value fails the decimal regex (§2), or exceeds 15 significant digits.
- **True-positive signature:** `44=1e5` (exponent), `44=NaN`/`44=Inf` (IEEE specials — defeat
  comparison-based risk checks), `44=1,000.5` (thousands comma), `44=1.2.3` (multi-dot),
  `44=+3.14` (unary plus), `44=.`/`44=-` (degenerate).
- **Detector note:** the regex rejects all of the above. A **separate soft rule** counts significant
  digits (strip sign, leading zeros, decimal point; count remaining digits) and flags >15 as a
  precision-loss advisory (SV-TYPE-9). Treat `NaN`/`Inf` as **High** severity (risk-check bypass).
- **False positives:** `23.` (trailing dot) and `.5` (leading dot) are **accepted by both engines** —
  the regex permits them; do not flag. Legitimately long high-precision prices on crypto venues may
  exceed 15 sig-digits → precision rule is advisory, not a security reject.

### 4.3 Enumerated grammar — CHAR / BOOLEAN / enum code-sets
*(AV-TYPE-16/17/30, SV-TYPE-26/27/35/36)* — Category: value/enum validation.
- **Signal:** CHAR length≠1; BOOLEAN ∉ {Y,N}; enum value ∉ dictionary code-set; case/kind mismatch.
- **True-positive signature:** `54=I` (Side has no I — last enum is H), `40=U` (OrdType stops at T),
  `35=d` (lowercase MsgType), `43=y`/`43=1`/`43=true` (boolean), `54=12` (char two bytes),
  `150=99` (char field fed a 2-digit int).
- **Detector note:** requires the Orchestra/dictionary code-sets loaded — emit `max_enum+1`, gap
  values, case-flipped, cross-kind. Prioritize security-relevant enums: MsgType(35), EncryptMethod(98),
  Side(54), OrdType(40), and the boolean session flags PossDupFlag(43), ResetSeqNumFlag(141),
  GapFillFlag(123), PossResend(97). For SettlType(63/587/1557) apply the union rule (enum ∪ Tenor).
- **False positives:** venues with `allowUnknownEnumValues`/user-defined-field ranges legitimately
  carry undefined enums — Medium-confidence unless the field is a core session/routing enum.
  User-defined tag ranges (≥5000, or Reserved*Plus) are expected to be non-standard.

### 4.4 Temporal grammar — UTCTIMESTAMP / UTCTIMEONLY / UTCDATEONLY / TZ* / MONTHYEAR / LOCALMKTDATE
*(AV-TYPE-18..26, SV-TYPE-13..22)* — Category: datatype lexical (date/time).
- **Signal:** value fails the temporal regex (§2); or passes the component-range regex but is a
  calendar-impossible date; or uses the ISO `xs:dateTime` form (`-`→`T`, trailing `Z`) in a FIX field.
- **True-positive signature:** `60=20259901-25:61:61` (month 99/hour 25/min 61/sec 61),
  `60=2023-11-30T09:30:00Z` (ISO form wedge), `52=...00.1` (1-digit fraction), `52=...00.` (bare dot),
  `60=20230231-...` (Feb-31 calendar), `200=202313` (MonthYear month 13), `200=202312w6` (bad week),
  `541=BANANA` (LOCALMKTDATE garbage), `1132=...+14:00` (TZ offset > ±12).
- **Detector note:** two-stage — (1) regex for component ranges and separators; (2) calendar
  post-check (days-in-month incl. leap year) for the date portion. Flag the C++↔Java differential
  explicitly: C++ rejects hour>23/min>59 but accepts sec=60/Feb-31/year-0000; Java's lenient
  `GregorianCalendar`/`SimpleDateFormat` **silently coerces** hour=25/month=99 → the value is
  accepted-and-shifted (replay/audit-trail corruption). For MONTHYEAR, flag any value that matches the
  defective XSD regex `\d{4}(0|1)\d([0-3wW]\d)?` but **not** the prose-strict regex.
- **False positives:** SS=60 is a **valid** leap second — do not flag on its own (flag SS=61).
  Sub-second fractions of 3/6/9/12 digits are standard; "other digit counts by bilateral agreement"
  are grammar-legal, so flag only as Low advisory. LOCALMKTDATE/MONTHYEAR/TZ*/CURRENCY/COUNTRY/
  EXCHANGE are `enforced-free`: real venues carry locale/venue-specific values the engine accepts;
  keep these Medium-confidence advisories, not reject-class.

### 4.5 String & identifier grammar — STRING / MULTIPLE* / CURRENCY / COUNTRY / EXCHANGE / LANGUAGE / DAYOFMONTH
*(AV-TYPE-23..29/33, SV-TYPE-23..29)* — Category: datatype lexical (string / declared-free).
- **Signal:** STRING contains non-printable control bytes; MULTIPLE* violates delimiter grammar;
  CURRENCY/COUNTRY/EXCHANGE/LANGUAGE off-shape; DAYOFMONTH out of 1..31.
- **True-positive signature:** `58=A\x00B\x1B[2J` (NUL + ANSI escape → log/console injection),
  `15=usd`/`15=ZZZ` (currency), `421=USA` (country 3-char), `207=` / `207=' OR 1=1` (exchange `.*`),
  `18=A  F` (double-space multi-char-value).
- **Detector note:** STRING control-char scan is **High** confidence and important for echoed fields
  (Text 58, ClOrdID 11, any field rendered to an operator console or stored in a DB) — flag NUL, ESC,
  CR, LF, BS, DEL. The `enforced-free` identifier types get a shape regex + optional ISO/MIC allow-list.
- **False positives:** EXCHANGE `.*` means *any* string is spec-valid — only treat injection-shaped or
  empty/oversized values as findings, not merely "non-MIC". A placeholder currency `XXX` ("no currency",
  ISO-4217 reserved) is legitimate. Multibyte UTF-8 in STRING may be legitimate (name fields); the
  control-char rule targets C0/C1 controls, not high bytes.

### 4.6 Framing & field structure — tag=value encoding
*(SV-ENC-3/4/6/7/14, AV-TYPE-8)* — Category: encoding/framing. **Stateless.**
- **Signal:** non-DATA value contains raw SOH or lacks exactly one `=`; doubled/missing SOH; empty
  value (`tag=|`); CheckSum not 3 digits / out of 000-255 / mismatched recompute; BodyLength ≠ counted
  body; mandated header-field order broken (8,9,35 first; 10 last); message over a configured size cap.
- **True-positive signature:** `58=ab^A9999=INJECTED` (SOH in non-data field → smuggling),
  `40=2||44=10` (double SOH / empty field), `10=001` not matching recompute, `8=..|35=D|9=..` (9/35
  swapped), `354=1000000|355=<1MB>` (oversized honest payload).
- **Detector note:** recompute BodyLength (bytes between the SOH after `9=…` and the SOH before `10=`)
  and CheckSum (sum of all bytes up to and including the SOH before `10=`, mod 256, 3-digit) — mismatch
  is High-confidence framing-integrity. SOH-in-non-data-value is SessionRejectReason 17; its absence in
  a reject log is the risk signal.
- **False positives:** some gateways legitimately skip checksum/bodylength verification (still flag,
  but note config). Body-field reordering is spec-legal (silent-normalize) → Low severity; only
  header-field order is a framing break.

---

## 5. XML-in-field content signatures (ENC — in-scope as string signature)

Covers `AV-ENC-1..10` (partial), `SV-ENC-8..11`, `SV-TYPE-34`. **Stateless / single-message.**

**Key framing:** quickfix (C++) and quickfixj do **not** parse inbound FIXML/SBE/FAST/JSON/GPB — their
only live XML sink is the dictionary loader. So message-level FIXML XXE is a **venue/gateway** concern,
not a quickfix runtime bug. BUT a tag=value log scanner CAN and SHOULD flag XML-attack signatures that
appear **inside** XmlData(213)/SecurityXML(1185)/EncodedText(355)-type field values, because any
downstream XML consumer (FpML processor, FIXML gateway, risk/clearing system) that parses those bytes
inherits the full XXE/DoS surface. The datatype says XMLData has "no content restrictions" (SV-TYPE-34),
so the scanner is the only guard.

- **Detection signals (string signatures inside DATA/XMLDATA field values):**
  - XXE / external entity: `<!DOCTYPE`, `<!ENTITY`, ` SYSTEM `, ` PUBLIC `
  - external-resource / SSRF: `file://`, `http://`, `https://`, `ftp://`, `jar:`, `netdoc:`,
    `169.254.169.254` (cloud-metadata) within a DOCTYPE/entity context
  - parameter-entity (blind XXE): `<!ENTITY %`, `%`-named entity refs inside the internal subset
  - billion-laughs / entity-expansion DoS: a `<!ENTITY>` whose value references other entities
    (`&name;` repeated), or **repeated entity references** `(&\w+;){N}` with N over a threshold
    (e.g. ≥100), or one large entity referenced many times (quadratic, AV-ENC-6)
  - XInclude (bypasses DOCTYPE defenses): `<xi:include`, `http://www.w3.org/2001/XInclude`
  - schemaLocation / namespace poisoning: `xsi:schemaLocation`, `noNamespaceSchemaLocation` pointing
    at an off-host URL (AV-ENC-9 / SV-ENC-10)
  - CDATA smuggling: `<![CDATA[` containing control bytes / embedded SOH / `tag=value` (AV-ENC-10)
  - encoding-decl / BOM smuggling: a UTF-16/UTF-7 BOM (`FF FE`, `FE FF`, `2B 2F 76`) or
    `encoding="UTF-7"`/`"UTF-16"` on the XML declaration carried in a field — a filter-bypass primitive
    for the DOCTYPE signatures above (AV-ENC-8)
  - deep nesting (stack-exhaustion): element nesting depth over a threshold inside the field (AV-ENC-7 /
    SV-ENC-11) — count `<tag>` open-depth
- **True-positive signature:** `213=<?xml ...><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>`
  inside an XmlData field; `<!DOCTYPE L [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;…">]>` (billion-laughs).
- **Severity / confidence:** High severity (if a downstream parser is unhardened), Medium confidence —
  the scanner can assert the **signature is present**, not that it is exploited (the exploit depends on
  the consuming XML parser's config).
- **False-positive sources:** SecurityXML / FpML fields legitimately carry XML — but a *well-formed*
  FpML payload has **no** `<!DOCTYPE`/`<!ENTITY`/`SYSTEM`/`file://`, so those signatures remain
  anomalous even in an XML-carrying field. A benign `<![CDATA[` is common; only flag CDATA that
  contains control bytes or an embedded `tag=value|` run. The BOM/encoding-decl heuristic has the
  highest FP rate (Low confidence) — many systems legitimately send UTF-16.
- **Out-of-scope note:** `AV-ENC-11` (classpath hardening-bypass, quickfixj `DataDictionary.java:80`
  gating the XXE mitigation on the JDK-Xerces factory name, and the always-unhardened
  `ExternalDtdDataDictionaryLoader`) is an **environment/SBOM** finding — it is not visible on the wire
  and must be checked against the target's classpath, not the log. The actual dictionary-load XXE/SSRF
  fixture (`FIX_External_DTD.xml`) is a build/config artifact, not a message.

---

## 6. Out-of-scope alternate encodings (need a live decoder)

These are NOT tag=value and cannot be validated from a QuickFIX tag=value log. Flag clearly as
requiring a live decoder / reference implementation for the target venue. Listed for completeness so
the scanner can emit an explicit "out-of-scope, venue-encoding" note if a non-tag=value feed is
mis-routed to it.

- **SBE (Simple Binary Encoding)** — `AV-ENC-12..17`: blockLength over/under-read, template/schema/
  version mismatch & unknown templateId, repeating-group numInGroup overflow, var-length length-prefix
  vs buffer (the binary analogue of CPP-C1), null/absent sentinel abuse. Venues: CME iLink3 / MDP3.
- **FAST** — `AV-ENC-18..21`: PMAP bit manipulation, stop-bit continuation overflow, **operator state
  desync (STATEFUL, cross-message)**, decimal exponent/mantissa & ByteVector overflow. Venues: FAST
  market-data feeds.
- **JSON encoding** — `AV-ENC-22..24`: duplicate-key divergence (validate-vs-execute smuggling), deep
  nesting / huge-number / precision loss, type confusion / NaN/Infinity / unicode-escape / trailing
  data / array-length abuse. Venues: REST/WS order & market-data gateways.
- **GPB (protobuf)** — `AV-ENC-25..26`: unknown field numbers & wire-type confusion, length-delimited
  length overflow & nested-message depth DoS. Venues: internal buses / FIX-GPB mappings.
- **WebSocket transport** — `AV-ENC-27..28`: text-vs-binary frame-type confusion & fragmentation
  desync, masking & control-frame abuse. Venues: FIX-over-WebSocket order entry.
- **TLS-record framing** — `AV-ENC-30`: encoding length-prefix desync via TLS-record/TCP-segment
  fragmentation; plaintext-on-FIXS-port downgrade. Transport/record layer, not application log.
- **Translating-gateway divergence** — `SV-ENC-12` (tag=value↔FIXML value divergence), `SV-ENC-13`
  (FIXML abbreviated-name/union-type ambiguity): require both encodings' views; a tag=value log sees
  only one side. The tag=value side of SOH/delimiter smuggling (`AV-ENC-29`) **is** in-scope and is
  already covered by the Len/Data algorithm (§3) and SV-ENC-3.

---

## 7. Validation caveats carried from the source catalogues

- Datatype lexical validation only fires in the engines when `UseDataDictionary=Y` **and** validation
  is enabled; with it off, ALL grammar violations are silently accepted. The scanner is engine-config
  independent — it validates the bytes regardless — but severity interpretation (reject vs silent
  accept) depends on the venue's config.
- The `enforced-free` types (CURRENCY, COUNTRY, EXCHANGE, LOCALMKTDATE, LOCALMKTTIME, MONTHYEAR, TZ*,
  LANGUAGE, DAYOFMONTH, MULTIPLEVALUESTRING/MULTIPLESTRINGVALUE, XMLDATA) are accepted verbatim by both
  quickfix and quickfixj even with validation ON — so these scanner checks are *additive* defence, and
  should be surfaced as Medium-confidence advisories rather than "the engine would reject this".
- C++↔Java differentials (SEQNUM width AV-TYPE-13; date leniency AV-TYPE-18/20/21; CHAR byte-vs-UTF-16
  AV-TYPE-16; MULTIPLECHARVALUE AV-TYPE-27) mean the *same* message can be accepted by one engine and
  rejected by the other — a fail-open-through-the-lenient-side risk at any gateway bridging the two.
  The scanner should treat these as High-value because they are cross-engine desync primitives.
- Exact SessionRejectReason codes (373 values) and crash-vs-leak outcomes for the C++ OOB path
  (AV-TYPE-1/2/3/11) are dynamic-verification items in the source reports — the scanner reports the
  *structural* condition, not the runtime outcome.
