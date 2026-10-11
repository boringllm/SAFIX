# QuickFIX Formats & Python FIX Parsing — Research for SAFIX

Research basis (read-only reference repos under `C:\temp\LLM\fix\`):
- Data dictionaries: `quickfix/spec/FIX44.xml`, `quickfix/spec/FIXT11.xml` (read fully); `FIX42.xml`, `FIX50SP2.xml` (headers skimmed).
- simplefix: `tools/simplefix/simplefix/{parser,message,constants,data,errors,__init__}.py`, `README.rst`.
- QuickFIX log/store: C++ `quickfix/src/C++/{FileStore,FileLog}.{cpp,h}`; QuickFIX/J `quickfixj/quickfixj-core/src/main/java/quickfix/{FileStore,FileLog,FileLogFactory}.java`, `quickfixj-base/.../FileUtil.java`; `quickfix/doc/html/configuration.html`.

This document is written so a developer can implement SAFIX's FIX parser, dictionary loader, and log/store auto-detector directly from it.

---

## 1. FIX wire format primer

### 1.1 Basic structure: `tag=value<SOH>`
A FIX message is a flat, ordered sequence of fields. Each field is `tag=value` followed by the **SOH** delimiter (ASCII `0x01`, "Start Of Header", shown as `|` or `^A` in printed logs).

- **tag**: an unsigned integer (the field number, e.g. `35`). On the wire it is ASCII digits.
- **value**: ASCII/raw bytes, terminated by `<SOH>` (except length-prefixed DATA fields, see 1.4).
- There is **no newline** inside a real message; the whole message is one byte string ending in `<SOH>` after the checksum.

Example (SOH shown as `|`):
```
8=FIX.4.4|9=65|35=A|34=1|49=CLIENT|52=20231015-14:30:00.000|56=SERVER|98=0|108=30|10=123|
```

### 1.2 The four structural fields
| Tag | Name | Role | Position |
|-----|------|------|----------|
| `8` | BeginString | Protocol version, e.g. `FIX.4.4`, or `FIXT.1.1` for FIX 5.x | **Must be first field** |
| `9` | BodyLength | Byte count of the "body" (see 1.3) | **Must be second field** |
| `35`| MsgType | Message type code, e.g. `A`=Logon, `0`=Heartbeat, `D`=NewOrderSingle, `8`=ExecutionReport | **Must be third field** (first body field) |
| `10`| CheckSum | 3-digit modulo-256 checksum | **Must be last field** |

The remaining header fields (34 MsgSeqNum, 49 SenderCompID, 56 TargetCompID, 52 SendingTime, ...) follow MsgType; then body fields; then the trailer (10, and optionally 93/89 Signature). Order of header vs. body vs. trailer matters to strict engines (QuickFIX `ValidateFieldsOutOfOrder`), but attackers will violate it.

### 1.3 BodyLength (tag 9) — exact computation
BodyLength = number of bytes starting **immediately after** the SOH that terminates the BodyLength field (i.e. the first byte of `35=...`) **up to and including** the SOH that terminates the field **immediately before** the CheckSum field (`10=`).

Equivalently: `len(full_message) - len("8=...<SOH>9=...<SOH>") - len("10=xxx<SOH>")`.

Confirmed by `simplefix/message.py::encode()`:
```
buf = b"35=" + msgtype + SOH + ...body...        # body starts at MsgType
body_length = len(buf)                            # everything from 35= to final SOH
buf = b"8=" + begin + SOH + b"9=" + body_length + SOH + buf
```
So the count covers from the `3` of `35=` through the SOH preceding `10=`. A valid message always has `10=` exactly `BodyLength` bytes after the start of the body.

**Anomalies SAFIX must flag**: declared `9=` ≠ computed body length (truncation/overflow, buffer-boundary attacks, smuggling extra fields past a short length). simplefix does **not** check this.

### 1.4 CheckSum (tag 10) — exact computation
CheckSum = (sum of every byte value in the message **up to but not including** the `1` of `10=`) **mod 256**, formatted as **exactly 3 ASCII digits, zero-padded** (`"%03d"`), then its own `<SOH>`.

Confirmed by `encode()`:
```
checksum = sum(c for c in buf)      # buf = everything through the SOH before 10=
buf += b"10=" + f"{checksum % 256:03}" + SOH
```
**Anomalies SAFIX must flag**: non-numeric checksum, not 3 digits, value ≠ recomputed sum, checksum computed over wrong range. simplefix does **not** verify the value — it only uses `10` as the stop tag.

### 1.5 Length-prefixed DATA fields (embedded SOH)
Some fields carry **binary/opaque data that may itself contain SOH (0x01)**. These are encoded as a pair: a **length** field immediately followed by the **data** field. The parser must read exactly `length` bytes for the data value instead of scanning for SOH.

Canonical pairs (len → data): `90→91` SecureData, `93→89` Signature, `95→96` RawData, `212→213` XmlData, `354→355` EncodedText, plus the full FIX.5.0SP2 set (68 pairs) — see `simplefix/data.py` `RAW_DATA` (vendor this table). Example:
```
95=5|96=ab|cd|          # RawData length 5, value is the 5 bytes "ab\x01cd" (contains SOH)
```
Here `96` holds `ab<SOH>cd` (5 bytes); the trailing SOH after the 5 bytes terminates the field. A naive SOH-split tokenizer would corrupt this. **Attack surface**: lying about the length (too short → desync; too long → over-read past end), or putting SOH-bearing data in a field the reader doesn't know is DATA.

### 1.6 Datatypes (from dictionaries)
Values are all ASCII on the wire; datatypes are semantic. Types seen in FIX44.xml (count): `STRING`(254), `INT`(193), `CHAR`(69), `NUMINGROUP`(59), `PRICE`(45), `QTY`(36), `LOCALMKTDATE`(36), `AMT`(34), `BOOLEAN`(30, `Y`/`N`), `PERCENTAGE`(23), `UTCTIMESTAMP`(21, `YYYYMMDD-HH:MM:SS[.sss]`), `LENGTH`(18), `FLOAT`(17), `CURRENCY`(17), `DATA`(16), `PRICEOFFSET`(10), `SEQNUM`(8), `MULTIPLEVALUESTRING`(8, space-separated enums), `EXCHANGE`(6), `MONTHYEAR`(5), `COUNTRY`(5), `UTCTIMEONLY`(1), `UTCDATEONLY`(1). `DATA` is the length-prefixed type from 1.5; `LENGTH`/`NUMINGROUP` are the integer counts preceding DATA fields / repeating groups.

---

## 2. Data dictionary XML schema reference

QuickFIX dictionaries are a single XML file per protocol version. Root → five sections. Section order in the QuickFIX files is: `<header>`, `<messages>`, `<trailer>`, `<components>`, `<fields>` (FIX44). A parser should locate sections by name, not position.

### 2.1 Root element `<fix>`
```xml
<fix type='FIX' major='4' minor='4' servicepack='0'>   <!-- FIX44.xml -->
<fix type='FIXT' major='1' minor='1' servicepack='0'>  <!-- FIXT11.xml -->
<fix type='FIX' major='5' minor='0' servicepack='2'>   <!-- FIX50SP2.xml -->
```
Attributes:
- `type`: `FIX` or `FIXT`. Determines the BeginString string: `FIX.<major>.<minor>` (e.g. `FIX.4.2`), except the FIXT transport whose BeginString is `FIXT.1.1`.
- `major`, `minor`: integers.
- `servicepack`: integer (0 when none). FIX50SP2 uses `servicepack='2'`.

BeginString derivation: `{"FIX" or "FIXT"}.{major}.{minor}`. (servicepack is **not** in the BeginString — FIX.5.0SP2 still logs on as `FIXT.1.1` with ApplVerID=9.)

### 2.2 `<header>` and `<trailer>`
Define the fields that appear in every message's header/trailer, in order, each with a `required` flag. They contain the same child elements as a `<message>` body: `<field>`, `<component>`, `<group>`.

```xml
<header>
  <field name='BeginString' required='Y' />
  <field name='BodyLength' required='Y' />
  <field name='MsgType' required='Y' />
  <field name='SenderCompID' required='Y' />
  ...
  <group name='NoHops' required='N'>
    <field name='HopCompID' required='N' />
    <field name='HopSendingTime' required='N' />
    <field name='HopRefID' required='N' />
  </group>
</header>
<trailer>
  <field name='SignatureLength' required='N' />
  <field name='Signature' required='N' />
  <field name='CheckSum' required='Y' />
</trailer>
```
**FIX 5.0 split**: in `FIX50SP2.xml` both are empty self-closing: `<header />` `<trailer />`. The header/trailer (and session/admin messages) live in **FIXT11.xml** instead (see 2.7).

### 2.3 `<messages>` / `<message>`
```xml
<messages>
  <message name='Heartbeat' msgtype='0' msgcat='admin'>
    <field name='TestReqID' required='N' />
  </message>
  <message name='NewOrderSingle' msgtype='D' msgcat='app'>
    <field name='ClOrdID' required='Y' />
    <component name='Instrument' required='Y' />
    <field name='Side' required='Y' />
    ...
  </message>
  <message name='XMLnonFIX' msgtype='n' msgcat='admin' />   <!-- can be empty -->
</messages>
```
`<message>` attributes:
- `name`: human name (e.g. `ExecutionReport`).
- `msgtype`: the tag-35 value. **1–2 chars**, may be a digit or letter or two-letter code (`0`, `A`, `D`, `8`, `AA`, `BH`, lowercase `n`). This is the key to look up by when parsing.
- `msgcat`: `admin` (session-level: Logon/Logout/Heartbeat/TestRequest/ResendRequest/SequenceReset/Reject) or `app` (business).

Children (ordered): `<field name required>`, `<component name required>`, `<group name required>`. Order defines the canonical field order for that message.

### 2.4 `<components>` / `<component>`
Reusable field blocks referenced by messages/other components by name. A component **definition** has only `name`; a **reference** (inside a message/group/component) has `name` + `required`.
```xml
<components>
  <component name='Instrument'>
    <field name='Symbol' required='N' />
    <field name='SecurityID' required='N' />
    <component name='SecAltIDGrp' required='N' />   <!-- nested component ref -->
    ...
  </component>
  <component name='Parties'>
    <group name='NoPartyIDs' required='N'>          <!-- a component wrapping a group -->
      <field name='PartyID' required='N' />
      <field name='PartyIDSource' required='N' />
      <field name='PartyRole' required='N' />
      <component name='PtysSubGrp' required='N' />   <!-- nested group via component -->
    </group>
  </component>
</components>
```
Components are a **flattening/inclusion** mechanism: when a message references `<component name='Instrument'>`, splice the component's children into the message at that position. Components may nest components and contain groups → recursion. Resolve by name lookup in the `<components>` map.

### 2.5 `<group>` — repeating groups (critical)
```xml
<group name='NoPartyIDs' required='N'>
  <field name='PartyID' required='N' />       <!-- FIRST field = implied delimiter -->
  <field name='PartyIDSource' required='N' />
  <field name='PartyRole' required='N' />
  <component name='PtysSubGrp' required='N' />
</group>
```
Attributes: **only `name` and `required`** (verified: no other attributes appear anywhere in FIX44.xml). The QuickFIX format is **not** the newer FIX Orchestra/Repository format — there are **no explicit `min`/`max`/`delimiter`/`implMinOccurs` attributes.** Conventions you must apply:
- `name` is the **count field** (always a `NUMINGROUP`/`INT` field, by convention named `NoXxx`, e.g. `NoPartyIDs`=453). Its integer value = number of repetitions that follow.
- **Implied delimiter = the FIRST child field listed in the group.** Each repetition begins when that delimiter tag reappears. (There is no attribute for this; it is positional.) Example: `NoPartyIDs` repetitions each start at `PartyID` (448).
- Children are the same as messages: ordered `<field>`, `<component>`, `<group>` (nested groups allowed → arbitrary nesting, e.g. `NoPartyIDs`→`PtysSubGrp`/`NoPartySubIDs`).
- `required='Y'` means the group must be present (count ≥ 1) when its container is present.

Parsing repeating groups correctly **requires the dictionary** (to know which tags are count fields, what the delimiter is, and which tags belong to the group) — this is why QuickFIX insists on `UseDataDictionary=Y` when groups are used. A dictionary-free tokenizer (like simplefix) returns a flat ordered list and leaves group reconstruction to the caller.

### 2.6 `<fields>` / `<field>` / `<value>`
The master field table — the authority for tag number ↔ name ↔ datatype ↔ enums.
```xml
<fields>
  <field number='1' name='Account' type='STRING' />
  <field number='4' name='AdvSide' type='CHAR'>
    <value enum='B' description='BUY' />
    <value enum='S' description='SELL' />
    <value enum='X' description='CROSS' />
    <value enum='T' description='TRADE' />
  </field>
  <field number='18' name='ExecInst' type='MULTIPLEVALUESTRING'>
    <value enum='1' description='NOT_HELD' />
    ...
  </field>
</fields>
```
`<field>` attributes:
- `number`: the integer tag (the join key between dictionary and wire/message definitions, which reference fields by `name`).
- `name`: unique field name used everywhere else in the file.
- `type`: one of the datatypes in 1.6.

`<value>` (0+ children; where enumerations live):
- `enum`: the on-wire value (e.g. `B`, `0`, `1`).
- `description`: symbolic constant (e.g. `BUY`). For `MULTIPLEVALUESTRING`, the wire value is a space-separated list of these enum tokens.

**Note**: enums are defined once per field in `<fields>`; message/group/header definitions reference fields by `name` only and never redefine enums or types.

### 2.7 FIXT 1.1 (transport/session) vs application dictionary split
- **FIX 4.0–4.4** (and 4.3): one self-contained dictionary. BeginString `FIX.4.x`. Header/trailer, admin + app messages all in the one file. SAFIX loads one dictionary keyed by BeginString.
- **FIX 5.0 / 5.0SP1 / 5.0SP2**: **two dictionaries**.
  - **FIXT11.xml** = the *session/transport* layer: defines `<header>`, `<trailer>`, and all **admin** messages (Logon `A`, Logout `5`, Heartbeat `0`, TestRequest `1`, ResendRequest `2`, Reject `3`, SequenceReset `4`). BeginString on the wire is `FIXT.1.1`.
  - **FIX50SP2.xml** = the *application* layer: `<header />`/`<trailer />` empty; only app messages (IOI, ExecutionReport, NewOrderSingle, ...). The app version is conveyed by **ApplVerID (1128)** / **DefaultApplVerID (1137)**, enum values `7`=FIX50, `8`=FIX50SP1, `9`=FIX50SP2 (see FIXT11 field 1128).
  - QuickFIX config expresses this as `TransportDataDictionary=FIXT11.xml` + `AppDataDictionary=FIX50SP2.xml` (vs. the single `DataDictionary=` for 4.x).
- **SAFIX implication**: build a dictionary loader that, for BeginString `FIXT.1.1`, loads a FIXT dictionary for header/trailer+admin and an app dictionary (chosen by ApplVerID or config) for business messages, merging the field tables. For `FIX.4.x`, load the single file. Field-number→definition tables can be merged into one lookup; keep per-message definitions separate per layer.

### 2.8 Minimal object model for a loaded dictionary
```
Dictionary(begin_string, type, major, minor, servicepack,
           fields_by_number: {int -> Field}, fields_by_name: {str -> Field},
           messages_by_msgtype: {str -> Message}, components: {str -> Component},
           header: [Element], trailer: [Element])
Field(number, name, type, values: {enum -> description})
Message(name, msgtype, msgcat, elements: [Element])
Component(name, elements: [Element])
Element = FieldRef(name, required) | ComponentRef(name, required) | GroupDef(name, required, elements)
# GroupDef.name is the NUMINGROUP count field; delimiter = elements[0] (first FieldRef, after resolving a leading component).
```

---

## 3. QuickFIX log & store formats

QuickFIX has two independent file-based subsystems: **FileLog** (human/audit log of messages + events) and **FileStore** (message persistence + sequence numbers for resend/recovery). The two C++/Java implementations differ in filenames and in binary-vs-text layout — SAFIX must handle both.

### 3.1 FileLog — `messages.log` / `event.log`
Produced by `FileLogFactory` when the session config sets `FileLogPath`. Two files per session: a **messages** log (the FIX traffic) and an **event** log (plain-text engine events — logons, disconnects, errors; not FIX). SAFIX cares about the messages log.

**Filename / session prefix**:
- **C++** (`FileLog.cpp`): prefix = `<BeginString>-<SenderCompID>-<TargetCompID>[-<SessionQualifier>]`; files are **`<prefix>.messages.current.log`** and **`<prefix>.event.current.log`**, with rotated backups `<prefix>.messages.backup.<N>.log`. A global (non-session) log uses prefix `GLOBAL`.
- **QuickFIX/J** (`FileLog.java` + `FileUtil.sessionIdFileName`): prefix = `<BeginString>-<Sender>[_<SenderSub>][_<SenderLoc>]-<Target>[_<TargetSub>][_<TargetLoc>][-<Qualifier>]`; files are **`<prefix>.messages.log`** and **`<prefix>.event.log`** (no `.current`). Illegal filename chars are replaced (QFJ-775), so `#`,`!` etc. become `_`.

Example filenames: `FIX.4.4-CLIENT-SERVER.messages.log`, `FIXT.1.1-ME-THEM.messages.current.log`.

**Line format** — `<timestamp><DELIM><raw FIX message with real SOH>\n`, one message per line:
- **C++** writes (both incoming and outgoing, `FileLog.h::onIncoming/onOutgoing`):
  ```
  m_messages << UtcTimeStampConvertor::convert(now, 9) << " : " << value << std::endl;
  ```
  → `YYYYMMDD-HH:MM:SS.ffffffffff : 8=FIX.4.4<SOH>9=...<SOH>...10=nnn<SOH>\n`
  - Timestamp precision **9** = up to nanoseconds; delimiter is **space-colon-space `" : "`**. Always present.
- **QuickFIX/J** (`FileLog.java::writeMessage` + `writeTimeStamp`):
  - The message timestamp is **optional**, controlled by `FileIncludeTimeStampForMessages` (**default OFF**). When off, the line is **just the raw message + `\n`** (no timestamp at all). When on, prefix is `UtcTimestampConverter.convert(date, includeMillis)` + delimiter **`": "` (colon-space, no leading space)**.
  - `FileIncludeMilliseconds` (default OFF) adds `.sss` to the timestamp.
  - So QFJ message lines look like either `8=FIX.4.4<SOH>...10=nnn<SOH>\n` (default) or `20231015-14:30:00: 8=FIX.4.4<SOH>...\n` or `20231015-14:30:00.123: 8=FIX...\n`.
  - Events always get a timestamp; messages do not by default.

**CRITICAL for SAFIX — no direction marker.** Neither C++ nor QFJ records inbound vs outbound in `messages.log`: `onIncoming`/`onOutgoing` (C++) and `logIncoming`/`logOutgoing` (QFJ) call the identical write path with no I/O tag. **Direction is not in the file.** To recover inbound/outbound:
1. Compare **SenderCompID(49)/TargetCompID(56)** in each message against the session's configured `SenderCompID`/`TargetCompID` (from the `.cfg`): if `49 == ourComp`, it is **outbound**; if `56 == ourComp`, it is **inbound**. This is the reliable method and needs the config (or inference of "our" CompID as the one that is constant as 49 across a subset).
2. Without config, infer: the CompID that appears as `49` in Logon `35=A` you *sent* is yours; or whichever CompID is constant on both sides and matches across the session.
SAFIX should treat direction as **derived metadata**, defaulting to "unknown" and upgrading to inbound/outbound when a config or heuristic resolves it.

**`FileLogHeartbeats`** (QFJ default **ON**): when off, Heartbeat/TestRequest admin noise is omitted from the log; attackers/analysts should not assume every seqnum appears.

**Timestamp recovery**: split each line on the **first** delimiter occurrence, but be careful — the timestamp itself contains `:` and `-`. Reliable rule: a log line that begins with the raw message starts with `8=` (BeginString). So: if the line starts with `8=` → no timestamp (QFJ default). Otherwise the timestamp is everything up to the delimiter that immediately precedes `8=`. Concretely, **find the substring starting at `8=FIX` (or `8=` followed by a version) and treat everything before it as the timestamp/prefix** (stripping a trailing `" : "` or `": "`). This is robust to both C++ and QFJ variants and to unknown custom prefixes.

### 3.2 FileStore — `.body` / `.header` / seqnum / `.session`
Produced when config sets `FileStorePath`. Persists outgoing messages (for resend) and sequence numbers. Filenames share the same session prefix as the log (C++: `<Begin>-<Sender>-<Target>[-<Qual>]`; QFJ: the FileUtil form).

**C++ FileStore** (`FileStore.cpp`) — 4 files:
| File | Format |
|------|--------|
| `<prefix>.body` | Raw FIX message bytes **concatenated back-to-back**, no separators. Each stored message is `msg.size()` bytes at a byte offset recorded in `.header`. Contains real SOH. |
| `<prefix>.header` | **TEXT index**, one record per stored message: `"%llu,%lld,%zu "` = `<MsgSeqNum>,<offset>,<size> ` (comma-separated, **space-terminated**, repeated). offset/size point into `.body`. |
| `<prefix>.seqnums` | **TEXT**, single record `"<nextSender> : <nextTarget>"` in fixed width `%20.20llu : %20.20llu` → file is exactly **43 bytes** for the 64-bit format. Legacy format was `%d : %d`. |
| `<prefix>.session` | **TEXT**, a single UTC creation timestamp string, format `YYYYMMDD-HH:MM:SS` (22-char buffer; `UtcTimeStampConvertor`). |

**QuickFIX/J FileStore** (`FileStore.java`) — 5 files, **different layout**:
| File | Format |
|------|--------|
| `<prefix>.body` | Same idea: concatenated raw message bytes, offsets in `.header`. |
| `<prefix>.header` | **BINARY**, big-endian (Java `DataOutputStream`): per message `writeInt(sequence)` (4 bytes) + `writeLong(offset)` (8 bytes) + `writeInt(size)` (4 bytes) = **16 bytes/record**. *Not* text — do not parse as ASCII. |
| `<prefix>.senderseqnums` | Sender next-seqnum, written via `writeUTF` (2-byte length prefix + ASCII digits). |
| `<prefix>.targetseqnums` | Target next-seqnum, `writeUTF`. (QFJ splits sender/target into two files; C++ keeps one `.seqnums`.) |
| `<prefix>.session` | Creation timestamp. |
(There is also `CachedFileStore` in QFJ with the same on-disk shape.)

**SAFIX implication**: the `.body` file is a goldmine — a raw stream of the session's outbound messages. To split it into messages, either (a) use the `.header` index (text for C++, 16-byte binary records for QFJ) for exact offset/size slicing, or (b) if `.header` is missing/corrupt, fall back to self-delimiting splitting on `8=`…`10=nnn<SOH>` boundaries (see 4.3). Auto-detect C++ vs QFJ header by: text `.header` (printable, commas) vs binary (16-byte multiples, high bytes). Presence of `.seqnums` → C++; `.senderseqnums`+`.targetseqnums` → QFJ.

### 3.3 Session settings file (`.cfg` / `.ini`)
INI-style, two heading types: `[DEFAULT]` (inherited by all sessions) and one `[SESSION]` per session. `#` begins a comment. `key=value` per line. Order: a `[SESSION]` inherits any `[DEFAULT]` key it doesn't override. Sample (`doc/html/configuration.html`):
```ini
# default settings for sessions
[DEFAULT]
ConnectionType=initiator
ReconnectInterval=60
SenderCompID=TW

# session definition
[SESSION]
BeginString=FIX.4.1
TargetCompID=ARCA
StartTime=12:30:00
EndTime=23:30:00
HeartBtInt=20
SocketConnectPort=9823
SocketConnectHost=123.123.123.123
DataDictionary=somewhere/FIX41.xml
```
Settings SAFIX should read (to identify a session, locate dictionaries, and resolve log direction):
- **Identity / routing**: `BeginString`, `SenderCompID`, `TargetCompID` (+ optional `SenderSubID`, `TargetSubID`, `SenderLocationID`, `TargetLocationID`, `SessionQualifier`). These define the session key and the filename prefix, and let SAFIX decide inbound/outbound.
- **Role**: `ConnectionType` = `initiator` or `acceptor`.
- **Dictionaries**: `UseDataDictionary` (`Y`/`N`), `DataDictionary=<file>` (FIX ≤4.4); for FIXT/5.x: `TransportDataDictionary=FIXT11.xml` + `AppDataDictionary=FIX50SP2.xml`, and `DefaultApplVerID` (ApplVerID enum or `FIX.5.0SP2`-style string).
- **Validation toggles** (tell SAFIX what the engine would/would not reject, useful for modelling permissiveness): `ValidateFieldsOutOfOrder` (default Y), `ValidateFieldsHaveValues`, `ValidateUserDefinedFields`, `CheckLatency`.
- **Storage/log paths**: `FileStorePath`, `FileLogPath`, `FileLogBackupPath`, `PersistMessages`.
- **Transport**: `SocketConnectHost`/`SocketConnectPort` (initiator), `SocketAcceptPort` (acceptor), `HeartBtInt`, `StartTime`/`EndTime`.
SAFIX can use a `.cfg` as an optional companion input to a log/store to resolve the session identity and direction; it must not require it.

---

## 4. Common FIX log formats "in the wild" + auto-detection

SAFIX will be handed files captured by many tools. Support at least these:

### 4.1 Formats to support
1. **Raw SOH stream** — one or many messages, delimiter is the real `0x01`. May be a single concatenated blob (no line breaks) or one message per line (`\n`/`\r\n`). This is the canonical form and what FileStore `.body` holds.
2. **Pipe-delimited (printed) logs** — `0x01` replaced by a printable separator for human reading. Common separators: `|` (most common; simplefix `pretty_print`/`to_string` default), `^A` literal, `^` , `;` , or even a space. Produced by copy-paste from terminals, Jira tickets, docs, `simplefix.pretty_print()`. SAFIX must let the delimiter be configured/auto-detected and must treat these as **lossy** (embedded-SOH DATA fields were already mangled if the tool blindly replaced bytes).
3. **QuickFIX `messages.log`** — section 3.1: optional `<timestamp> : ` / `<timestamp>: ` prefix + raw-SOH message + `\n`, no direction marker, C++ or QFJ filename. The most important real-world format.
4. **QuickFIX FileStore `.body` (+ `.header`)** — section 3.2: concatenated raw messages, split via the index file or by self-delimiting boundaries.
5. **FIXimate / spec-tool exports & Wireshark/tshark** — Wireshark's FIX dissector can export as text where fields are shown as `Tag=Value` lines or with the `fix.` field names; `tshark -V` output is multi-line per message with human labels. Captured **pcap payloads** (follow-TCP-stream) are raw-SOH. Support: (a) raw-SOH extracted from a TCP stream (same as #1), and (b) a tolerant "one `tag=value` per line, blank line between messages" reader for pretty-printed exports. FIXimate is primarily a reference/lookup site; its "exports" are effectively tag=value with `|` or newline separators → handled by #2.
6. **Timestamped/prefixed app logs** — many in-house apps prepend their own timestamp, log level, thread, or `<-- / -->` arrows for direction. SAFIX should strip any prefix before the first `8=` and, if an arrow/`IN`/`OUT`/`<--`/`-->` token is present in the prefix, capture it as a direction hint.

### 4.2 Recovering timestamp + direction (general rule)
For each candidate line:
1. Locate the first occurrence of `8=` that is followed by a FIX version token (`FIX.` or `FIXT.`). Everything before it = **prefix**; everything from it to the message end = **message**.
2. Parse the prefix opportunistically: a leading `YYYYMMDD-HH:MM:SS(.frac)?` (optionally followed by `:`/`Z`/offset) → timestamp; tokens `IN`/`OUT`/`<--`/`-->`/`RX`/`TX`/`recv`/`sent` → direction hint. Leave direction `unknown` otherwise and resolve later from 49/56 vs config (3.1).
3. The message end is the SOH **after** `10=nnn`. Prefer the explicit `10=` terminator; a trailing `\n`/`\r\n` ends the record for line-oriented files.

### 4.3 Auto-detection strategy (recommended algorithm)
Operate on bytes, never assume UTF-8 beyond ASCII:
1. **Read a probe** (first ~64 KB) as bytes.
2. **Pick the field delimiter**: if `0x01` present → delimiter = SOH (raw format, #1/#3/#4). Else scan for a byte that appears right after `10=` 3-digit groups and between `tag=value` tokens; candidates in priority order `|`, `\x01`, `^`, `;`, `\t`, ` `. Confirm by checking that splitting yields mostly `int=...` tokens and that `8=`,`9=`,`35=`,`10=` appear. This picks the pipe/printable variant (#2).
3. **Detect store `.body` vs log**: if a sibling `<prefix>.header` exists, or the data is one giant blob with multiple `8=FIX`…`10=nnn` runs and **no** line breaks/timestamps → treat as FileStore `.body`; split by the header index if available, else by boundary rule below. Binary `.header` (size % 16 == 0, non-printable) → QFJ; text `.header` with commas → C++.
4. **Detect per-line timestamp**: if lines do **not** start with `8=`, attempt prefix parse (4.2). If the detachable prefix matches a UTC timestamp and `" : "`/`": "` delimiter → QuickFIX messages.log; keep the timestamp.
5. **Message boundary rule (delimiter-agnostic, dictionary-free)**: a message starts at `8=` and ends at the delimiter following a `10=` + exactly 3 digits. Use this to re-segment concatenated streams and to recover from a corrupt/missing `.header`. Cross-check each segment's recomputed BodyLength/CheckSum and flag mismatches (do **not** discard — see §5).
6. **Version**: read BeginString (tag 8) of the first well-formed message to choose the dictionary (`FIX.4.x` single; `FIXT.1.1` → FIXT + app-by-ApplVerID).

SAFIX should expose the detected `{input_kind, field_delimiter, record_delimiter, has_timestamp, timestamp_format, direction_source}` so results are explainable, and allow explicit override of every detected parameter.

---

## 5. Python parsing recommendation

### 5.1 simplefix assessment (as an adversarial-log parser)
simplefix is a clean, dependency-free, MIT-licensed, well-tested library. `FixParser` is a streaming tokenizer; `FixMessage` is an **ordered list of `(tag_bytes, value_bytes)` pairs** that **preserves order and duplicates** and stores **values as raw bytes**. It correctly handles **length-prefixed DATA fields with embedded SOH** (`parser.py` lines 301–322, using the `RAW_DATA` table in `data.py`) and can be told to stop on a byte (LF) for multi-message files (`set_stop_byte`). `pretty_print()`/`to_string('|')` map SOH↔`|`. These are genuinely useful and align with what SAFIX needs for the *data model's spirit*.

**But for adversarial/malformed input it is fail-fast, which is disqualifying as-is.** `get_message()` **raises exceptions** (aborting the whole message) on exactly the cases a security scanner must survive and *record*:
- Non-numeric tag → `TagNotNumberError` (line 297–299). One bad tag kills the parse.
- Zero-length value → `EmptyValueError` by default (line 344) unless `allow_empty_values`.
- Missing leading `8=` → `FieldOrderError` (line 395) unless `allow_missing_begin_string`.
- DATA length not numeric → `RawLengthNotNumberError`; DATA not followed by SOH → `RawDataNotFollowedByFieldSeparator` (lines 310–311, 362–364) — i.e. a lying length tag throws.
- Stop-byte mid-tag → `IncompleteTagError`.

Other gaps:
- **No BodyLength (9) validation** and **no CheckSum (10) validation** at all — the parser merely uses `10` as the stop tag. So it silently accepts wrong `9`/`10` (lenient, but SAFIX must compute these itself to *detect* the anomaly).
- **Does not preserve byte offsets** or the exact raw per-field segment (it re-derives tag ints and value bytes; it discards the original `=`/SOH positions and any bytes stripped before `8=`). A security scanner needs offsets to point at the exact malicious bytes.
- **Fixed, FIX.5.0SP2 DATA-tag table**: unknown/custom DATA fields need `add_raw()`; an attacker using an unexpected tag for SOH-bearing data will desync a dictionary-free read.
- `get()`/`remove()` support duplicates via `nth`, but there is **no group structure** (dictionary-free by design).

**Verdict: do NOT depend on `FixParser.get_message()` as SAFIX's primary parser.** Its exception-on-malformed behavior is the opposite of the "never reject, always record" requirement.

### 5.2 Recommendation: write SAFIX's own lenient parser; vendor simplefix's data, not its parser
- **Write a custom, lenient, byte-oriented tokenizer** that **never raises on malformed input**. On any anomaly it records a structured finding and continues. This is non-negotiable for a scanner and is a small amount of code (the hard parts are the DATA-field and group logic, both well understood here).
- **Vendor (copy, with attribution — MIT) the `RAW_DATA` table from `simplefix/data.py`** as static data (the 68 length→data tag pairs) — it is the valuable, tedious-to-reproduce part. Optionally vendor the SOH/pretty-print constants.
- **Optionally keep simplefix as an installable dev/test dependency** to use as a *conformance oracle*: feed well-formed messages to both and assert agreement; this cheaply validates SAFIX's happy path. Do not put it on the runtime parse path.
- Rationale for custom over "vendor-and-wrap simplefix": the needed behaviors (no exceptions, byte offsets, BodyLength/CheckSum recomputation, dictionary-driven group reconstruction, per-field raw capture) touch the core of the tokenizer loop; wrapping would mean rewriting `get_message()` anyway.

### 5.3 Proposed internal FIX message data model
Preserve **everything**: order, duplicates, raw bytes, and byte offsets — never normalize away an anomaly. Suggested structures (bytes-first; decode lazily):
```python
@dataclass
class RawField:
    index: int            # 0-based position within the message (ordinal)
    tag_bytes: bytes      # exact tag bytes as seen (e.g. b"35", or b"3x5" if malformed)
    tag: int | None       # parsed int, or None if non-numeric (anomaly recorded)
    value: bytes          # exact value bytes (may contain SOH for DATA fields)
    raw: bytes            # the exact slice b"tag=value" as it appeared on the wire
    tag_offset: int       # byte offset of the tag, relative to message start
    value_offset: int     # byte offset of the value
    end_offset: int       # offset just past the terminating SOH
    is_data_value: bool   # True if read as a length-prefixed DATA value
    anomalies: list[Anomaly]   # per-field issues (non-numeric tag, empty value, ...)

@dataclass
class FixMessage:
    fields: list[RawField]          # ORDERED, duplicates kept exactly as seen
    raw: bytes                      # exact original message bytes (8=...10=nnn<SOH>)
    msg_offset: int                 # byte offset of this message within the source file
    source_line: int | None         # line number if line-oriented
    begin_string: bytes | None       # tag 8 (first occurrence)
    msg_type: bytes | None            # tag 35
    body_length_declared: int | None  # tag 9 as given
    body_length_computed: int         # recomputed per §1.3
    checksum_declared: bytes | None   # tag 10 as given
    checksum_computed: int            # recomputed per §1.4
    # recovered log metadata (may be unknown):
    timestamp: str | None
    direction: Literal["in","out","unknown"]
    field_delimiter: bytes            # b"\x01" or b"|" etc. as detected
    anomalies: list[Anomaly]          # message-level issues
    groups: GroupTree | None          # OPTIONAL, filled only when a dictionary is loaded

@dataclass
class Anomaly:
    code: str            # e.g. "NON_NUMERIC_TAG","BAD_CHECKSUM","BODYLENGTH_MISMATCH",
                         # "EMPTY_VALUE","MISSING_BEGINSTRING","DATA_LEN_OVERRUN",
                         # "DUPLICATE_TAG","SOH_IN_NONDATA_VALUE","TRAILING_BYTES", ...
    severity: str        # info|warn|error
    field_index: int | None
    tag: int | None
    detail: str
    byte_offset: int | None
```
Accessors mirror simplefix for familiarity but over the raw model: `get(tag, nth=1)`, `get_all(tag) -> list`, `count()`, iteration yields `RawField`. Provide `decoded(encoding='latin-1')` helpers but keep bytes authoritative (latin-1 round-trips any byte, good for display).

Core access is **dictionary-free** (always works, even on garbage). A **second, dictionary-aware pass** builds the optional `groups: GroupTree` by walking the message against the loaded dictionary (using NUMINGROUP count fields and first-child delimiters per §2.5), emitting anomalies for count mismatches, out-of-order group fields, unknown tags, undefined enums, and type violations — without ever discarding the flat `fields` list.

### 5.4 Anomalies the lenient parser must record (not reject)
Wrong/short/long BodyLength (compare declared vs computed); bad/missing/mis-padded CheckSum (compare vs recomputed); non-numeric or empty tag; empty value; missing or non-first BeginString; MsgType missing/misplaced; embedded SOH in a non-DATA value (`SOH_IN_NONDATA_VALUE`); DATA length overrun/underrun; duplicate tags where the dictionary expects one; repeating-group count ≠ actual repetitions; tags out of required order; unknown tag / undefined enum / type mismatch (dictionary pass); trailing bytes after `10=` within a record; truncated message (no `10=`). Each anomaly carries the exact byte offset so SAFIX can point at the malicious input.

---

## Appendix — key source references
- Wire/encode semantics (BodyLength, CheckSum, raw flag): `tools/simplefix/simplefix/message.py` `encode()` (lines ~523–575).
- Lenient-parse gaps / exceptions: `tools/simplefix/simplefix/parser.py` `get_message()` (lines ~265–410); `errors.py`.
- DATA tag table (vendor this): `tools/simplefix/simplefix/data.py` (`RAW_DATA`, `RAW_DATA_TAGS`, `RAW_LEN_TAGS`).
- SOH/equals constants: `tools/simplefix/simplefix/constants.py` (`SOH_BYTE=1`, `EQUALS_BYTE=61`, `SOH_STR=b'\x01'`).
- C++ FileLog line format (timestamp `" : "`, no direction): `quickfix/src/C++/FileLog.h` `onIncoming/onOutgoing` (lines 87–95); filenames `FileLog.cpp` (`messages.current.log`, backups).
- C++ FileStore layout (`.body`/`.header` text/`.seqnums` 43-byte/`.session`): `quickfix/src/C++/FileStore.cpp` (`set()` line ~257 header record `"%llu,%lld,%zu "`; `setSeqNum()` line ~335; filenames lines 73–78).
- QFJ FileLog (optional timestamp `": "`, `FileIncludeTimeStampForMessages` default off, no direction, `messages.log`): `quickfixj-core/.../FileLog.java`; settings + defaults `FileLogFactory.java`.
- QFJ FileStore (binary `.header` 16-byte records, split `senderseqnums`/`targetseqnums`): `quickfixj-core/.../FileStore.java` `set()` lines 369–384.
- Filename sanitization + prefix: `quickfixj-base/.../FileUtil.java` `sessionIdFileName()` (lines 39–59).
- Config `.cfg` format + settings: `quickfix/doc/html/configuration.html` ([DEFAULT]/[SESSION], `FileStorePath`, `FileLogPath`, `DataDictionary`, `TransportDataDictionary`, `AppDataDictionary`, `DefaultApplVerID`, `UseDataDictionary`, `ValidateFieldsOutOfOrder`).
- Dictionary schema: `quickfix/spec/FIX44.xml` (sections at lines 2/35/2354/2359/3733), `FIXT11.xml` (full), `FIX50SP2.xml` (`<header />`/`<trailer />` empty — confirms FIXT split).
