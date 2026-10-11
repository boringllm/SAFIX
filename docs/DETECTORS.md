# SAFIX Detector Catalogue

Inventory of SAFIX detection rules (**61** rules), each mapped to the source attack-vector ID(s) it realizes. Run `safix rules` for the live list.

## SESS (15 rules)

| Rule ID | Severity | Conf | Title | Vectors | Regulatory |
|---------|----------|:----:|-------|---------|------------|
| SAFIX-SESS-FRM-001 | high | H | BodyLength(9) does not match the computed body | AV-SESS-FRM-07, AV-SESS-FRM-01, SV-ENC-4 |  |
| SAFIX-SESS-FRM-002 | high | H | BodyLength(9) is non-numeric | AV-SESS-FRM-01 |  |
| SAFIX-SESS-FRM-003 | high | H | CheckSum(10) does not match the recomputed value | AV-SESS-FRM-06, SV-ENC-4 |  |
| SAFIX-SESS-FRM-004 | medium | M | CheckSum(10) is not exactly three digits | SV-TYPE-37 |  |
| SAFIX-SESS-FRM-005 | medium | M | Message has no CheckSum(10) (truncated?) | AV-SESS-FRM-02 |  |
| SAFIX-SESS-FRM-006 | high | M | Message does not begin with BeginString(8) | AV-SESS-FRM-05, AV-STRUCT-16 |  |
| SAFIX-SESS-FRM-007 | high | M | Bytes present after CheckSum(10) within the record | AV-SESS-FRM-03 |  |
| SAFIX-SESS-SEQ-003 | medium | M | Too-low MsgSeqNum (sequence rewind / desync) | AV-SESS-SEQ-03 |  |
| SAFIX-SESS-SEQ-005 | medium | M | ResendRequest EndSeqNo(16)=0 (resend all — amplification) | AV-SESS-SEQ-05 |  |
| SAFIX-SESS-SEQ-007 | medium | H | ResendRequest inverted range (BeginSeqNo > EndSeqNo) | AV-SESS-SEQ-08 |  |
| SAFIX-SESS-SEQ-009 | medium | L | SequenceReset leapfrogs the sequence forward | AV-SESS-SEQ-09 |  |
| SAFIX-SESS-SEQ-011 | medium | M | PossDup resend missing OrigSendingTime(122) | AV-SESS-SEQ-12, SV-SESS-10 |  |
| SAFIX-SESS-SEQ-012 | high | H | Duplicate MsgSeqNum without PossDup(43=Y) (replay/injection) | AV-SESS-SEQ-12, SV-SESS-3 |  |
| SAFIX-SESS-SEQ-013 | high | M | GapFill targets a previously-queued high seqnum (smuggling chain) | AV-SESS-SEQ-13 |  |
| SAFIX-SESS-STA-001 | medium | L | Logon ResetSeqNumFlag(141)=Y (sequence reset) | AV-SESS-STA-01, SV-SESS-15 |  |

## TYPE (13 rules)

| Rule ID | Severity | Conf | Title | Vectors | Regulatory |
|---------|----------|:----:|-------|---------|------------|
| SAFIX-TYPE-001 | critical | H | DATA field declared length overruns the message (over-read) | AV-TYPE-1, AV-TYPE-3, SV-TYPE-31 |  |
| SAFIX-TYPE-002 | high | H | DATA field declared length disagrees with the field boundary | AV-TYPE-4, AV-TYPE-1, SV-TYPE-32 |  |
| SAFIX-TYPE-003 | medium | M | DATA field has no preceding length field (orphan) | AV-TYPE-8 |  |
| SAFIX-TYPE-004 | high | H | DATA length field is non-numeric | AV-TYPE-9, SV-TYPE-33 |  |
| SAFIX-TYPE-005 | high | H | DATA length field is negative | AV-TYPE-2, SV-TYPE-33 |  |
| SAFIX-TYPE-010 | medium | H | Datatype grammar violation | AV-TYPE-13, SV-TYPE-4, SV-TYPE-5 |  |
| SAFIX-TYPE-011 | medium | H | Calendar-impossible date | SV-TYPE-13 |  |
| SAFIX-TYPE-012 | high | H | Integer magnitude / width overflow | SV-TYPE-5 |  |
| SAFIX-TYPE-013 | low | L | Decimal precision-loss (advisory) | SV-TYPE-9 |  |
| SAFIX-TYPE-014 | high | H | Non-finite value in decimal field | AV-TYPE-15 |  |
| SAFIX-TYPE-017 | medium | M | Zero/negative count field | AV-TYPE-13, SV-TYPE-4 |  |
| SAFIX-TYPE-020 | high | M | Enum value not in dictionary code-set | AV-TYPE-30, AV-TYPE-33, SV-TYPE-35 |  |
| SAFIX-TYPE-021 | high | H | Control characters in STRING field | AV-TYPE-29 |  |

## STRUCT (14 rules)

| Rule ID | Severity | Conf | Title | Vectors | Regulatory |
|---------|----------|:----:|-------|---------|------------|
| SAFIX-STRUCT-001 | medium | M | Field has a non-numeric tag | AV-TYPE-31, AV-STRUCT-04 |  |
| SAFIX-STRUCT-002 | low | M | Tag has a leading zero (alias risk, e.g. 007 == 7) | AV-TYPE-31, SV-TYPE-1 |  |
| SAFIX-STRUCT-003 | low | M | Field has an empty value | SV-ENC-3 |  |
| SAFIX-STRUCT-004 | high | H | A structural tag (8/9/35/10) appears more than once | AV-STRUCT-06, SV-STRUCT-24 |  |
| SAFIX-STRUCT-005 | medium | M | Token without a '=' separator | AV-STRUCT-04, AV-TYPE-7 |  |
| SAFIX-STRUCT-006 | low | L | Field not terminated by a delimiter (truncated?) | AV-SESS-FRM-02 |  |
| SAFIX-STRUCT-101 | medium | H | Missing required field | AV-STRUCT-01, SV-STRUCT-1 |  |
| SAFIX-STRUCT-110 | low | L | Unknown/undefined tag | AV-STRUCT-04, AV-STRUCT-05 |  |
| SAFIX-STRUCT-111 | medium | M | Foreign tag for this message type | AV-STRUCT-05 |  |
| SAFIX-STRUCT-120 | medium | M | Unknown or undefined MsgType(35) | AV-STRUCT-20 |  |
| SAFIX-STRUCT-130 | high | M | Repeating-group count desync | AV-STRUCT-08, AV-STRUCT-09 |  |
| SAFIX-STRUCT-131 | high | H | Negative group count | AV-STRUCT-11, AV-TYPE-13 |  |
| SAFIX-STRUCT-132 | high | H | Non-numeric group count | AV-STRUCT-12, AV-TYPE-13 |  |
| SAFIX-STRUCT-140 | high | H | Duplicate scalar tag (parameter pollution) | AV-STRUCT-06, AV-STRUCT-07, SV-STRUCT-24 |  |

## APP (12 rules)

| Rule ID | Severity | Conf | Title | Vectors | Regulatory |
|---------|----------|:----:|-------|---------|------------|
| SAFIX-APP-001 | high | H | Non-positive OrderQty(38) | AV-APP-01, SV-APP-1 | SEC 15c3-5(c)(1)(ii), MiFID II RTS 6 Art.15 |
| SAFIX-APP-002 | medium | M | OrderQty(38) exceeds max order size | AV-APP-01 | SEC 15c3-5(c)(1)(ii), MiFID II RTS 6 Art.15 |
| SAFIX-APP-004 | medium | M | Order notional exceeds limit | AV-APP-01 | SEC 15c3-5(c)(1)(ii), MiFID II RTS 6 Art.15 |
| SAFIX-APP-005 | high | H | Non-positive Price(44) | AV-APP-02, SV-APP-2 | SEC 15c3-5(c)(1)(ii), MiFID II RTS 6 Art.15 |
| SAFIX-APP-010 | critical | H | OrigClOrdID(41) BOLA — cancel/replace of a foreign order | AV-APP-05, SV-APP-6 | SEC 15c3-5(c)(2)(iii), MiFID II RTS 6 Art.18 |
| SAFIX-APP-012 | high | M | Quantity escalation on replace | AV-APP-10, SV-APP-12 | SEC 15c3-5(b), MiFID II RTS 6 Art.15 |
| SAFIX-APP-018 | medium | M | Future-dated TransactTime(60) | AV-APP-16, SV-APP-18 | MiFID II RTS 25 (clock sync) |
| SAFIX-APP-019 | medium | M | Stale TransactTime(60) | AV-APP-16, SV-APP-18 | MiFID II RTS 25 (clock sync) |
| SAFIX-APP-022 | medium | M | Mass-cancel-all (kill-switch scope) | AV-APP-19 | MiFID II RTS 6 Art.12 (kill functionality) |
| SAFIX-APP-030 | medium | H | Stop order without StopPx(99) | SV-APP-3, AV-APP-03 |  |
| SAFIX-APP-031 | medium | H | Limit order without Price(44) | SV-APP-3 |  |
| SAFIX-APP-032 | low | M | Market order carrying a Price(44) | AV-APP-04 |  |

## ENC (7 rules)

| Rule ID | Severity | Conf | Title | Vectors | Regulatory |
|---------|----------|:----:|-------|---------|------------|
| SAFIX-ENC-001 | high | H | External-entity XXE signature in a field value | AV-ENC-01, AV-ENC-02, SV-ENC-8 |  |
| SAFIX-ENC-002 | high | M | Parameter-entity (blind XXE) signature | AV-ENC-04, SV-ENC-9 |  |
| SAFIX-ENC-003 | high | M | Entity-expansion / billion-laughs signature | AV-ENC-03, AV-ENC-06 |  |
| SAFIX-ENC-004 | high | M | XInclude signature (bypasses DOCTYPE defenses) | AV-ENC-05 |  |
| SAFIX-ENC-005 | medium | M | schemaLocation pointing off-host (schema poisoning/SSRF) | AV-ENC-09, SV-ENC-10 |  |
| SAFIX-ENC-006 | medium | M | CDATA smuggling (control bytes / embedded frame) | AV-ENC-10 |  |
| SAFIX-ENC-008 | low | L | UTF-7/16 BOM or encoding declaration (filter-bypass primitive) | AV-ENC-08 |  |
