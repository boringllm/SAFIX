"""Length-prefixed DATA field table and FIX byte constants.

The ``RAW_DATA`` pair table below is vendored (copied verbatim) from **simplefix**
(https://github.com/da4089/simplefix), ``simplefix/data.py``, which is distributed under the
MIT License, Copyright (c) 2017-2023 David Arnold. Reproduced here under that license; see the
project README for the full attribution.

Each pair is ``(length_tag, data_tag)``: the integer value of ``length_tag`` gives the exact
byte length of the immediately-following ``data_tag`` value, which may itself contain the SOH
(0x01) delimiter. A correct parser must read exactly that many bytes for the data value rather
than scanning for SOH. This is also the core of the Len/Data desync attack family (AV-TYPE-1/2/3,
AV-TYPE-11): a declared length that disagrees with the real field boundary.
"""

from __future__ import annotations

# FIX byte constants.
SOH = b"\x01"
SOH_BYTE = 0x01
EQUALS_BYTE = 0x3D  # '='

# Raw/length-prefixed DATA fields, as defined in FIX.5.0SP2 ep228 (vendored from simplefix).
RAW_DATA: tuple[tuple[int, int], ...] = (
    (90, 91),        # SecureData
    (93, 89),        # Signature
    (95, 96),        # RawData
    (212, 213),      # XmlData
    (348, 349),      # EncodedIssuer
    (350, 351),      # EncodedSecurityDesc
    (352, 353),      # EncodedListExecInst
    (354, 355),      # EncodedText
    (356, 357),      # EncodedSubject
    (358, 359),      # EncodedHeadline
    (360, 361),      # EncodedAllocText
    (362, 363),      # EncodedUnderlyingIssuer
    (364, 365),      # EncodedUnderlyingSecurityDesc
    (445, 446),      # EncodedListStatusText
    (618, 619),      # EncodedLegIssuer
    (621, 622),      # EncodedLegSecurityDesc
    (1277, 1278),    # DerivativeEncodedIssuer
    (1280, 1281),    # DerivativeEncodedSecurityDesc
    (1282, 1283),    # DerivativeSecurityXML
    (1397, 1398),    # EncodedMktSegmDesc
    (1401, 1402),    # EncryptedPassword
    (1403, 1404),    # EncryptedNewPassword
    (1468, 1469),    # EncodedSecurityListDesc
    (1525, 1527),    # EncodedDocumentationText
    (1578, 1579),    # EncodedEventText
    (1620, 1621),    # InstrumentScopeEncodedSecurityDesc
    (1664, 1665),    # EncodedRejectText
    (1678, 1697),    # EncodedOptionExpirationDesc
    (1733, 1734),    # EncodedFirmAllocText
    (2072, 2073),    # EncodedUnderlyingEventText
    (2074, 2075),    # EncodedLegEventText
    (2179, 2180),    # EncodedLegOptionExpirationDesc
    (2111, 2112),    # EncodedAttachment
    (2287, 2288),    # EncodedUnderlyingOptionExpirationDate
    (2351, 2352),    # EncodedComplianceText
    (2372, 2371),    # EncodedTradeContinuationText
    (2481, 2482),    # EncodedMDStatisticDesc
    (2494, 2493),    # EncodedLegDocumentationText
    (2522, 2521),    # EncodedWarningText
    (2637, 2638),    # EncodedMiscFeeSubTypeDesc
    (2651, 2652),    # EncodedCommissionDesc
    (2665, 2666),    # EncodedAllocCommissionDesc
    (40004, 40005),  # EncodedAdditionalTermBondDesc
    (40008, 40009),  # EncodedAdditionalTermBondIssuer
    (40978, 40979),  # EncodedLegStreamText
    (40980, 40981),  # EncodedLegProvisionText
    (40982, 40983),  # EncodedStreamText
    (40984, 40985),  # EncodedPaymentText
    (40986, 40987),  # EncodedProvisionText
    (40988, 40989),  # EncodedUnderlyingStreamText
    (41083, 41084),  # EncodedDeliveryStreamCycleDesc
    (41101, 41101),  # EncodedMarketDisruptionFallbackUnderlierSecurityDesc
    (41107, 41108),  # EncodedExerciseDesc
    (41256, 41257),  # EncodedStreamCommodityDesc
    (41320, 41321),  # EncodedLegAdditionalTermBondDesc
    (41324, 41325),  # EncodedLegAdditionalTermBondIssuer
    (41458, 41459),  # EncodedLegDeliveryStreamCycleDesc
    (41476, 41477),  # EncodedLegMarketDisruptionFallbackUnderlierSecurityDesc
    (41482, 41483),  # EncodedLegExerciseDesc
    (41653, 41654),  # EncodedLegStreamCommodityDesc
    (41710, 41711),  # EncodedUnderlyingAdditionalTermBondDesc
    (41806, 41807),  # EncodedUnderlyingDeliveryStreamCycleDesc
    (41811, 41812),  # EncodedUnderlyingExerciseDesc
    (41873, 41874),  # EncodedUnderlyingMarketDisruptionFallbackUnderlierSecDesc
    (41969, 41970),  # EncodedUnderlyingStreamCommodityDesc
    (42025, 42026),  # EncodedUnderlyingAdditionalTermBondIssuer
    (42171, 42172),  # EncodedUnderlyingProvisionText
)

# length_tag -> data_tag  and  data_tag -> length_tag
LEN_TO_DATA: dict[int, int] = {ln: dt for ln, dt in RAW_DATA}
DATA_TO_LEN: dict[int, int] = {dt: ln for ln, dt in RAW_DATA}

# Convenience sets.
RAW_LEN_TAGS = frozenset(LEN_TO_DATA)
RAW_DATA_TAGS = frozenset(DATA_TO_LEN)
