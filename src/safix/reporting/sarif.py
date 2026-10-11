"""SARIF 2.1.0 report of a scan result.

Maps SAFIX findings to the OASIS SARIF schema: each distinct rule becomes a
``tool.driver.rules`` entry and each finding a ``results`` entry with an explicit ``level``,
a ``security-severity`` property, a physical location + region, and ``partialFingerprints``
for dedup. Suppressed findings use the SARIF ``suppressions`` array.
"""

from __future__ import annotations

import json

from ..engine.runner import ScanResult
from ..model.finding import Finding

SARIF_VERSION = "2.1.0"
SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def _rule_descriptor(f: Finding) -> dict:
    return {
        "id": f.rule_id,
        "name": f.rule_id.replace("-", ""),
        "shortDescription": {"text": f.title},
        "fullDescription": {"text": f.remediation or f.title},
        "defaultConfiguration": {"level": f.severity.sarif_level},
        "properties": {
            "category": f.category,
            "vector_ids": f.vector_ids,
            "regulatory_refs": f.regulatory_refs,
            "confidence": f.confidence.value,
            "security-severity": str(f.severity.score),
            "tags": ["security", "fix-protocol", f.category.lower()] + f.tags,
        },
    }


def _result(f: Finding) -> dict:
    region: dict = {}
    if f.byte_offset is not None:
        region["byteOffset"] = f.byte_offset
    if f.source_line is not None:
        region["startLine"] = f.source_line
    location = {
        "physicalLocation": {
            "artifactLocation": {"uri": f.source or "input"},
            **({"region": region} if region else {}),
        },
        "logicalLocations": [{"fullyQualifiedName": f.session or "", "kind": "session"}],
    }
    result = {
        "ruleId": f.rule_id,
        "level": f.severity.sarif_level,
        "message": {"text": f"{f.title}: {f.message}"},
        "locations": [location],
        "partialFingerprints": {"safix/v1": f.fingerprint},
        "properties": {
            "priority": f.priority,
            "confidence": f.confidence.value,
            "severity": f.severity.value,
            "vector_ids": f.vector_ids,
            "regulatory_refs": f.regulatory_refs,
            "msg_type": f.msg_type,
            "msg_seq": f.msg_seq,
            "direction": f.direction,
            "evidence": f.evidence,
            "benign_notes": f.benign_notes,
            "occurrence_count": f.occurrence_count,
        },
    }
    if f.suppressed:
        result["suppressions"] = [{"kind": "external", "justification": f.suppressed_by or ""}]
    return result


def build(result: ScanResult) -> dict:
    findings = result.findings
    rules = {f.rule_id: _rule_descriptor(f) for f in findings}
    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SAFIX",
                        "informationUri": "https://example.invalid/safix",
                        "rules": list(rules.values()),
                    }
                },
                "results": [_result(f) for f in findings],
                "properties": {
                    "message_count": result.message_count,
                    "session_count": result.session_count,
                    "detected_format": result.detected_format,
                },
            }
        ],
    }


def render(result: ScanResult) -> str:
    return json.dumps(build(result), indent=2, ensure_ascii=False)
