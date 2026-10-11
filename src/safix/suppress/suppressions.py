"""Suppression/allowlist matching, dedup, and severity filtering of findings."""

from __future__ import annotations

from ..config import Config, Suppression
from ..model.finding import Finding, Severity, severity_at_least


def _matches(sup: Suppression, f: Finding) -> bool:
    """A suppression matches a finding when every field it specifies matches the finding."""
    if sup.rule_id is not None and sup.rule_id != f.rule_id:
        return False
    if sup.category is not None and sup.category != f.category:
        return False
    if sup.session is not None and sup.session != (f.session or ""):
        return False
    if sup.comp_id is not None:
        sess = f.session or ""
        if sup.comp_id not in sess:
            return False
    if sup.tag is not None and sup.tag != f.tag:
        return False
    if sup.value is not None and sup.value != (f.evidence or ""):
        return False
    if sup.fingerprint is not None and sup.fingerprint != f.fingerprint:
        return False
    # an empty suppression (no fields) never matches — avoid muting everything
    specified = any(v is not None for v in (
        sup.rule_id, sup.category, sup.session, sup.comp_id, sup.tag, sup.value, sup.fingerprint))
    return specified


def apply_suppressions(findings: list[Finding], config: Config) -> list[Finding]:
    """Mark findings suppressed (retained, not deleted) when an allowlist entry matches."""
    for f in findings:
        for sup in config.suppressions:
            if _matches(sup, f):
                f.suppressed = True
                f.suppressed_by = sup.reason or "allowlist"
                break
    return findings


def dedup(findings: list[Finding]) -> list[Finding]:
    """Collapse findings with identical fingerprints, counting occurrences."""
    out: dict[str, Finding] = {}
    for f in findings:
        fp = f.fingerprint
        if fp in out:
            out[fp].occurrence_count += 1
        else:
            out[fp] = f
    return list(out.values())


def postprocess(findings: list[Finding], config: Config) -> list[Finding]:
    """Suppress, optionally dedup, filter by severity_min, and sort by priority."""
    apply_suppressions(findings, config)
    result = dedup(findings) if config.dedup else findings
    minimum = Severity(config.severity_min)
    result = [f for f in result if severity_at_least(f.severity, minimum)]
    result.sort(key=lambda f: (f.priority, f.severity.rank), reverse=True)
    return result
