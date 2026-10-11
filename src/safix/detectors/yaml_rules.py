"""Evaluate declarative YAML rules (built-in + user packs) against each message."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional

from ..dictionary import datatypes as dt
from ..model.finding import Finding
from ..rules import loader as rule_loader
from ..rules.schema import Rule, RuleCondition
from .base import Detector, register

if TYPE_CHECKING:  # pragma: no cover
    from ..dictionary.spec import FixSpec
    from ..engine.context import ScanContext
    from ..model.message import FixMessage


def _num(v: str) -> Optional[float]:
    try:
        return float(v)
    except ValueError:
        return None


def _eval_condition(cond: RuleCondition, msg: "FixMessage", spec: Optional["FixSpec"]) -> bool:
    fields = msg.get_fields(cond.tag)
    present = bool(fields)
    if cond.exists is not None:
        return present == cond.exists
    if not present:
        return False
    values = [f.value_str for f in fields]
    if cond.equals is not None:
        return any(v == cond.equals for v in values)
    if cond.not_equals is not None:
        return all(v != cond.not_equals for v in values)
    if cond.contains is not None:
        return any(cond.contains in v for v in values)
    if cond.regex is not None:
        return any(re.search(cond.regex, v) for v in values)
    if cond.in_ is not None:
        return any(v in cond.in_ for v in values)
    if cond.gt is not None:
        return any((_num(v) is not None and _num(v) > cond.gt) for v in values)
    if cond.lt is not None:
        return any((_num(v) is not None and _num(v) < cond.lt) for v in values)
    if cond.datatype_violation:
        if spec is None:
            return False
        t = spec.field_type(cond.tag) or ""
        return any(dt.validate(t, f.value).lexical_ok is False for f in fields)
    if cond.enum_violation:
        if spec is None:
            return False
        allowed = spec.enum_values(cond.tag)
        return bool(allowed) and any(v not in allowed for v in values)
    return True  # bare tag → treated as "exists"


def _matches(rule: Rule, msg: "FixMessage", spec: Optional["FixSpec"]) -> bool:
    if rule.msg_types and (msg.msg_type not in rule.msg_types):
        return False
    if rule.direction in ("received", "sent"):
        want = "in" if rule.direction == "received" else "out"
        if msg.direction != want:
            return False
    if not rule.when:
        return False
    results = (_eval_condition(c, msg, spec) for c in rule.when)
    return all(results) if rule.match == "all" else any(results)


@register
class YamlRuleDetector(Detector):
    id = "yaml-rules"
    category = "CUSTOM"
    title = "Declarative YAML rule packs (built-in + user)"

    def __init__(self) -> None:
        self._builtin: list[Rule] = rule_loader.load_builtin()
        self._user_cache: dict[str, list[Rule]] = {}

    def _rules_for(self, ctx: "ScanContext") -> list[Rule]:
        rules = list(self._builtin)
        path = getattr(ctx.config, "rules_path", None)
        if path:
            if path not in self._user_cache:
                try:
                    self._user_cache[path] = rule_loader.load_dir(path)
                except Exception:  # pragma: no cover - user rule error
                    self._user_cache[path] = []
            rules.extend(self._user_cache[path])
        return rules

    def analyze(self, msg: "FixMessage", ctx: "ScanContext") -> None:
        rules = self._rules_for(ctx)
        if not rules:
            return
        spec = ctx.spec_for(msg)
        for rule in rules:
            if not ctx.config.rule_enabled(rule.id, rule.category):
                continue
            if _matches(rule, msg, spec):
                ctx.add(
                    Finding(
                        rule_id=rule.id, title=rule.title,
                        message=rule.message or rule.title,
                        severity=rule.severity, confidence=rule.confidence,
                        category=rule.category, vector_ids=list(rule.vector_ids),
                        benign_notes=list(rule.benign), remediation=rule.remediation,
                        regulatory_refs=list(rule.regulatory_refs), tags=list(rule.tags),
                        dedup_key=f"{rule.id}:{msg.get_str(11)}",
                    ),
                    msg,
                )
