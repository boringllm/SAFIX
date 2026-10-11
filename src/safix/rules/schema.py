"""Declarative YAML rule schema (Sigma-inspired, FIX-specialized).

A YAML rule expresses a stateless, single-message check as a set of field conditions combined
with ``match: all|any``. Rules are evaluated by :mod:`safix.detectors.yaml_rules`, letting users
add custom detections without writing Python. Example:

    id: SAFIX-CUSTOM-0001
    title: Market order with FOK time-in-force
    category: APP
    severity: medium
    confidence: medium
    vector_ids: [AV-APP-04]
    msg_types: ["D", "G"]
    direction: any
    match: all
    when:
      - {tag: 40, equals: "1"}      # OrdType = Market
      - {tag: 59, equals: "4"}      # TimeInForce = FOK
    benign: ["Some venues permit market FOK."]
    remediation: "Review market FOK orders."
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from ..model.finding import Confidence, Severity


class RuleCondition(BaseModel):
    tag: int
    equals: Optional[str] = None
    not_equals: Optional[str] = None
    contains: Optional[str] = None
    regex: Optional[str] = None
    in_: Optional[list[str]] = Field(default=None, alias="in")
    gt: Optional[float] = None
    lt: Optional[float] = None
    exists: Optional[bool] = None
    datatype_violation: Optional[bool] = None
    enum_violation: Optional[bool] = None

    model_config = {"populate_by_name": True}


class Rule(BaseModel):
    id: str
    title: str
    message: Optional[str] = None
    category: str = "CUSTOM"
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    status: str = "stable"
    vector_ids: list[str] = Field(default_factory=list)
    msg_types: list[str] = Field(default_factory=list)   # empty = all
    direction: str = "any"                                # received | sent | any
    match: str = "all"                                    # all | any
    when: list[RuleCondition] = Field(default_factory=list)
    benign: list[str] = Field(default_factory=list)
    remediation: Optional[str] = None
    references: list[str] = Field(default_factory=list)
    regulatory_refs: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class RulePack(BaseModel):
    rules: list[Rule] = Field(default_factory=list)
