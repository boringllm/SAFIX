"""SAFIX scan configuration (loadable from YAML)."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

from .model.finding import Severity


class Thresholds(BaseModel):
    """Tunable detection thresholds. Defaults are starting points; tune per venue."""

    # fat-finger / order sanity (APP D01/D02)
    max_order_qty: float = 100_000
    max_order_notional: float = 5_000_000
    require_positive_price: bool = True
    require_positive_qty: bool = True
    price_band_pct: float = 20.0          # +/- % from a learned/reference price
    absurd_price_multiple: float = 10.0   # >10x or <0.1x reference = absurd
    round_lot: float = 1                  # set to e.g. 100 to flag sub-round-lot qtys (off by default)

    # replace escalation / baseline (APP D12/D02)
    replace_qty_ratio: float = 10.0
    baseline_min_samples: int = 5
    # order rate / notional throttle (APP D20)
    order_rate_window_sec: int = 1
    order_rate_count: int = 100
    # wash / self-trade window (APP D19)
    wash_window_sec: int = 5

    # time sanity (APP D18)
    stale_transacttime_seconds: int = 3600
    future_transacttime_seconds: int = 60

    # session rate limits (SESS)
    logon_flood_window_sec: int = 60
    logon_flood_count: int = 5
    resend_flood_window_sec: int = 60
    resend_flood_count: int = 10
    testrequest_flood_window_sec: int = 60
    testrequest_flood_count: int = 20
    message_rate_window_sec: int = 1
    message_rate_count: int = 1000

    # encoding / size (ENC)
    xml_entity_ref_threshold: int = 100
    xml_nesting_depth_threshold: int = 50
    max_message_size: int = 65536

    # datatype advisories (TYPE)
    decimal_significant_digits: int = 15
    queued_high_seqnum_limit: int = 1000  # unbounded-queue DoS proxy (SESS-SEQ-02)


class Suppression(BaseModel):
    """An allowlist entry. A finding is suppressed if every present field matches it."""

    rule_id: Optional[str] = None
    category: Optional[str] = None
    session: Optional[str] = None
    comp_id: Optional[str] = None
    tag: Optional[int] = None
    value: Optional[str] = None
    fingerprint: Optional[str] = None
    reason: Optional[str] = None


class Config(BaseModel):
    """Top-level scan configuration."""

    # dictionary / parsing
    fix_version: Optional[str] = None       # force a dictionary version, e.g. "FIX.4.4"
    app_version: Optional[str] = None       # FIXT app dictionary, e.g. "FIX.5.0SP2"
    dictionary_path: Optional[str] = None   # explicit dictionary XML
    field_delimiter: Optional[str] = None   # override delimiter (single char, e.g. "|")
    line_oriented: Optional[bool] = None
    baseline_path: Optional[str] = None     # learned per-instrument price baseline (JSON)
    rules_path: Optional[str] = None        # directory of user YAML rule packs

    # direction resolution
    our_comp_ids: list[str] = Field(default_factory=list)

    # rule selection
    disabled_rules: list[str] = Field(default_factory=list)
    enabled_rules: Optional[list[str]] = None   # if set, ONLY these run
    enabled_categories: Optional[list[str]] = None

    # triage
    severity_min: Severity = Severity.INFO
    dedup: bool = True
    # comp-ids that legitimately share order ownership (give-up / drop-copy) — suppress BOLA FPs
    session_ownership_groups: list[list[str]] = Field(default_factory=list)

    thresholds: Thresholds = Field(default_factory=Thresholds)
    suppressions: list[Suppression] = Field(default_factory=list)

    def delimiter_bytes(self) -> Optional[bytes]:
        if self.field_delimiter is None:
            return None
        if self.field_delimiter.lower() in ("soh", "\\x01", "01"):
            return b"\x01"
        return self.field_delimiter.encode("latin-1")[:1]

    def rule_enabled(self, rule_id: str, category: str) -> bool:
        if self.enabled_rules is not None and rule_id not in self.enabled_rules:
            return False
        if self.enabled_categories is not None and category not in self.enabled_categories:
            return False
        if rule_id in self.disabled_rules:
            return False
        return True

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.model_validate(data)

    @classmethod
    def default(cls) -> "Config":
        return cls()
