"""Scan context: the mutable state shared across detectors during one scan."""

from __future__ import annotations

from collections import Counter
from typing import Optional

from ..config import Config
from ..dictionary import loader
from ..dictionary.spec import FixSpec
from ..model.finding import Finding
from ..model.message import FixMessage
from ..model.session import SessionKey, SessionState


class ScanContext:
    """Holds configuration, the loaded dictionary(ies), per-session state, and findings."""

    def __init__(self, config: Config):
        self.config = config
        self.findings: list[Finding] = []
        self.sessions: dict[SessionKey, SessionState] = {}
        self.orderbook: dict = {}            # ClOrdID -> order record (APP)
        self.instrument_baseline: dict = {}  # symbol -> price/qty stats (APP)
        self.windows: dict = {}              # ad-hoc cross-message windows (APP wash, etc.)
        self.stats: Counter = Counter()
        self._spec_cache: dict[str, FixSpec] = {}
        self._forced_spec: Optional[FixSpec] = None
        self._spec_load_failed: set[str] = set()
        self._current_msg: Optional[FixMessage] = None
        self._load_forced_spec()
        self._load_baseline()

    # --- dictionary resolution --------------------------------------------------------------
    def _load_forced_spec(self) -> None:
        cfg = self.config
        try:
            if cfg.dictionary_path:
                self._forced_spec = loader.load_file(cfg.dictionary_path)
            elif cfg.fix_version:
                self._forced_spec = loader.load(cfg.fix_version, app_version=cfg.app_version)
        except (OSError, ValueError) as exc:  # pragma: no cover - config error path
            self.stats["dict_load_errors"] += 1
            self._forced_spec = None
            self.stats[f"dict_error:{exc}"] += 1

    def _load_baseline(self) -> None:
        if not self.config.baseline_path:
            return
        try:
            from . import baseline
            self.instrument_baseline.update(
                baseline.to_context_baseline(baseline.load(self.config.baseline_path)))
        except (OSError, ValueError):  # pragma: no cover - config error path
            self.stats["baseline_load_errors"] += 1

    def spec_for(self, msg: FixMessage) -> Optional[FixSpec]:
        if self._forced_spec is not None:
            return self._forced_spec
        bs = msg.begin_string
        if not bs:
            return None
        if bs in self._spec_cache:
            return self._spec_cache[bs]
        if bs in self._spec_load_failed:
            return None
        try:
            spec = loader.load_for_begin_string(bs, app_version=self.config.app_version)
        except (OSError, ValueError):
            self._spec_load_failed.add(bs)
            self.stats["unknown_version"] += 1
            return None
        self._spec_cache[bs] = spec
        return spec

    # --- session state ----------------------------------------------------------------------
    def session_state(self, msg: FixMessage) -> SessionState:
        key = SessionKey.from_message(msg)
        st = self.sessions.get(key)
        if st is None:
            st = SessionState(key=key)
            self.sessions[key] = st
        return st

    # --- direction --------------------------------------------------------------------------
    def resolve_direction(self, msg: FixMessage) -> str:
        if msg.direction in ("in", "out"):
            return msg.direction
        ours = set(self.config.our_comp_ids)
        if ours:
            if msg.sender_comp_id in ours:
                msg.direction = "out"
            elif msg.target_comp_id in ours:
                msg.direction = "in"
        return msg.direction

    # --- emitting findings ------------------------------------------------------------------
    def add(self, finding: Finding, msg: Optional[FixMessage] = None) -> Finding:
        """Record a finding, filling provenance from ``msg`` where the detector left it blank."""
        m = msg or self._current_msg
        if m is not None:
            if finding.session is None:
                finding.session = str(SessionKey.from_message(m))
            if finding.msg_seq is None:
                finding.msg_seq = m.seq_num
            if finding.msg_type is None:
                finding.msg_type = m.msg_type
            if finding.direction == "unknown":
                finding.direction = m.direction
            if finding.timestamp is None:
                finding.timestamp = m.timestamp
            if finding.source is None:
                finding.source = m.source
            if finding.source_line is None:
                finding.source_line = m.source_line
            if not finding.msg_offset:
                finding.msg_offset = m.msg_offset
            if finding.evidence is None:
                finding.evidence = m.pretty()[:200]
        self.findings.append(finding)
        self.stats[f"finding:{finding.category}"] += 1
        return finding

    def set_current(self, msg: Optional[FixMessage]) -> None:
        self._current_msg = msg
