"""Session identity and per-session state carried across a scan."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .message import FixMessage


@dataclass(frozen=True, slots=True)
class SessionKey:
    """Identifies one directional message stream (as literally addressed in the messages)."""

    begin_string: str
    sender: str
    target: str

    def __str__(self) -> str:
        return f"{self.begin_string}:{self.sender}->{self.target}"

    @classmethod
    def from_message(cls, msg: FixMessage) -> "SessionKey":
        return cls(
            begin_string=msg.begin_string or "?",
            sender=msg.sender_comp_id or "?",
            target=msg.target_comp_id or "?",
        )

    @property
    def counterparties(self) -> frozenset[str]:
        return frozenset((self.sender, self.target))


@dataclass(slots=True)
class SessionState:
    """Mutable per-session state accumulated while scanning (for stateful detectors)."""

    key: SessionKey
    message_count: int = 0
    # sequence tracking
    expected_seq: Optional[int] = None       # next expected MsgSeqNum
    last_seq: Optional[int] = None
    seen_seqnums: set[int] = field(default_factory=set)
    queued_high_seqnums: dict[int, int] = field(default_factory=dict)  # seq -> msg_offset
    # lifecycle
    logged_on: bool = False
    logon_count: int = 0
    logout_count: int = 0
    # negotiated params (from Logon)
    heartbeat_int: Optional[int] = None
    reset_seq_requests: int = 0
    # replay / dup tracking
    seen_body_hashes: set[str] = field(default_factory=set)
    outstanding_testreqids: set[str] = field(default_factory=set)
    outstanding_resend: list[tuple[int, int]] = field(default_factory=list)
    # rate windows: name -> list of timestamps/offsets (filled by detectors)
    rate_windows: dict[str, list] = field(default_factory=dict)
    # free-form scratch space for individual detectors
    scratch: dict = field(default_factory=dict)
