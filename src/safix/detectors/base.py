"""Detector base class and the detector registry.

Detectors are stateless singletons; all mutable per-scan state lives in the
:class:`~safix.engine.context.ScanContext`. A detector either inspects a single message
(``analyze``) or produces findings at end-of-scan from accumulated state (``finalize``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from ..engine.context import ScanContext
    from ..model.message import FixMessage


class Detector:
    """Base detector. Subclasses set ``id``/``category`` and override ``analyze``/``finalize``."""

    id: str = "base"
    category: str = ""
    title: str = ""

    def analyze(self, msg: "FixMessage", ctx: "ScanContext") -> None:
        """Inspect one message; emit findings via ``ctx.add(...)``."""

    def finalize(self, ctx: "ScanContext") -> None:
        """Emit findings derived from accumulated state at the end of the scan."""


_REGISTRY: list[Detector] = []


def register(cls: type[Detector]) -> type[Detector]:
    """Class decorator: instantiate the detector once and add it to the registry."""
    _REGISTRY.append(cls())
    return cls


def all_detectors() -> list[Detector]:
    return list(_REGISTRY)


def clear_registry() -> None:  # pragma: no cover - test helper
    _REGISTRY.clear()
