"""Detector package. Importing it registers all built-in detectors."""

from __future__ import annotations

from . import app_order  # noqa: F401
from . import datatype  # noqa: F401
from . import encoding  # noqa: F401
from . import parser_anomaly  # noqa: F401
from . import session_seq  # noqa: F401
from . import structure  # noqa: F401
from . import yaml_rules  # noqa: F401

__all__ = ["parser_anomaly", "datatype", "structure", "session_seq", "encoding", "app_order",
           "yaml_rules"]
