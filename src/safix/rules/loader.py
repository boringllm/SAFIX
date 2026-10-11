"""Load declarative YAML rule packs from files/directories."""

from __future__ import annotations

from pathlib import Path

import yaml

from .schema import Rule

BUILTIN_DIR = Path(__file__).resolve().parent / "builtin"


def _rules_from_doc(doc: object, source: str) -> list[Rule]:
    rules: list[Rule] = []
    if isinstance(doc, dict) and "rules" in doc:
        items = doc["rules"]
    elif isinstance(doc, list):
        items = doc
    elif isinstance(doc, dict):
        items = [doc]
    else:
        return rules
    for item in items:
        rules.append(Rule.model_validate(item))
    return rules


def load_text(text: str, source: str = "<text>") -> list[Rule]:
    """Parse rules from a YAML string (raises on invalid YAML/schema)."""
    rules: list[Rule] = []
    for doc in yaml.safe_load_all(text):
        if doc is not None:
            rules.extend(_rules_from_doc(doc, source))
    return rules


def load_file(path: str | Path) -> list[Rule]:
    path = Path(path)
    return load_text(path.read_text(encoding="utf-8"), str(path))


def load_dir(path: str | Path) -> list[Rule]:
    rules: list[Rule] = []
    p = Path(path)
    if not p.exists():
        return rules
    for f in sorted(p.rglob("*.y*ml")):
        if f.is_file():
            rules.extend(load_file(f))
    return rules


def load_builtin() -> list[Rule]:
    return load_dir(BUILTIN_DIR)
