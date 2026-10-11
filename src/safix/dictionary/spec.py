"""In-memory model of a loaded FIX data dictionary."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional, Union


@dataclass(slots=True)
class DictField:
    number: int
    name: str
    type: str
    values: dict[str, str] = field(default_factory=dict)  # enum code -> description

    @property
    def has_enums(self) -> bool:
        return bool(self.values)


@dataclass(slots=True)
class FieldRef:
    name: str
    required: bool


@dataclass(slots=True)
class ComponentRef:
    name: str
    required: bool


@dataclass(slots=True)
class GroupDef:
    name: str                    # the NUMINGROUP count field (e.g. "NoPartyIDs")
    required: bool
    elements: list["Element"] = field(default_factory=list)


Element = Union[FieldRef, ComponentRef, GroupDef]


@dataclass(slots=True)
class DictMessage:
    name: str
    msgtype: str
    msgcat: str
    elements: list[Element] = field(default_factory=list)


@dataclass(slots=True)
class DictComponent:
    name: str
    elements: list[Element] = field(default_factory=list)


@dataclass(slots=True)
class FixSpec:
    begin_string: str
    type: str
    major: int
    minor: int
    servicepack: int
    fields_by_number: dict[int, DictField] = field(default_factory=dict)
    fields_by_name: dict[str, DictField] = field(default_factory=dict)
    messages_by_msgtype: dict[str, DictMessage] = field(default_factory=dict)
    messages_by_name: dict[str, DictMessage] = field(default_factory=dict)
    components: dict[str, DictComponent] = field(default_factory=dict)
    header: list[Element] = field(default_factory=list)
    trailer: list[Element] = field(default_factory=list)
    # derived indexes
    group_count_tags: set[int] = field(default_factory=set)
    group_delimiters: dict[int, int] = field(default_factory=dict)  # count_tag -> delimiter_tag
    group_member_tags: set[int] = field(default_factory=set)        # tags that may repeat (any msg)
    len_to_data: dict[int, int] = field(default_factory=dict)
    data_to_len: dict[int, int] = field(default_factory=dict)
    source_files: list[str] = field(default_factory=list)
    _member_cache: dict[str, set[int]] = field(default_factory=dict, repr=False)

    # --- lookups ----------------------------------------------------------------------------
    def field_number(self, name: str) -> Optional[int]:
        f = self.fields_by_name.get(name)
        return None if f is None else f.number

    def field_type(self, number: int) -> Optional[str]:
        f = self.fields_by_number.get(number)
        return None if f is None else f.type

    def field_name(self, number: int) -> Optional[str]:
        f = self.fields_by_number.get(number)
        return None if f is None else f.name

    def is_known_tag(self, number: int) -> bool:
        return number in self.fields_by_number

    def enum_values(self, number: int) -> dict[str, str]:
        f = self.fields_by_number.get(number)
        return {} if f is None else f.values

    def message(self, msgtype: str) -> Optional[DictMessage]:
        return self.messages_by_msgtype.get(msgtype)

    # --- element resolution (splice components) ---------------------------------------------
    def expand(self, elements: list[Element], _seen: Optional[set[str]] = None) -> Iterator[Element]:
        """Yield elements with ComponentRefs spliced in (recursively). Groups are yielded as-is
        (their children are themselves expandable via ``expand``)."""
        _seen = _seen or set()
        for el in elements:
            if isinstance(el, ComponentRef):
                comp = self.components.get(el.name)
                if comp is None or el.name in _seen:
                    continue
                yield from self.expand(comp.elements, _seen | {el.name})
            else:
                yield el

    def allowed_tags(self, msgtype: str) -> set[int]:
        """All field tags allowed anywhere in a message of ``msgtype`` (header+body+trailer)."""
        msg = self.messages_by_msgtype.get(msgtype)
        tags: set[int] = set()
        self._collect_tags(self.header, tags)
        self._collect_tags(self.trailer, tags)
        if msg is not None:
            self._collect_tags(msg.elements, tags)
        return tags

    def _collect_tags(self, elements: list[Element], out: set[int],
                      _seen: Optional[set[str]] = None) -> None:
        _seen = _seen or set()
        for el in elements:
            if isinstance(el, FieldRef):
                n = self.field_number(el.name)
                if n is not None:
                    out.add(n)
            elif isinstance(el, ComponentRef):
                comp = self.components.get(el.name)
                if comp is not None and el.name not in _seen:
                    self._collect_tags(comp.elements, out, _seen | {el.name})
            elif isinstance(el, GroupDef):
                cnt = self.field_number(el.name)
                if cnt is not None:
                    out.add(cnt)
                self._collect_tags(el.elements, out, _seen)

    def required_top_level_tags(self, msgtype: str) -> set[int]:
        """Required field tags that must appear at top level (required field whose enclosing
        components are all required; fields inside groups are excluded — their requiredness is
        conditional on the group being present)."""
        out: set[int] = set()
        self._collect_required(self.header, out, set())
        msg = self.messages_by_msgtype.get(msgtype)
        if msg is not None:
            self._collect_required(msg.elements, out, set())
        self._collect_required(self.trailer, out, set())
        return out

    def _collect_required(self, elements: list[Element], out: set[int],
                          _seen: set[str]) -> None:
        for el in elements:
            if isinstance(el, FieldRef):
                if el.required:
                    n = self.field_number(el.name)
                    if n is not None:
                        out.add(n)
            elif isinstance(el, ComponentRef):
                if el.required:
                    comp = self.components.get(el.name)
                    if comp is not None and el.name not in _seen:
                        self._collect_required(comp.elements, out, _seen | {el.name})
            # GroupDef contents are conditionally required (skip for top-level requireds)

    def group_member_tags_for(self, msgtype: Optional[str]) -> set[int]:
        """Tags that appear inside a repeating group for this message type (header+trailer+msg).

        Unlike the global ``group_member_tags``, this is scoped so a field that is scalar in one
        message but a group member in another is only treated as repeatable where it actually is.
        """
        cache_key = msgtype or ""
        cached = self._member_cache.get(cache_key)
        if cached is not None:
            return cached
        members: set[int] = set()

        def walk(elements: list[Element], seen_comp: set[str], depth: int = 0) -> None:
            if depth > 40:
                return
            for el in elements:
                if isinstance(el, GroupDef):
                    self._collect_tags(el.elements, members)
                    walk(el.elements, seen_comp, depth + 1)
                elif isinstance(el, ComponentRef):
                    comp = self.components.get(el.name)
                    if comp is not None and el.name not in seen_comp:
                        walk(comp.elements, seen_comp | {el.name}, depth + 1)

        walk(self.header, set())
        walk(self.trailer, set())
        msg = self.messages_by_msgtype.get(msgtype) if msgtype else None
        if msg is not None:
            walk(msg.elements, set())
        self._member_cache[cache_key] = members
        return members

    def describe(self) -> dict:
        return {
            "begin_string": self.begin_string,
            "type": self.type,
            "version": f"{self.major}.{self.minor}" + (f"SP{self.servicepack}" if self.servicepack else ""),
            "fields": len(self.fields_by_number),
            "messages": len(self.messages_by_msgtype),
            "components": len(self.components),
            "group_count_tags": len(self.group_count_tags),
            "data_pairs": len(self.len_to_data),
            "source_files": self.source_files,
        }
