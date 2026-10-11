"""Load QuickFIX XML data dictionaries into a :class:`FixSpec`.

Handles the FIX 4.x single-file form and the FIX 5.x / FIXT split (a FIXT transport dictionary
for the header/trailer + admin messages merged with an application dictionary). Bundled
dictionaries ship in ``safix/data/dictionaries``.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from ..parsing.rawdata import LEN_TO_DATA
from .spec import (
    ComponentRef,
    DictComponent,
    DictField,
    DictMessage,
    Element,
    FieldRef,
    FixSpec,
    GroupDef,
)

_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "dictionaries"

# BeginString / version token -> bundled filename stem
_VERSION_FILE = {
    "FIX.4.0": "FIX40", "FIX.4.1": "FIX41", "FIX.4.2": "FIX42", "FIX.4.3": "FIX43",
    "FIX.4.4": "FIX44", "FIX.5.0": "FIX50", "FIX.5.0SP1": "FIX50SP1", "FIX.5.0SP2": "FIX50SP2",
    "FIXT.1.1": "FIXT11",
}
# ApplVerID(1128) enum -> app dictionary stem (for FIXT sessions)
_APPLVER_FILE = {"7": "FIX50", "8": "FIX50SP1", "9": "FIX50SP2"}

_DEFAULT_APP = "FIX50SP2"


def bundled_path(stem: str) -> Path:
    p = _DATA_DIR / f"{stem}.xml"
    if not p.exists():
        raise FileNotFoundError(f"bundled dictionary not found: {p}")
    return p


def _parse_elements(parent: ET.Element) -> list[Element]:
    out: list[Element] = []
    for child in parent:
        req = child.get("required", "N") == "Y"
        if child.tag == "field":
            out.append(FieldRef(name=child.get("name", ""), required=req))
        elif child.tag == "component":
            out.append(ComponentRef(name=child.get("name", ""), required=req))
        elif child.tag == "group":
            out.append(GroupDef(name=child.get("name", ""), required=req,
                                 elements=_parse_elements(child)))
    return out


def load_file(path: str | Path) -> FixSpec:
    """Load a single QuickFIX dictionary XML file into a :class:`FixSpec`.

    The XML is checked for a DOCTYPE / ENTITY declaration before parsing and refused if present:
    ``xml.etree`` expands internal entities, so an untrusted dictionary could otherwise trigger
    entity-expansion (billion-laughs) DoS. Legitimate QuickFIX dictionaries contain neither.
    """
    path = Path(path)
    raw = path.read_bytes()
    lowered = raw.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise ValueError(
            f"refusing to load dictionary {path}: contains a DOCTYPE/ENTITY declaration "
            "(entity-expansion / XXE guard)")
    root = ET.fromstring(raw)
    dtype = root.get("type", "FIX")
    major = int(root.get("major", "0"))
    minor = int(root.get("minor", "0"))
    sp = int(root.get("servicepack", "0") or "0")
    begin = f"{dtype}.{major}.{minor}"

    spec = FixSpec(begin_string=begin, type=dtype, major=major, minor=minor, servicepack=sp)
    spec.source_files.append(str(path))

    # <fields> — master table with enums
    fields_el = root.find("fields")
    if fields_el is not None:
        for fe in fields_el.findall("field"):
            try:
                number = int(fe.get("number", ""))
            except ValueError:
                continue
            name = fe.get("name", "")
            ftype = fe.get("type", "STRING")
            values = {ve.get("enum", ""): ve.get("description", "")
                      for ve in fe.findall("value")}
            df = DictField(number=number, name=name, type=ftype, values=values)
            spec.fields_by_number[number] = df
            if name:
                spec.fields_by_name[name] = df

    # <header> / <trailer>
    h = root.find("header")
    if h is not None:
        spec.header = _parse_elements(h)
    t = root.find("trailer")
    if t is not None:
        spec.trailer = _parse_elements(t)

    # <components>
    comps = root.find("components")
    if comps is not None:
        for ce in comps.findall("component"):
            name = ce.get("name", "")
            spec.components[name] = DictComponent(name=name, elements=_parse_elements(ce))

    # <messages>
    msgs = root.find("messages")
    if msgs is not None:
        for me in msgs.findall("message"):
            m = DictMessage(name=me.get("name", ""), msgtype=me.get("msgtype", ""),
                            msgcat=me.get("msgcat", ""), elements=_parse_elements(me))
            spec.messages_by_msgtype[m.msgtype] = m
            if m.name:
                spec.messages_by_name[m.name] = m

    _derive_indexes(spec)
    return spec


def _derive_indexes(spec: FixSpec) -> None:
    # group count tags = NUMINGROUP fields
    for num, fld in spec.fields_by_number.items():
        if fld.type.upper() == "NUMINGROUP":
            spec.group_count_tags.add(num)
    # len/data pairs = vendored table restricted to tags present in this dictionary
    for len_tag, data_tag in LEN_TO_DATA.items():
        if len_tag in spec.fields_by_number or data_tag in spec.fields_by_number:
            spec.len_to_data[len_tag] = data_tag
            spec.data_to_len[data_tag] = len_tag
    _derive_groups(spec)


def _derive_groups(spec: FixSpec) -> None:
    """Populate group_delimiters (count_tag -> first-field tag) and group_member_tags."""
    seen_comps: set[str] = set()

    def first_field_tag(elements: list[Element]) -> int | None:
        for el in spec.expand(elements):
            if isinstance(el, FieldRef):
                return spec.field_number(el.name)
            if isinstance(el, GroupDef):
                return spec.field_number(el.name)
        return None

    def walk(elements: list[Element], _depth: int = 0) -> None:
        if _depth > 40:
            return
        for el in elements:
            if isinstance(el, GroupDef):
                count_tag = spec.field_number(el.name)
                delim = first_field_tag(el.elements)
                if count_tag is not None and delim is not None:
                    spec.group_delimiters[count_tag] = delim
                members: set[int] = set()
                spec._collect_tags(el.elements, members)
                spec.group_member_tags |= members
                walk(el.elements, _depth + 1)
            elif isinstance(el, ComponentRef):
                comp = spec.components.get(el.name)
                if comp is not None and el.name not in seen_comps:
                    seen_comps.add(el.name)
                    walk(comp.elements, _depth + 1)
                    seen_comps.discard(el.name)

    walk(spec.header)
    walk(spec.trailer)
    for msg in spec.messages_by_msgtype.values():
        walk(msg.elements)


def _merge_app_into_transport(transport: FixSpec, app: FixSpec) -> FixSpec:
    """Merge an application dictionary into a FIXT transport dictionary.

    Header/trailer and admin messages come from the transport (FIXT); application messages and
    their fields/components are added from the app dictionary.
    """
    merged = FixSpec(
        begin_string=transport.begin_string, type=transport.type,
        major=app.major, minor=app.minor, servicepack=app.servicepack,
    )
    merged.source_files = transport.source_files + app.source_files
    # fields: transport first, app overrides/adds
    merged.fields_by_number = {**transport.fields_by_number, **app.fields_by_number}
    merged.fields_by_name = {**transport.fields_by_name, **app.fields_by_name}
    merged.components = {**transport.components, **app.components}
    # messages: FIXT admin + app
    merged.messages_by_msgtype = {**transport.messages_by_msgtype, **app.messages_by_msgtype}
    merged.messages_by_name = {**transport.messages_by_name, **app.messages_by_name}
    # header/trailer from transport (FIXT owns the session layer)
    merged.header = transport.header
    merged.trailer = transport.trailer
    _derive_indexes(merged)
    return merged


def load(version_or_path: str, *, app_version: Optional[str] = None) -> FixSpec:
    """Load a dictionary by bundled version string (``FIX.4.4``, ``FIXT.1.1``) or file path.

    For ``FIXT.1.1`` the application dictionary defaults to FIX50SP2 (override with
    ``app_version``, e.g. ``FIX.5.0SP1`` or an ApplVerID enum like ``8``).
    """
    # explicit path?
    p = Path(version_or_path)
    if p.exists() and p.suffix.lower() == ".xml":
        return load_file(p)

    if version_or_path == "FIXT.1.1":
        transport = load_file(bundled_path("FIXT11"))
        app_stem = _DEFAULT_APP
        if app_version:
            app_stem = _VERSION_FILE.get(app_version) or _APPLVER_FILE.get(app_version, _DEFAULT_APP)
        app = load_file(bundled_path(app_stem))
        return _merge_app_into_transport(transport, app)

    stem = _VERSION_FILE.get(version_or_path)
    if stem is None:
        raise ValueError(f"unknown dictionary version: {version_or_path!r}")
    return load_file(bundled_path(stem))


def load_for_begin_string(begin_string: str, *, app_version: Optional[str] = None) -> FixSpec:
    """Choose and load the right dictionary for a message's BeginString(8)."""
    return load(begin_string, app_version=app_version)


def available_versions() -> list[str]:
    return sorted(_VERSION_FILE)
