"""FastAPI backend for the SAFIX web UI."""

from __future__ import annotations

import asyncio
import json
import queue as _queue
import threading
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .. import __version__
from ..config import Config
from ..dictionary import loader
from ..engine.runner import scan_bytes
from ..model.finding import Severity
from ..reporting import render_text
from ..rules import loader as rule_loader


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

_STATIC = Path(__file__).resolve().parent / "static"
_CATALOG = Path(__file__).resolve().parent.parent / "data" / "rule_catalog.json"


class ScanRequest(BaseModel):
    content: str = ""
    config: dict = {}
    report: Optional[str] = None  # if set: return that rendered report instead of JSON


class CustomRules(BaseModel):
    yaml: str = ""


class RuleStore:
    """Persists user-authored YAML rules to a directory the YAML detector can load."""

    def __init__(self, base_dir: Path):
        self.dir = base_dir / "safix-user-rules"
        self.file = self.dir / "rules.yml"

    def read_text(self) -> str:
        try:
            return self.file.read_text(encoding="utf-8")
        except OSError:
            return ""

    def has_rules(self) -> bool:
        return self.file.exists() and self.file.stat().st_size > 0

    def validate_and_write(self, text: str) -> tuple[bool, int, Optional[str]]:
        text = text or ""
        if not text.strip():
            # empty = clear custom rules
            if self.file.exists():
                self.file.unlink()
            return True, 0, None
        try:
            rules = rule_loader.load_text(text, "user")
        except Exception as exc:  # YAML or schema error
            return False, 0, f"{type(exc).__name__}: {exc}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.file.write_text(text, encoding="utf-8")
        return True, len(rules), None

    def parsed(self) -> list:
        try:
            return rule_loader.load_text(self.read_text(), "user") if self.has_rules() else []
        except Exception:
            return []


def _config_from(data: dict) -> Config:
    try:
        return Config.model_validate(data or {})
    except Exception:
        return Config.default()


def _load_catalog() -> list[dict]:
    try:
        return json.loads(_CATALOG.read_text(encoding="utf-8"))
    except OSError:
        return []


def create_app(workdir: Optional[Path] = None) -> FastAPI:
    app = FastAPI(title="SAFIX", version=__version__)
    store = RuleStore(workdir or Path.cwd())

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        idx = _STATIC / "index.html"
        return idx.read_text(encoding="utf-8") if idx.exists() else "<h1>SAFIX</h1>"

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__,
                "rules_file": str(store.file), "custom_rules": len(store.parsed())}

    @app.get("/api/dictionaries")
    def dictionaries() -> dict:
        return {"versions": loader.available_versions()}

    @app.get("/api/config/schema")
    def config_schema() -> dict:
        cfg = Config.default()
        return {"defaults": cfg.model_dump(mode="json"),
                "thresholds_schema": list(cfg.thresholds.model_dump().keys()),
                "severities": ["critical", "high", "medium", "low", "info"]}

    @app.get("/api/rules")
    def rules() -> dict:
        import safix.detectors  # noqa: F401
        from ..detectors.base import all_detectors
        return {"detectors": [{"id": d.id, "category": d.category, "title": d.title}
                              for d in all_detectors()]}

    @app.get("/api/rules/all")
    def rules_all() -> dict:
        import safix.detectors  # noqa: F401
        from ..detectors.base import all_detectors
        detectors = [{"id": d.id, "category": d.category, "title": d.title, "source": "detector"}
                     for d in all_detectors()]
        catalog = [{**r, "source": "built-in"} for r in _load_catalog()]
        custom = [{"id": r.id, "category": r.category, "severity": r.severity.value,
                   "title": r.title, "source": "custom"} for r in store.parsed()]
        return {"detectors": detectors, "catalog": catalog, "custom": custom}

    @app.get("/api/rules/custom")
    def get_custom() -> dict:
        return {"yaml": store.read_text()}

    @app.put("/api/rules/custom")
    def put_custom(body: CustomRules) -> dict:
        ok, count, error = store.validate_and_write(body.yaml)
        return {"ok": ok, "count": count, "error": error}

    @app.get("/api/rules/help")
    def rules_help() -> dict:
        return {
            "operators": [
                {"op": "equals", "desc": "value equals", "example": '{tag: 40, equals: "2"}'},
                {"op": "not_equals", "desc": "no occurrence equals", "example": '{tag: 54, not_equals: "1"}'},
                {"op": "contains", "desc": "substring present", "example": '{tag: 58, contains: "DROP"}'},
                {"op": "regex", "desc": "Python regex search", "example": '{tag: 11, regex: "^SEQ[0-9]+$"}'},
                {"op": "in", "desc": "value in a list", "example": '{tag: 40, in: ["3", "4"]}'},
                {"op": "gt / lt", "desc": "numeric compare", "example": '{tag: 38, gt: 100000}'},
                {"op": "exists", "desc": "field present / absent", "example": '{tag: 99, exists: false}'},
                {"op": "datatype_violation", "desc": "fails its FIX datatype grammar", "example": '{tag: 44, datatype_violation: true}'},
                {"op": "enum_violation", "desc": "value not in the dictionary code-set", "example": '{tag: 54, enum_violation: true}'},
            ],
            "example": (
                "rules:\n"
                "  - id: SAFIX-CUSTOM-0001\n"
                "    title: Market order with FOK time-in-force\n"
                "    category: APP            # SESS | TYPE | STRUCT | APP | ENC | CUSTOM\n"
                "    severity: medium         # critical | high | medium | low | info\n"
                "    confidence: medium       # high | medium | low\n"
                "    msg_types: [\"D\", \"G\"]   # restrict to these MsgType(35); omit = all\n"
                "    match: all               # all = AND, any = OR\n"
                "    when:\n"
                "      - {tag: 40, equals: \"1\"}   # OrdType = Market\n"
                "      - {tag: 59, equals: \"4\"}   # TimeInForce = FOK\n"
                "    benign: [\"Some venues permit market FOK.\"]\n"
                "    remediation: \"Review market FOK orders.\"\n"
            ),
        }

    @app.post("/api/scan")
    def scan(req: ScanRequest):
        cfg = _config_from(req.config)
        if store.has_rules() and not cfg.rules_path:
            cfg.rules_path = str(store.dir)
        data = req.content.encode("latin-1", "replace")
        result = scan_bytes(data, config=cfg, source="web-input")
        if req.report in ("sarif", "json", "html", "junit"):
            text = render_text(result, req.report)
            media = {"sarif": "application/json", "json": "application/json",
                     "html": "text/html", "junit": "application/xml"}[req.report]
            headers = {"Content-Disposition": f'attachment; filename="safix-report.{_EXT[req.report]}"'}
            return PlainTextResponse(text, media_type=media, headers=headers)
        return JSONResponse(result.to_dict())

    @app.get("/api/watch/stream")
    async def watch_stream(request: Request, path: str, from_start: bool = False,
                           severity_min: str = "info", fix_version: str = "", delimiter: str = ""):
        """Server-Sent Events stream of findings from passively tailing a server-side log file."""
        from ..engine.live import LiveScanner
        from ..parsing import tail
        from ..parsing.logreader import ReadOptions

        cfg = Config.default()
        try:
            cfg.severity_min = Severity(severity_min)
        except ValueError:
            pass
        if fix_version:
            cfg.fix_version = fix_version
        if delimiter:
            cfg.field_delimiter = delimiter
        if store.has_rules():
            cfg.rules_path = str(store.dir)

        async def gen():
            if path != "-" and not Path(path).exists():
                yield _sse("error", {"message": f"file not found: {path}"})
                return
            scanner = LiveScanner(cfg)
            q: _queue.Queue = _queue.Queue(maxsize=10000)
            stop = threading.Event()
            opts = ReadOptions()
            d = cfg.delimiter_bytes()
            if d is not None:
                opts.field_delimiter = d

            def worker():
                try:
                    src = (tail.follow_stream(options=opts, stop=stop.is_set) if path == "-"
                           else tail.follow_file(path, options=opts, from_start=from_start,
                                                 poll_interval=0.3, stop=stop.is_set))
                    for msg in src:
                        for f in scanner.feed(msg):
                            try:
                                q.put(f.to_dict(), timeout=1)
                            except _queue.Full:
                                pass
                        if stop.is_set():
                            break
                except Exception as exc:  # pragma: no cover - surfaced to the client
                    try:
                        q.put({"__error__": str(exc)}, timeout=1)
                    except _queue.Full:
                        pass
                finally:
                    try:
                        q.put(None, timeout=1)
                    except _queue.Full:
                        pass

            t = threading.Thread(target=worker, daemon=True)
            t.start()
            yield _sse("status", {"state": "watching", "path": path})
            last_summary = 0.0
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        item = q.get_nowait()
                    except _queue.Empty:
                        await asyncio.sleep(0.2)
                    else:
                        if item is None:
                            yield _sse("status", {"state": "ended"})
                            break
                        if "__error__" in item:
                            yield _sse("error", {"message": item["__error__"]})
                            break
                        yield _sse("finding", item)
                    now = time.monotonic()
                    if now - last_summary > 1.0:
                        yield _sse("summary", scanner.summary())
                        last_summary = now
            finally:
                stop.set()

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.post("/api/scan/upload")
    async def scan_upload(file: UploadFile, fix_version: str = "", delimiter: str = ""):
        raw = await file.read()
        cfg = Config.default()
        if fix_version:
            cfg.fix_version = fix_version
        if delimiter:
            cfg.field_delimiter = delimiter
        if store.has_rules():
            cfg.rules_path = str(store.dir)
        result = scan_bytes(raw, config=cfg, source=file.filename or "upload")
        return JSONResponse({**result.to_dict(), "content": raw.decode("latin-1", "replace")})

    if _STATIC.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

    return app


_EXT = {"sarif": "sarif", "json": "json", "html": "html", "junit": "xml"}
