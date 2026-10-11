"""Tests for the FastAPI web backend."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
import tempfile  # noqa: E402
from pathlib import Path  # noqa: E402

from fastapi.testclient import TestClient  # noqa: E402

from safix.web.api import create_app  # noqa: E402

client = TestClient(create_app(workdir=Path(tempfile.mkdtemp())))


def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_dictionaries_and_rules():
    assert "FIX.4.4" in client.get("/api/dictionaries").json()["versions"]
    detectors = client.get("/api/rules").json()["detectors"]
    assert any(d["id"] == "datatype" for d in detectors)


def test_config_schema():
    schema = client.get("/api/config/schema").json()
    assert "thresholds" in schema["defaults"]
    assert "max_order_qty" in schema["thresholds_schema"]


def test_scan_json():
    payload = {
        "content": "8=FIX.4.4|35=D|34=2|49=C|52=20231015-09:00:01.000|56=S|11=O1|11=O2|"
                   "55=AAPL|54=I|38=-100|40=2|44=1e5|60=20231015-09:00:01.000|10=0|",
        "config": {"severity_min": "info"},
    }
    r = client.post("/api/scan", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["message_count"] == 1
    rules = {f["rule_id"] for f in data["findings"]}
    assert "SAFIX-APP-001" in rules       # negative qty
    assert "SAFIX-STRUCT-140" in rules     # duplicate ClOrdID


def test_scan_sarif_report():
    payload = {"content": "8=FIX.4.4|35=0|34=1|49=C|56=S|10=0|", "report": "sarif"}
    r = client.post("/api/scan", json=payload)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert '"version": "2.1.0"' in r.text


def test_index_served():
    r = client.get("/")
    assert r.status_code == 200
    assert "SAFIX" in r.text


def test_rules_all_and_help():
    allr = client.get("/api/rules/all").json()
    assert allr["detectors"] and allr["catalog"]
    ids = {r["id"] for r in allr["catalog"]}
    assert any(i.startswith("SAFIX-") for i in ids)
    help_ = client.get("/api/rules/help").json()
    assert any(o["op"] == "equals" for o in help_["operators"])
    assert "when:" in help_["example"]


def test_custom_rule_roundtrip_and_effect():
    yaml_text = (
        "rules:\n"
        "  - id: WEB-CUSTOM-1\n"
        "    title: Account 999 forbidden\n"
        "    severity: high\n"
        "    msg_types: ['D']\n"
        "    when:\n"
        "      - {tag: 1, equals: '999'}\n"
    )
    r = client.put("/api/rules/custom", json={"yaml": yaml_text})
    assert r.json()["ok"] and r.json()["count"] == 1
    assert "WEB-CUSTOM-1" in client.get("/api/rules/custom").json()["yaml"]
    # the saved rule now fires on a scan
    order = ("8=FIX.4.4|35=D|34=2|49=C|52=20231015-09:00:00.000|56=S|11=O1|1=999|55=AAPL|"
             "54=1|38=100|40=2|44=150|60=20231015-09:00:00.000|10=0|")
    data = client.post("/api/scan", json={"content": order, "config": {}}).json()
    assert "WEB-CUSTOM-1" in {f["rule_id"] for f in data["findings"]}


def test_invalid_custom_rule_rejected():
    r = client.put("/api/rules/custom", json={"yaml": "rules:\n  - id: X\n    severity: not-a-severity\n    when: []\n"})
    body = r.json()
    assert body["ok"] is False and body["error"]


def test_disabled_rule_hidden_in_scan():
    order = ("8=FIX.4.4|35=D|34=2|49=C|52=20231015-09:00:00.000|56=S|11=O1|55=AAPL|"
             "54=1|38=-100|40=2|44=150|60=20231015-09:00:00.000|10=0|")
    base = client.post("/api/scan", json={"content": order, "config": {}}).json()
    assert "SAFIX-APP-001" in {f["rule_id"] for f in base["findings"]}
    off = client.post("/api/scan", json={"content": order, "config": {"disabled_rules": ["SAFIX-APP-001"]}}).json()
    assert "SAFIX-APP-001" not in {f["rule_id"] for f in off["findings"]}


def test_watch_stream_missing_file():
    with client.stream("GET", "/api/watch/stream", params={"path": "/no/such/safix_file.log"}) as r:
        assert r.status_code == 200
        text = ""
        for line in r.iter_lines():
            text += line + "\n"
            if len(text) > 400:
                break
    assert "event: error" in text


def test_report_download_headers():
    r = client.post("/api/scan", json={"content": "8=FIX.4.4|35=0|34=1|49=C|56=S|10=0|", "report": "html"})
    assert r.status_code == 200
    assert "attachment" in r.headers.get("content-disposition", "")
