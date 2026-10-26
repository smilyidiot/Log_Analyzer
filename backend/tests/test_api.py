"""API tests for the Log Analyzer."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample_access.log"
client = TestClient(app)


def test_health():
    assert client.get("/api/health").json()["status"] == "ok"


def test_sample():
    r = client.get("/api/sample")
    assert r.status_code == 200
    assert r.json()["summary"]["total_requests"] > 0


def test_analyze_upload():
    with SAMPLE.open("rb") as fh:
        r = client.post("/api/analyze", files={"file": ("access.log", fh, "text/plain")})
    assert r.status_code == 200
    assert len(r.json()["anomalous_ips"]) >= 1


def test_analyze_rejects_garbage():
    r = client.post("/api/analyze", files={"file": ("x.log", b"not a log\n", "text/plain")})
    assert r.status_code == 422


def test_excel_report():
    with SAMPLE.open("rb") as fh:
        r = client.post("/api/report", files={"file": ("access.log", fh, "text/plain")})
    assert r.status_code == 200
    assert r.content[:2] == b"PK"
