"""Tests for the log analytics core against the bundled sample."""

from __future__ import annotations

from pathlib import Path

import pytest

from app import analytics, parser

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample_access.log"


@pytest.fixture(scope="module")
def df():
    return parser.parse_logs(str(SAMPLE))


def test_summary(df):
    s = analytics.summary(df)
    assert s["total_requests"] == len(df)
    assert 0 <= s["error_rate_pct"] <= 100
    assert s["unique_visitors"] > 0


def test_status_classes_present(df):
    classes = {r["status_class"] for r in analytics.by_status_class(df).to_dict("records")}
    assert "2xx" in classes and "4xx" in classes


def test_anomalous_ip_detected(df):
    flagged = analytics.anomalous_ips(df)
    assert "203.0.113.66" in set(flagged["ip"])  # the injected attacker


def test_report_shape(df):
    r = analytics.build_report(df)
    assert set(r) >= {
        "summary", "by_status_class", "top_paths", "top_ips",
        "traffic_by_hour", "top_errors", "anomalous_ips", "traffic_spikes", "insights",
    }
    assert r["insights"]
