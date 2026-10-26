"""Tests for the Combined Log Format parser."""

from __future__ import annotations

import pytest

from app import parser

GOOD = (
    '12.34.56.78 - - [20/Oct/2026:13:55:36 +0000] "GET /api/users HTTP/1.1" 200 2326 "-" "curl/8.4.0"\n'
    '9.9.9.9 - - [20/Oct/2026:13:56:00 +0000] "POST /login HTTP/1.1" 401 120 "-" "Mozilla/5.0"\n'
)


def test_parse_basic():
    df = parser.parse_logs(GOOD)
    assert len(df) == 2
    assert df.iloc[0]["ip"] == "12.34.56.78"
    assert df.iloc[0]["status"] == 200
    assert df.iloc[0]["bytes"] == 2326
    assert df.iloc[1]["method"] == "POST"


def test_skips_garbage_lines():
    df = parser.parse_logs(GOOD + "this is not a log line\n")
    assert len(df) == 2  # garbage ignored


def test_empty_raises():
    with pytest.raises(parser.LogParseError):
        parser.parse_logs("nothing parseable here\n")


def test_dash_bytes_become_zero():
    line = '1.1.1.1 - - [20/Oct/2026:00:00:00 +0000] "GET / HTTP/1.1" 304 - "-" "x"\n'
    df = parser.parse_logs(line)
    assert df.iloc[0]["bytes"] == 0
