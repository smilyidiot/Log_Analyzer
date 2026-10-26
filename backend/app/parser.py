"""Parse NCSA Combined Log Format access logs into a tidy DataFrame.

A typical line looks like::

    12.34.56.78 - - [10/Oct/2026:13:55:36 +0000] "GET /api/users HTTP/1.1" 200 2326 "https://ref" "Mozilla/5.0"
"""

from __future__ import annotations

import re
from io import StringIO
from typing import IO

import pandas as pd

# One compiled regex captures every field of the combined log format.
_LINE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) '
    r'"(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'
)


class LogParseError(ValueError):
    """Raised when a log file yields no parseable lines."""


def parse_logs(source: str | IO[str] | bytes) -> pd.DataFrame:
    """Parse an access log (path, file-like or bytes) into a cleaned DataFrame.

    Unparseable lines are skipped. The returned frame has typed columns:
    ``ip, timestamp, method, path, status, bytes, referrer, agent``.
    """
    if isinstance(source, bytes):
        source = StringIO(source.decode("utf-8", "replace"))
    elif isinstance(source, str) and "\n" not in source:
        # Treat a bare string without newlines as a file path.
        with open(source, encoding="utf-8", errors="replace") as fh:
            return _parse_lines(fh)
    elif isinstance(source, str):
        source = StringIO(source)
    return _parse_lines(source)


def _parse_lines(lines) -> pd.DataFrame:
    records = []
    for line in lines:
        m = _LINE.match(line.strip())
        if not m:
            continue
        d = m.groupdict()
        records.append(d)

    if not records:
        raise LogParseError("No parseable Combined Log Format lines found.")

    df = pd.DataFrame.from_records(records)
    df["timestamp"] = pd.to_datetime(df["ts"], format="%d/%b/%Y:%H:%M:%S %z", errors="coerce", utc=True)
    df["status"] = pd.to_numeric(df["status"], errors="coerce").astype("Int64")
    df["bytes"] = pd.to_numeric(df["bytes"].replace("-", "0"), errors="coerce").fillna(0).astype("int64")
    df = df.dropna(subset=["timestamp", "status"]).reset_index(drop=True)
    return df[["ip", "timestamp", "method", "path", "status", "bytes", "referrer", "agent"]]
