"""Generate a deterministic sample access.log in Combined Log Format (stdlib only).

Includes a noisy/abusive IP and a traffic spike so the anomaly detection has
something to flag. Run:  python backend/data/generate_sample.py
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

RNG = random.Random(2026)

PATHS = ["/", "/login", "/api/users", "/api/orders", "/products", "/products/42",
         "/static/app.js", "/static/style.css", "/search", "/checkout", "/admin"]
AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/123.0",
    "curl/8.4.0",
]
STATUS = [200, 200, 200, 200, 200, 301, 404, 404, 500]


def line(ip: str, ts: datetime, method: str, path: str, status: int, size: int, agent: str) -> str:
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'


def main() -> None:
    start = datetime(2026, 10, 20, 0, 0, 0, tzinfo=timezone.utc)
    rows = []

    def rand_ip() -> str:
        return f"{RNG.randint(11, 220)}.{RNG.randint(0, 255)}.{RNG.randint(0, 255)}.{RNG.randint(1, 254)}"

    ips = [rand_ip() for _ in range(40)]

    # Normal traffic spread across 24 hours.
    for hour in range(24):
        volume = RNG.randint(8, 22)
        for _ in range(volume):
            ts = start + timedelta(hours=hour, seconds=RNG.randint(0, 3599))
            rows.append((ts, RNG.choice(ips), RNG.choice(["GET", "GET", "GET", "POST"]),
                         RNG.choice(PATHS), RNG.choice(STATUS), RNG.randint(120, 8000), RNG.choice(AGENTS)))

    # Abusive IP hammering /login (shows up as an anomalous IP).
    attacker = "203.0.113.66"
    for _ in range(300):
        ts = start + timedelta(hours=14, seconds=RNG.randint(0, 3599))
        rows.append((ts, attacker, "POST", "/login", RNG.choice([401, 401, 403, 200]),
                     RNG.randint(80, 300), "curl/8.4.0"))

    rows.sort(key=lambda r: r[0])
    out = Path(__file__).resolve().parent / "sample_access.log"
    with out.open("w") as fh:
        for ts, ip, method, path, status, size, agent in rows:
            fh.write(line(ip, ts, method, path, status, size, agent) + "\n")
    print(f"Wrote {len(rows)} log lines -> {out}")


if __name__ == "__main__":
    main()
