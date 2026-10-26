# Log Analyzer

A Python tool that parses **web access logs** (NCSA Combined Log Format) and
turns them into traffic, error and **anomaly** analytics — exposed as a
**FastAPI** service, a **Typer CLI** and a downloadable **Excel** report.

Built with the help of AI coding tools (Claude Code) and reviewed/tested by hand.

## What it does

- **Parse** logs with a single compiled regex (`parser.py`); malformed lines are skipped.
- **Analytics** (`analytics.py`, Pandas/NumPy):
  - Summary: total requests, unique visitors, bytes served, error rate, time window.
  - Breakdown by status class (2xx/3xx/4xx/5xx), top paths, top IPs, traffic by hour.
  - Top error endpoints (4xx/5xx).
  - **Anomaly detection**: IPs with outlier request volume (z-score ≥ 3 → possible abuse) and hourly traffic spikes.
- **Outputs**: JSON (API), a formatted terminal summary (CLI) and a multi-sheet **Excel** report.

## Tech stack

Python · **Pandas / NumPy** · **FastAPI** + Pydantic · **openpyxl** · **Typer** CLI · **pytest**.

## Run it

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# API (docs at http://localhost:8000/docs)
uvicorn app.main:app --reload --port 8000

# CLI
python -m app.cli analyze data/sample_access.log
python -m app.cli analyze data/sample_access.log --excel report.xlsx

# tests
pytest -q
```

Regenerate the sample log with `python data/generate_sample.py`.

## API

| Method & path | Purpose |
|---|---|
| `GET /api/health` | Liveness probe |
| `GET /api/sample` | Analytics for the bundled sample log |
| `POST /api/analyze` | Analytics for an uploaded log file |
| `POST /api/report` | Download a multi-sheet Excel report |

## Input format

NCSA Combined Log Format, e.g.:

```
12.34.56.78 - - [20/Oct/2026:13:55:36 +0000] "GET /api/users HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
```
