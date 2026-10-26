"""FastAPI service for the Log Analyzer."""

from __future__ import annotations

import io
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from . import __version__, analytics, exporters, parser
from .models import Report

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample_access.log"

app = FastAPI(title="Log Analyzer API", version=__version__,
              description="Parse access logs and surface traffic, error and anomaly analytics.")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


def _report(raw: bytes) -> dict:
    try:
        df = parser.parse_logs(raw)
    except parser.LogParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return analytics.build_report(df)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/sample", response_model=Report)
def sample() -> dict:
    return analytics.build_report(parser.parse_logs(str(SAMPLE)))


@app.post("/api/analyze", response_model=Report)
async def analyze(file: UploadFile = File(...)) -> dict:
    return _report(await file.read())


@app.post("/api/report")
async def report(file: UploadFile = File(...)) -> StreamingResponse:
    data = _report(await file.read())
    return StreamingResponse(
        io.BytesIO(exporters.to_excel(data)),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": 'attachment; filename="log_report.xlsx"'},
    )
