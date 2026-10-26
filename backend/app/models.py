"""Pydantic models for the Log Analyzer API responses."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Summary(BaseModel):
    total_requests: int
    unique_visitors: int
    total_bytes: int
    error_count: int
    error_rate_pct: float
    start_time: str
    end_time: str


class StatusRow(BaseModel):
    status_class: str
    count: int


class PathRow(BaseModel):
    path: str
    hits: int
    bytes: int


class IpRow(BaseModel):
    ip: str
    requests: int


class HourRow(BaseModel):
    hour: str
    requests: int


class ErrorRow(BaseModel):
    path: str
    status: int
    count: int


class AnomalousIp(BaseModel):
    ip: str
    requests: int
    z_score: float


class SpikeRow(BaseModel):
    hour: str
    requests: int
    z_score: float


class Report(BaseModel):
    summary: Summary
    by_status_class: list[StatusRow]
    top_paths: list[PathRow]
    top_ips: list[IpRow]
    traffic_by_hour: list[HourRow]
    top_errors: list[ErrorRow]
    anomalous_ips: list[AnomalousIp]
    traffic_spikes: list[SpikeRow]
    insights: list[str] = Field(default_factory=list)
