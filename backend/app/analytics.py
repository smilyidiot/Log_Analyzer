"""Traffic, error and anomaly analytics over a parsed access-log DataFrame."""

from __future__ import annotations

import numpy as np
import pandas as pd


def _status_class(code: int) -> str:
    return f"{code // 100}xx"


def summary(df: pd.DataFrame) -> dict:
    total = len(df)
    errors = int((df["status"] >= 400).sum())
    return {
        "total_requests": total,
        "unique_visitors": int(df["ip"].nunique()),
        "total_bytes": int(df["bytes"].sum()),
        "error_count": errors,
        "error_rate_pct": round(errors / total * 100, 2) if total else 0.0,
        "start_time": df["timestamp"].min().isoformat(),
        "end_time": df["timestamp"].max().isoformat(),
    }


def by_status_class(df: pd.DataFrame) -> pd.DataFrame:
    s = df["status"].map(_status_class).value_counts().rename_axis("status_class").reset_index(name="count")
    return s.sort_values("status_class").reset_index(drop=True)


def top_paths(df: pd.DataFrame, top: int = 10) -> pd.DataFrame:
    out = df.groupby("path", observed=True).agg(hits=("path", "count"), bytes=("bytes", "sum"))
    return out.sort_values("hits", ascending=False).head(top).reset_index()


def top_ips(df: pd.DataFrame, top: int = 10) -> pd.DataFrame:
    out = df.groupby("ip", observed=True).agg(requests=("ip", "count")).sort_values("requests", ascending=False)
    return out.head(top).reset_index()


def traffic_by_hour(df: pd.DataFrame) -> pd.DataFrame:
    hourly = (
        df.set_index("timestamp").resample("h").size().rename("requests").reset_index()
    )
    hourly["hour"] = hourly["timestamp"].dt.strftime("%Y-%m-%d %H:00")
    return hourly[["hour", "requests"]]


def top_errors(df: pd.DataFrame, top: int = 10) -> pd.DataFrame:
    errs = df[df["status"] >= 400]
    if errs.empty:
        return pd.DataFrame(columns=["path", "status", "count"])
    out = (
        errs.groupby(["path", "status"], observed=True)
        .size()
        .rename("count")
        .reset_index()
        .sort_values("count", ascending=False)
        .head(top)
    )
    return out


def anomalous_ips(df: pd.DataFrame, z: float = 3.0) -> pd.DataFrame:
    """Flag IPs whose request volume is a statistical outlier (possible abuse)."""
    counts = df.groupby("ip", observed=True).size().rename("requests").reset_index()
    mean, std = counts["requests"].mean(), counts["requests"].std(ddof=0)
    if not std or np.isnan(std):
        return counts.iloc[0:0]
    counts["z_score"] = ((counts["requests"] - mean) / std).round(2)
    flagged = counts[counts["z_score"] >= z].sort_values("requests", ascending=False)
    return flagged.reset_index(drop=True)


def traffic_spikes(df: pd.DataFrame, z: float = 2.5) -> pd.DataFrame:
    """Flag hours whose request volume spikes above the mean."""
    hourly = traffic_by_hour(df)
    mean, std = hourly["requests"].mean(), hourly["requests"].std(ddof=0)
    if not std or np.isnan(std):
        return hourly.iloc[0:0]
    hourly["z_score"] = ((hourly["requests"] - mean) / std).round(2)
    return hourly[hourly["z_score"] >= z].reset_index(drop=True)


def _insights(summ: dict, statuses: pd.DataFrame, ips: pd.DataFrame, spikes: pd.DataFrame) -> list[str]:
    notes = [f"{summ['total_requests']:,} requests from {summ['unique_visitors']:,} unique visitors."]
    if summ["error_rate_pct"] > 0:
        notes.append(f"Error rate is {summ['error_rate_pct']:.1f}% ({summ['error_count']:,} 4xx/5xx responses).")
    if not ips.empty:
        top = ips.iloc[0]
        notes.append(f"Top IP {top['ip']} made {int(top['requests']):,} requests (z={top['z_score']}) — possible abuse.")
    if not spikes.empty:
        notes.append(f"{len(spikes)} traffic spike hour(s) detected above normal volume.")
    return notes


def build_report(df: pd.DataFrame) -> dict:
    """Assemble the full analytics report as a JSON-serialisable dict."""
    summ = summary(df)
    statuses = by_status_class(df)
    ips = anomalous_ips(df)
    spikes = traffic_spikes(df)
    return {
        "summary": summ,
        "by_status_class": statuses.to_dict(orient="records"),
        "top_paths": top_paths(df).to_dict(orient="records"),
        "top_ips": top_ips(df).to_dict(orient="records"),
        "traffic_by_hour": traffic_by_hour(df).to_dict(orient="records"),
        "top_errors": top_errors(df).to_dict(orient="records"),
        "anomalous_ips": ips.to_dict(orient="records"),
        "traffic_spikes": spikes.to_dict(orient="records"),
        "insights": _insights(summ, statuses, ips, spikes),
    }
