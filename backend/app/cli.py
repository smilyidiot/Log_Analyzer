"""Command-line interface for the Log Analyzer.

    python -m app.cli analyze data/sample_access.log
    python -m app.cli analyze data/sample_access.log --excel report.xlsx --json
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from . import analytics, exporters, parser

cli = typer.Typer(add_completion=False, help="Log Analyzer command-line tools.")
_SAMPLE = Path(__file__).resolve().parent.parent / "data" / "sample_access.log"


def _run(path: Path, excel: Path | None, as_json: bool) -> None:
    try:
        df = parser.parse_logs(str(path))
    except parser.LogParseError as exc:
        typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    report = analytics.build_report(df)

    if as_json:
        typer.echo(json.dumps(report, indent=2))
    else:
        s = report["summary"]
        typer.secho("\nLog Analyzer", fg=typer.colors.CYAN, bold=True)
        typer.echo(f"  Window        : {s['start_time']} .. {s['end_time']}")
        typer.echo(f"  Requests      : {s['total_requests']:,} from {s['unique_visitors']:,} IPs")
        typer.echo(f"  Error rate    : {s['error_rate_pct']:.1f}%  ({s['error_count']:,} errors)")
        typer.secho("\n  Status mix:", bold=True)
        for row in report["by_status_class"]:
            typer.echo(f"    {row['status_class']}  {row['count']:>8,}")
        typer.secho("\n  Insights:", bold=True)
        for note in report["insights"]:
            typer.echo(f"    • {note}")

    if excel:
        excel.write_bytes(exporters.to_excel(report))
        typer.secho(f"Wrote Excel report -> {excel}", fg=typer.colors.GREEN)


@cli.command()
def analyze(
    path: Path = typer.Argument(..., exists=True, readable=True, help="Access log file."),
    excel: Path = typer.Option(None, "--excel", help="Write an Excel report to this path."),
    as_json: bool = typer.Option(False, "--json", help="Print the full report as JSON."),
) -> None:
    """Analyse an access log and optionally export an Excel report."""
    _run(path, excel, as_json)


@cli.command()
def sample(excel: Path = typer.Option(None, "--excel"), as_json: bool = typer.Option(False, "--json")) -> None:
    """Run the analysis on the bundled sample log."""
    _run(_SAMPLE, excel, as_json)


if __name__ == "__main__":
    cli()
