"""CLI commands for CloudCostGuard."""

from __future__ import annotations

import sys
import typer
from typing import List, Optional

from cloudcostguard.analyzers.base import BaseAnalyzer
from cloudcostguard.config import get_region, get_account_id
from cloudcostguard.models.finding import Finding, Severity, Confidence
from cloudcostguard.reports.terminal import TerminalReport
from cloudcostguard.reports.json_report import JSONReport
from cloudcostguard.reports.html_report import render_html
from cloudcostguard.analyzers.ec2 import EC2Analyzer
from cloudcostguard.analyzers.ebs import EBSAnalyzer
from cloudcostguard.analyzers.elastic_ip import ElasticIPAnalyzer
from cloudcostguard.analyzers.s3 import S3Analyzer


def scan_all_services(
    regions: Optional[List[str]] = None,
    services: Optional[List[str]] = None,
    verbose: bool = False,
) -> dict:
    """Scan AWS resources for cost and waste analysis."""
    if regions is None:
        region = get_region() or "us-east-1"
        regions = [region]
    else:
        regions = regions

    if services is None:
        services = ["ec2", "ebs", "elastic_ip", "s3"]

    all_findings: list[Finding] = []
    resources_scanned = 0

    analyzer_map = {
        "ec2": EC2Analyzer(),
        "ebs": EBSAnalyzer(),
        "elastic_ip": ElasticIPAnalyzer(),
        "s3": S3Analyzer(),
    }

    for region_name in regions:
        for service_name in services:
            if service_name not in analyzer_map:
                continue

            analyzer = analyzer_map[service_name]
            try:
                findings = analyzer.scan(region_name, verbose)
                resources_scanned += analyzer.resources_scanned
                all_findings.extend(findings)
            except Exception as e:
                if verbose:
                    typer.echo(f"Error scanning {service_name} in {region_name}: {e}")
                continue

    summary: dict = {
        "account_id": get_account_id() or "unknown",
        "region": ", ".join(regions),
        "resources_scanned": resources_scanned,
        "potential_monthly_waste": round(sum(f.estimated_monthly_cost or 0.0 for f in all_findings), 2),
        "findings": all_findings,
    }

    return {
        "findings": all_findings,
        "summary": summary,
        "regions": regions,
        "timestamp": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
    }


app = typer.Typer(
    name="cloudcostguard",
    help="AWS Cost & Waste Scanner CLI",
    add_completion=False,
)


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        help="Show the version and exit.",
    ),
):
    """AWS Cost & Waste Scanner CLI."""
    if version:
        from cloudcostguard import __version__
        typer.echo(f"cloudcostguard {__version__}")
        raise typer.Exit()


@app.command()
def scan(
    region: str = typer.Option(
        None,
        "--region",
        "-r",
        help="AWS region to scan (default: from AWS config or us-east-1)",
    ),
    services: str = typer.Option(
        None,
        "--services",
        help="Comma-separated list of services to scan (ec2,ebs,elastic_ip,s3)",
    ),
    format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, json, html",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        help="Enable verbose debug output",
    ),
    output_file: str = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file for json/html format",
    ),
) -> None:
    """Scan AWS resources for cost and waste analysis."""
    result = scan_all_services(
        regions=[region] if region else None,
        services=[s.strip().lower() for s in services.split(",")] if services else None,
        verbose=verbose,
    )

    summary = result["summary"]
    findings = result["findings"]
    timestamp = result["timestamp"]
    account_id = summary.get("account_id", "unknown")
    regions_display = summary.get("region", "unknown").split(",")

    if format == "json":
        json_report = JSONReport(output_file)
        json_str = json_report.render(
            findings=findings,
            summary=summary,
            timestamp=timestamp,
            account_id=account_id,
            regions=regions_display,
        )
        typer.echo(json_str)
    elif format == "html":
        html_str = render_html(
            findings=findings,
            summary=summary,
            timestamp=timestamp,
            account_id=account_id,
            regions=regions_display,
        )
        if output_file:
            with open(output_file, "w") as f:
                f.write(html_str)
            typer.echo(f"HTML report written to {output_file}")
        else:
            typer.echo(html_str)
    else:
        report = TerminalReport()
        report.render(findings, summary)


@app.command()
def version(_: bool = False) -> None:
    """Show the version."""
    from cloudcostguard import __version__
    typer.echo(f"cloudcostguard {__version__}")


def main() -> None:
    """Entry point for CLI."""
    typer.run(app)


if __name__ == "__main__":
    main()
