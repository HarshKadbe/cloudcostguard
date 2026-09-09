"""Terminal report for CloudCostGuard findings."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.text import Text

from cloudcostguard.models.finding import Finding, Severity


class TerminalReport:
    """Professional terminal report using Rich."""

    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    def render(self, findings: list[Finding], summary: dict[str, Any]) -> None:
        """Render findings and summary to terminal."""
        self._render_header(summary)
        self._render_findings(findings)
        self._render_summary(findings, summary)

    def _render_header(self, summary: dict[str, Any]) -> None:
        """Render the header section."""
        title = Text("CloudCostGuard", style="bold blue")
        subtitle = Text("AWS Cost & Waste Scanner", style="dim")
        self.console.print(title)
        self.console.print(subtitle)
        self.console.print()

        account = summary.get("account_id", "unknown")
        region = summary.get("region", "unknown")
        self.console.print(f"Account: {account}")
        self.console.print(f"Region: {region}")
        self.console.print()

    def _render_findings(self, findings: list[Finding]) -> None:
        """Render findings grouped by severity."""
        # Group by severity
        by_severity: dict[Severity, list[Finding]] = {}
        for f in findings:
            by_severity.setdefault(f.severity, []).append(f)

        for sev in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]:
            findings_list = by_severity.get(sev, [])
            if not findings_list:
                continue

            # Map severity to rich style
            if sev == Severity.CRITICAL:
                style = "red"
                emoji = "🔴"
            elif sev == Severity.HIGH:
                style = "red"
                emoji = "⚠"
            elif sev == Severity.MEDIUM:
                style = "yellow"
                emoji = "⚡"
            elif sev == Severity.LOW:
                style = "cyan"
                emoji = "ℹ"
            else:
                style = "green"
                emoji = "ℹ"

            self.console.print()
            self.console.print(f"{emoji} {sev.value.upper()}", style=f"bold {style}")
            self.console.print(
                "────────────────────────────────────────",
                style=f"italic {style}",
            )

            for f in findings_list:
                self._render_finding(f)

    def _render_finding(self, finding: Finding) -> None:
        """Render a single finding."""
        desc = finding.description
        evidence = finding.evidence
        cost = finding.estimated_monthly_cost

        # Format cost
        cost_str = f"${cost:.2f}" if cost > 0 else "~estimate~"

        self.console.print()
        self.console.print(f"  {finding.resource_id}", style="bold")
        self.console.print(f"  {desc}", style="dim")
        if evidence:
            self.console.print(f"  Evidence: {evidence}")
        self.console.print(f"  Estimated monthly waste: {cost_str} {finding.currency}")

    def _render_summary(self, findings: list[Finding], summary: dict[str, Any]) -> None:
        """Render the summary section."""
        self.console.print("────────────────────────────────────────")
        total_high = sum(1 for f in findings if f.severity == Severity.HIGH)
        total_low = sum(1 for f in findings if f.severity == Severity.LOW)
        total_estimated = summary.get("potential_monthly_waste", 0.0)
        self.console.print(f"Resources scanned: {summary.get('resources_scanned', 0)}")
        self.console.print(f"Potential monthly waste: ${total_estimated:.2f} USD")
        self.console.print(f"High: {total_high}, Low: {total_low}")
