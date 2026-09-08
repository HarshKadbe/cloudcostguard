"""JSON report for CloudCostGuard findings."""

import json
from typing import Any

from cloudcostguard.models.finding import Finding


class JSONReport:
    """Machine-readable JSON report."""

    def __init__(self, output_file: str | None = None):
        self.output_file = output_file

    def render(
        self,
        findings: list[Finding],
        summary: dict[str, Any],
        timestamp: str,
        account_id: str,
        regions: list[str],
    ) -> str:
        """Render findings and summary as JSON."""
        data = {
            "scan": {
                "timestamp": timestamp,
                "account_id": account_id,
                "regions": regions,
            },
            "summary": {
                "resources_scanned": summary.get("resources_scanned", 0),
                "potential_monthly_waste": summary.get("potential_monthly_waste", 0.0),
            },
            "findings": [f.to_dict() for f in findings],
        }

        json_str = json.dumps(data, indent=2, default=str)
        if self.output_file:
            with open(self.output_file, "w") as f:
                f.write(json_str)
        return json_str
