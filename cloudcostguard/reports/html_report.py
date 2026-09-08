"""HTML report for CloudCostGuard findings."""

from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cloudcostguard.models.finding import Finding


def render_html(
    findings: list[Finding],
    summary: dict[str, Any],
    timestamp: str,
    account_id: str,
    regions: list[str],
    template_dir: str | None = None,
) -> str:
    """Render findings and summary as standalone HTML."""
    env = Environment(
        autoescape=select_autoescape(["html", "xml"]),
        loader=FileSystemLoader(template_dir or "."),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    # Inline template for standalone use
    template = env.from_string(
        """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudCostGuard Report</title>
    <style>
        body {font-family: Arial, sans-serif; margin: 40px; line-height: 1.6;}
        h1 {color: #333; border-bottom: 2px solid #667; padding-bottom: 10px;}
        .header {margin-bottom: 20px;}
        .account {font-size: 0.9em; color: #666; margin-bottom: 20px;}
        .section {margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 20px;}
        .findings {margin-top: 20px;}
        .finding {margin: 10px 0; padding: 10px; border-left: 4px solid; border-radius: 4px;}
        .critical {border-color: #e74c3c; background: #fdf2f2;}
        .high {border-color: #e67e22; background: #fdf6ec;}
        .medium {border-color: #f1c40f; background: #f9f8f1;}
        .low {border-color: #3498db; background: #ebf5fb;}
        .info {border-color: #9b59b6; background: #f2e9f6;}
        .summary {background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;}
        .cost {font-weight: bold; color: #c0392b;}
        table {width: 100%; border-collapse: collapse; margin: 20px 0;}
        th, td {padding: 8px; text-align: left; border-bottom: 1px solid #ddd;}
        th {background: #f2f2f2;}
    </style>
</head>
<body>
    <h1>CloudCostGuard Report</h1>
    <div class="header">
        <div class="account">Account: {{ account_id }}</div>
        <div>Region: {{ regions|join(', ') }}</div>
        <div>Scan Time: {{ timestamp }}</div>
    </div>

    <div class="section summary">
        <h2>Summary</h2>
        <p>Resources Scanned: {{ resources_scanned }}</p>
        <p class="cost">Potential Monthly Waste: ${{ "%.2f"|format(potential_monthly_waste) }}</p>
    </div>

    {% if findings %}
    <div class="findings">
        <h2>Findings</h2>
        {% for f in findings %}
        <div class="finding {{ f.severity.value }}">
            <h3>{{ f.title }}</h3>
            <p><strong>Resource:</strong> {{ f.resource_id }}</p>
            <p><strong>Service:</strong> {{ f.service }}</p>
            <p><strong>Region:</strong> {{ f.region }}</p>
            <p><strong>Estimated Monthly Waste:</strong> <span class="cost">${{ "%.2f"|format(f.estimated_monthly_cost) }}</span></p>
            <p><strong>Evidence:</strong> {{ f.evidence|default('N/A') }}</p>
            <p><strong>Recommendation:</strong> {{ f.recommendation|default('N/A') }}</p>
        </div>
        {% endfor %}
    </div>
    {% endif %}

    <footer style="margin-top: 40px; font-size: 0.8em; color: #666;">
        Note: Cost estimates are approximate. Review AWS billing before making financial decisions.
    </footer>
</body>
</html>"""
    )

    result = template.render(
        findings=findings,
        summary=summary,
        timestamp=timestamp,
        account_id=account_id,
        regions=regions,
        resources_scanned=summary.get("resources_scanned", 0),
        potential_monthly_waste=summary.get("potential_monthly_waste", 0.0),
    )
    return result
