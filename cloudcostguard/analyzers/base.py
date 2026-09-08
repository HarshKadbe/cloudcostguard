"""Base analyzer class for CloudCostGuard."""

from __future__ import annotations

from typing import ClassVar

from cloudcostguard.models.finding import Confidence, Finding, Severity


class BaseAnalyzer:
    """Base class for all CloudCostGuard analyzers."""

    name: str = "base"
    services: ClassVar[list[str]] = ["ec2"]

    def __init__(self):
        self.resources_scanned = 0

    def scan(self, region: str, verbose: bool = False) -> list[Finding]:
        """Scan resources in the given region. Must be implemented by subclasses."""
        raise NotImplementedError

    def _create_finding(
        self,
        region: str,
        service: str,
        resource_id: str,
        resource_type: str,
        severity: Severity,
        title: str,
        description: str,
        evidence: str = "",
        cost: float = 0.0,
        confidence: Confidence = Confidence.MEDIUM,
        metadata: dict | None = None,
    ) -> Finding:
        """Create a Finding instance."""
        return Finding(
            service=service,
            resource_id=resource_id,
            resource_type=resource_type,
            region=region,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            estimated_monthly_cost=cost,
            confidence=confidence,
            metadata=metadata or {},
        )
