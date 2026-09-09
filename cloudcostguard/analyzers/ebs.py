"""EBS analyzer for CloudCostGuard."""

from __future__ import annotations

from datetime import UTC

import boto3
from botocore.exceptions import ClientError

from cloudcostguard.analyzers.base import BaseAnalyzer, Confidence, Finding, Severity


class EBSAnalyzer(BaseAnalyzer):
    """Analyzer for EBS volumes."""

    name = "ebs"

    def __init__(self):
        super().__init__()
        self.services = ["ec2"]

    def scan(self, region: str, verbose: bool = False) -> list[Finding]:
        """Scan EBS volumes for unattached or stale volumes."""
        findings: list[Finding] = []
        self.resources_scanned = 0

        try:
            client = boto3.client("ec2", region_name=region)

            # Describe all volumes
            volumes = []
            paginator = client.get_paginator("describe_volumes")
            for page in paginator.paginate():
                volumes.extend(page.get("Volumes", []))

            self.resources_scanned = len(volumes)

            for volume in volumes:
                volume_id = volume.get("VolumeId", "unknown")
                size = volume.get("Size", 0)
                state = volume.get("State", "unknown")
                attachments = volume.get("Attachments", [])
                availability_zone = volume.get("AvailabilityZone", "")
                volume_type = volume.get("VolumeType", "unknown")
                create_time = volume.get("CreateTime")

                # Check for unattached volumes
                if not attachments:
                    cost = self._estimate_ebs_cost(size) if verbose else 0.0

                    finding = self._create_finding(
                        region=region,
                        service="ebs",
                        resource_id=volume_id,
                        resource_type="volume",
                        severity=Severity.HIGH,
                        title="Unattached EBS volume",
                        description=f"EBS volume {volume_id} is unattached",
                        evidence=f"Volume size: {size} GB; State: {state}; Attachments: {len(attachments)}",
                        cost=cost,
                        confidence=Confidence.HIGH,
                        metadata={
                            "size_gb": size,
                            "state": state,
                            "volume_type": volume_type,
                            "availability_zone": availability_zone,
                        },
                    )
                    findings.append(finding)
                # Check for obviously stale volumes (very old, unattached or minimal attachment)
                elif attachments and create_time:
                    from datetime import datetime
                    now = datetime.now(UTC)
                    days_since_creation = (now - create_time).days
                    if days_since_creation > 365:  # > 1 year old
                        cost = self._estimate_ebs_cost(size) if verbose else 0.0
                        finding = self._create_finding(
                            region=region,
                            service="ebs",
                            resource_id=volume_id,
                            resource_type="volume",
                            severity=Severity.MEDIUM,
                            title="Old/stale EBS volume",
                            description=f"EBS volume {volume_id} is {days_since_creation} days old",
                            evidence=f"Created {days_since_creation} days ago; Size: {size} GB; Type: {volume_type}; Still attached",
                            cost=cost,
                            confidence=Confidence.MEDIUM,
                            metadata={
                                "size_gb": size,
                                "state": state,
                                "volume_type": volume_type,
                                "days_since_creation": days_since_creation,
                            },
                        )
                        findings.append(finding)

        except ClientError:
            pass  # Silently handle AWS errors; findings will be empty

        return findings

    @staticmethod
    def _estimate_ebs_cost(size_gb: int) -> float:
        """Estimate monthly EBS cost for a volume size."""
        # GP3 pricing approx $0.08/GB-month
        return round(size_gb * 0.08, 2)
