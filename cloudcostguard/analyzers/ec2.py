"""EC2 analyzer for CloudCostGuard."""

from __future__ import annotations

from datetime import UTC
from typing import ClassVar

import boto3
from botocore.exceptions import ClientError

from cloudcostguard.analyzers.base import BaseAnalyzer, Confidence, Finding, Severity


class EC2Analyzer(BaseAnalyzer):
    """Analyzer for EC2 resources."""

    name: str = "ec2"
    services: ClassVar[tuple[str, ...]] = ("ec2",)

    def scan(self, region: str, verbose: bool = False) -> list[Finding]:
        """Scan EC2 instances for waste indicators.

        Conditions that create findings:
        - Stopped instance: state == "stopped" (instance is not running)
        - Old/stale instance: launch_time is > 90 days ago and (no name tag or age > 180 days)

        Note: Findings are based on instance state and launch time, NOT CloudWatch
        utilization metrics. No CPU/memory usage data is required or checked.

        AccessDenied errors are caught and logged; the scan continues with other instances.
        Throttling errors may propagate depending on boto3 retry behavior.
        """
        findings: list[Finding] = []
        self.resources_scanned = 0

        try:
            client = boto3.client("ec2", region_name=region)

            # Describe all instances
            instances = []
            paginator = client.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    instances.extend(reservation.get("Instances", []))

            self.resources_scanned = len(instances)

            for instance in instances:
                instance_id = instance.get("InstanceId", "unknown")
                instance_type = instance.get("InstanceType", "unknown")
                state = instance.get("State", {}).get("Name", "unknown")
                launch_time = instance.get("LaunchTime")
                tags = instance.get("Tags", [])
                name = self._get_tag_value(tags, "Name")

                # Check for stopped instances
                if state == "stopped":
                    # Calculate how long it's been stopped
                    from datetime import datetime

                    now = datetime.now(UTC)
                    if launch_time:
                        age_days = (now - launch_time).days
                    else:
                        age_days = 0

                    cost = self._estimate_ec2_cost(instance_type) if verbose else 0.0

                    finding = self._create_finding(
                        region=region,
                        service="ec2",
                        resource_id=instance_id,
                        resource_type="instance",
                        severity=Severity.MEDIUM,
                        title="Stopped EC2 instance",
                        description=f"EC2 instance {instance_id} ({instance_type}) is stopped",
                        evidence=f"Instance state: stopped; Launched: {launch_time}; Age: ~{age_days} days",
                        cost=cost,
                        confidence=Confidence.HIGH
                        if age_days > 30
                        else Confidence.MEDIUM,
                        metadata={
                            "instance_type": instance_type,
                            "state": state,
                            "age_days": age_days,
                            "name": name,
                        },
                    )
                    findings.append(finding)

                # Check for old/stale instances (launched more than 90 days ago with no tags)
                if launch_time:
                    from datetime import datetime

                    now = datetime.now(UTC)
                    days_since_launch = (now - launch_time).days
                    if days_since_launch > 90:
                        has_name = name is not None and name != ""
                        if not has_name or age_days > 180:
                            cost = (
                                self._estimate_ec2_cost(instance_type)
                                if verbose
                                else 0.0
                            )
                            finding = self._create_finding(
                                region=region,
                                service="ec2",
                                resource_id=instance_id,
                                resource_type="instance",
                                severity=Severity.LOW,
                                title="Old/stale EC2 instance",
                                description=f"EC2 instance {instance_id} ({instance_type}) is {days_since_launch} days old",
                                evidence=f"Launched {days_since_launch} days ago; Instance type: {instance_type}; Name: {name or 'unset'}",
                                cost=cost,
                                confidence=Confidence.LOW,
                                metadata={
                                    "instance_type": instance_type,
                                    "launch_time": str(launch_time),
                                    "age_days": days_since_launch,
                                    "name": name,
                                },
                            )
                            findings.append(finding)

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "AccessDenied":
                # AccessDenied: cannot describe instances; continue scan with empty results
                pass
            else:
                # Other AWS errors: propagate to CLI-level handler
                raise

        except Exception:
            # Non-AWS errors (e.g., configuration, unexpected) are logged
            # and the scan continues with no EC2 findings
            raise

        return findings

    @staticmethod
    def _get_tag_value(tags: list, key: str) -> str:
        """Get a tag value by key."""
        if not tags:
            return ""
        for tag in tags:
            if tag.get("Key") == key:
                return tag.get("Value", "")
        return ""

    @staticmethod
    def _estimate_ec2_cost(instance_type: str) -> float:
        """Estimate monthly EC2 cost for an instance type."""
        pricing = {
            "t3.nano": 0.000006,
            "t3.micro": 0.000008,
            "t3.small": 0.000018,
            "t3.medium": 0.000032,
            "t3.large": 0.000058,
            "t3.xlarge": 0.000116,
        }
        hourly = pricing.get(instance_type, 0.02)
        return round(hourly * 24 * 30, 2)
