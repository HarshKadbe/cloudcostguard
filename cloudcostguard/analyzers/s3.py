"""S3 analyzer for CloudCostGuard."""

from __future__ import annotations

from datetime import UTC
from typing import ClassVar

import boto3
import typer
from botocore.exceptions import ClientError

from cloudcostguard.analyzers.base import BaseAnalyzer, Confidence, Finding, Severity


class S3Analyzer(BaseAnalyzer):
    """Analyzer for S3 buckets."""

    name: str = "s3"
    services: ClassVar[tuple[str, ...]] = ("s3",)

    def scan(self, region: str, verbose: bool = False) -> list[Finding]:
        """Scan S3 buckets for potentially stale/unused buckets."""
        findings: list[Finding] = []
        self.resources_scanned = 0

        try:
            client = boto3.client("s3", region_name=region)

            # List buckets
            buckets = []
            response = client.list_buckets()
            buckets = response.get("Buckets", [])

            self.resources_scanned = len(buckets)

            for bucket in buckets:
                bucket_name = bucket.get("Name", "unknown")
                creation_date = bucket.get("CreationDate")
                owner_id = bucket.get("Owner", {}).get("ID", "")

                # Check for potentially stale buckets
                # A bucket is considered potentially stale if:
                # - It has no common prefixes (no folders/) suggesting no active uploads
                # - It was created more than 365 days ago
                # We need to check bucket contents/objects

                try:
                    # Check if bucket has any objects
                    objects_response = client.list_objects_v2(
                        Bucket=bucket_name, MaxKeys=1
                    )
                    has_objects = objects_response.get("KeyCount", 0) > 0
                    last_modified = None
                    if has_objects:
                        # Get the most recent object
                        objects = client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                        if objects.get("KeyCount", 0) > 0:
                            last_modified = objects.get("Contents", [{}])[0].get(
                                "LastModified"
                            )

                    days_since_activity = 0
                    if last_modified:
                        from datetime import datetime

                        now = datetime.now(UTC)
                        # Make aware if naive
                        lm = last_modified
                        if lm.tzinfo is None:
                            lm = lm.replace(tzinfo=UTC)
                        days_since_activity = (now - lm).days

                    # Bucket has no objects or very old last activity
                    if not has_objects or days_since_activity > 365:
                        # Determine severity based on bucket age and ownership
                        if days_since_activity > 365 and not has_objects:
                            severity = Severity.MEDIUM
                            title = "Potentially unused S3 bucket"
                            description = f"S3 bucket {bucket_name} has no objects and is {days_since_activity} days old"
                            evidence = f"Bucket created: {creation_date}; No objects found; Last activity: {days_since_activity} days ago"
                            cost = (
                                0.0  # S3 pricing varies too much to estimate precisely
                            )
                            confidence = Confidence.MEDIUM
                        elif not has_objects:
                            severity = Severity.LOW
                            title = "Empty S3 bucket"
                            description = f"S3 bucket {bucket_name} is empty"
                            evidence = (
                                f"Bucket created: {creation_date}; No objects found"
                            )
                            cost = 0.0
                            confidence = Confidence.LOW
                        else:
                            # Has objects but very old last modified
                            severity = Severity.LOW
                            title = "S3 bucket with old last activity"
                            description = f"S3 bucket {bucket_name} has objects but last activity was {days_since_activity} days ago"
                            evidence = f"Last object modified: {last_modified}; Bucket created: {creation_date}"
                            cost = 0.0
                            confidence = Confidence.LOW

                        finding = self._create_finding(
                            region=region,
                            service="s3",
                            resource_id=bucket_name,
                            resource_type="bucket",
                            severity=severity,
                            title=title,
                            description=description,
                            evidence=evidence,
                            cost=cost,
                            confidence=confidence,
                            metadata={
                                "bucket_name": bucket_name,
                                "creation_date": str(creation_date)
                                if creation_date
                                else "unknown",
                                "days_since_activity": days_since_activity,
                                "owner_id": owner_id,
                            },
                        )
                        findings.append(finding)

                except ClientError as e:
                    # May not have permissions to list objects
                    typer.echo(
                        f"Permission denied listing objects in {bucket_name}: {e}"
                    )
                    continue

        except ClientError as e:
            typer.echo(f"AWS Error scanning S3 in {region}: {e}")
            typer.echo(f"Error scanning S3 in {region}: {e}")

        return findings
