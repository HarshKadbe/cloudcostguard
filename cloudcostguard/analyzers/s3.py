"""S3 analyzer for CloudCostGuard."""

from __future__ import annotations

from datetime import UTC
from typing import ClassVar

import boto3
from botocore.exceptions import ClientError

from cloudcostguard.analyzers.base import BaseAnalyzer, Confidence, Finding, Severity


class S3Analyzer(BaseAnalyzer):
    """Analyzer for S3 buckets."""

    name: str = "s3"
    services: ClassVar[tuple[str, ...]] = ("s3",)

    def scan(self, region: str, verbose: bool = False) -> list[Finding]:
        """Scan S3 buckets for potentially stale/unused buckets.

        Conditions that create findings:
        - Empty bucket: has_objects is False (no objects found via list_objects_v2)
        - Potentially unused bucket: has_objects is False AND days_since_activity > 365

        Note: Findings are based on object count from list_objects_v2 with MaxKeys=1.
        This is a single-object check, not a full inventory. No listing of common
        prefixes or I/O metrics is required or checked.

        AccessDenied errors are caught and the bucket is skipped (continue with
        other buckets). Other AWS errors may propagate to the CLI-level handler.
        """
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

                # Check bucket contents
                try:
                    # Check if bucket has any objects (single-object check)
                    objects_response = client.list_objects_v2(
                        Bucket=bucket_name, MaxKeys=1
                    )
                    has_objects = objects_response.get("KeyCount", 0) > 0
                    last_modified = None
                    if has_objects:
                        # Get the most recent object (single-object check)
                        objects = client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                        if objects.get("KeyCount", 0) > 0:
                            last_modified = objects.get("Contents", [{}])[0].get(
                                "LastModified"
                            )
                except ClientError:
                    # Cannot check bucket contents; skip this bucket
                    continue

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
                    # Determine severity based on bucket age and object status
                    if not has_objects and days_since_activity > 365:
                        # No objects AND very old: potentially unused
                        severity = Severity.MEDIUM
                        title = "Potentially unused S3 bucket"
                        description = (
                            f"S3 bucket {bucket_name} has no objects and is "
                            f"{days_since_activity} days old"
                        )
                        evidence = (
                            f"Bucket created: {creation_date}; No objects found; "
                            f"Last activity: {days_since_activity} days ago"
                        )
                        cost = 0.0  # S3 pricing varies too much to estimate precisely
                        confidence = Confidence.MEDIUM
                        recommendation = (
                            "Review bucket necessity and lifecycle policies"
                        )
                    elif not has_objects:
                        # No objects but recent: empty bucket
                        severity = Severity.LOW
                        title = "Empty S3 bucket"
                        description = f"S3 bucket {bucket_name} is empty"
                        evidence = f"Bucket created: {creation_date}; No objects found"
                        cost = 0.0
                        confidence = Confidence.LOW
                        recommendation = "Review if bucket is needed; consider lifecycle configuration"
                    else:
                        # Has objects but very old last modified
                        severity = Severity.LOW
                        title = "S3 bucket with old last activity"
                        description = (
                            f"S3 bucket {bucket_name} has objects but last activity was "
                            f"{days_since_activity} days ago"
                        )
                        evidence = f"Last object modified: {last_modified}; Bucket created: {creation_date}"
                        cost = 0.0
                        confidence = Confidence.LOW
                        recommendation = "Review bucket contents and lifecycle policies"

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
                            "creation_date": (
                                str(creation_date) if creation_date else "unknown"
                            ),
                            "days_since_activity": days_since_activity,
                            "owner_id": owner_id,
                        },
                    )
                    finding.recommendation = recommendation
                    findings.append(finding)

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "AccessDenied":
                # AccessDenied: cannot list buckets; continue with empty results
                pass
            else:
                # Other AWS errors: propagate to CLI-level handler
                raise

        except Exception:
            # Non-AWS errors: continue scan with no S3 findings
            raise

        return findings
