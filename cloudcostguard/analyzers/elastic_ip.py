"""Elastic IP analyzer for CloudCostGuard."""

from __future__ import annotations

from typing import ClassVar

import boto3
from botocore.exceptions import ClientError, OperationNotPageableError

from cloudcostguard.analyzers.base import BaseAnalyzer, Confidence, Finding, Severity

# Approximate monthly pricing for Elastic IP (unassociated)
PRICING_ELASTIC_IP_MONTHLY = 0.005


class ElasticIPAnalyzer(BaseAnalyzer):
    """Analyzer for Elastic IPs."""

    name: str = "elastic_ip"
    services: ClassVar[tuple[str, ...]] = ("ec2",)

    def scan(self, region: str, verbose: bool = False) -> list[Finding]:
        """Scan Elastic IPs for unused/unassociated addresses."""
        findings: list[Finding] = []
        self.resources_scanned = 0

        try:
            client = boto3.client("ec2", region_name=region)

            # Describe addresses
            addresses = []
            try:
                paginator = client.get_paginator("describe_addresses")
                for page in paginator.paginate(PublicIp=False):
                    addresses.extend(page.get("Addresses", []))
            except ClientError:
                # Fallback: describe_addresses may fail; continue with empty results
                pass

            self.resources_scanned = len(addresses)

            for addr in addresses:
                alloc_id = addr.get("AllocationId", "unknown")
                public_ip = addr.get("PublicIp", "unknown")
                domain = addr.get("Domain", "unknown")
                instance_id = addr.get("InstanceId", "")
                network_interface_id = addr.get("NetworkInterfaceId", "")
                tag_set = addr.get("TagSet", [])

                # Check for unused/unassociated Elastic IP (no instance or ENI attached)
                if not instance_id and not network_interface_id:
                    cost = PRICING_ELASTIC_IP_MONTHLY if verbose else 0.0

                    # Get name tag
                    name = self._get_tag_value(tag_set, "Name")

                    finding = self._create_finding(
                        region=region,
                        service="ec2",
                        resource_id=alloc_id,
                        resource_type="elastic_ip",
                        severity=Severity.LOW,
                        title="Unused Elastic IP",
                        description=f"Elastic IP {alloc_id} ({public_ip}) is unassociated",
                        evidence=f"Domain: {domain}; No instance or network interface attached; Name: {name or 'unset'}",
                        cost=cost,
                        confidence=Confidence.HIGH,
                        metadata={
                            "allocation_id": alloc_id,
                            "public_ip": public_ip,
                            "domain": domain,
                            "instance_id": instance_id,
                            "network_interface_id": network_interface_id,
                            "name": name,
                        },
                    )
                    findings.append(finding)

        except (ClientError, OperationNotPageableError):
            # Fallback: describe_addresses may not be paginatable; continue with empty results
            pass

        return findings

    @staticmethod
    def _get_tag_value(tag_set: list, key: str) -> str:
        """Get a tag value by key."""
        if not tag_set:
            return ""
        for tag in tag_set:
            if tag.get("Key") == key:
                return tag.get("Value", "")
        return ""
