"""AWS client abstraction for CloudCostGuard."""

from __future__ import annotations

from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class AWSClient:
    """Wrapper for boto3 clients with error handling and credential resolution."""

    def __init__(
        self,
        service: str,
        region: str | None = None,
        profile: str | None = None,
    ):
        self.service = service
        self.region = region
        self.profile = profile
        self._client = None

    @property
    def client(self):
        """Lazy-initialize and return the boto3 client."""
        if self._client is None:
            kwargs = {}
            if self.region:
                kwargs["region_name"] = self.region
            if self.profile:
                kwargs["profile_name"] = self.profile
            self._client = boto3.client(self.service, **kwargs)
        return self._client

    def call(self, operation: str, **params) -> Any:
        """Make a boto3 API call with error handling."""
        try:
            return getattr(self.client, operation)(**params)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            raise AWSError(
                error_code=error_code,
                message=e.response.get("Error", {}).get("Message", str(e)),
                original_error=e,
            )
        except BotoCoreError as e:
            raise AWSError(
                error_code="BotoCoreError",
                message=str(e),
                original_error=e,
            )

    def list_resources(
        self, paginator_name: str = "paginator", **kwargs
    ) -> list[dict[str, Any]]:
        """List resources using a paginator if available."""
        client = self.client
        if hasattr(client, f"{paginator_name}"):
            paginator = client.get_paginator(paginator_name)
            pages = paginator.paginate(**kwargs)
            resources = []
            for page in pages:
                resources.extend(page)
            return resources
        else:
            result = (
                client.list_objects_v2(**kwargs)
                if "MaxKeys" in kwargs
                else client.list_objects(**kwargs)
            )
            return result.get("Contents", []) if isinstance(result, dict) else []

    def describe_resource(self, resource_id: str, **kwargs) -> dict[str, Any] | None:
        """Describe a specific resource by ID."""
        try:
            caller = getattr(self.client, f"describe_{self.service}_resource_by_id")
            return caller(ResourceId=resource_id, **kwargs)
        except (ClientError, AttributeError):
            return None


AWSError = ClientError
