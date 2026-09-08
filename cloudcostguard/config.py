"""CloudCostGuard configuration."""

from __future__ import annotations

import os
from functools import lru_cache

import boto3
from botocore.exceptions import ClientError


@lru_cache
def get_account_id() -> str | None:
    """Get AWS account ID using STS."""
    try:
        client = boto3.client("sts")
        return client.get_caller_identity()["Account"]
    except ClientError:
        return None


@lru_cache
def get_region() -> str | None:
    """Get default AWS region from environment or config."""
    return os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION")


@lru_cache
def get_profile() -> str | None:
    """Get AWS profile name."""
    return os.environ.get("AWS_PROFILE")


def is_readonly_mode() -> bool:
    """Check if the application is running in readonly mode."""
    return True
