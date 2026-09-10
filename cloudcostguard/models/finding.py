"""Finding model for CloudCostGuard scan results."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """Confidence levels for findings."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Finding(BaseModel):
    """A finding from a CloudCostGuard analyzer."""

    service: str
    resource_id: str
    resource_type: str
    region: str
    severity: Severity
    title: str
    description: str
    evidence: str = ""
    estimated_monthly_cost: float = 0.0
    currency: str = "USD"
    confidence: Confidence = Confidence.MEDIUM
    recommendation: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    model_config = {"validate_by_name": True}

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary (for JSON serialization)."""
        d = self.model_dump(mode="json")
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Create Finding from dictionary."""
        data["severity"] = Severity(data["severity"])
        data["confidence"] = Confidence(data["confidence"])
        return cls(**data)
