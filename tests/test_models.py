"""Tests for CloudCostGuard finding models."""

from cloudcostguard.models.finding import Confidence, Finding, Severity


def test_finding_creation():
    """Test basic finding creation."""
    finding = Finding(
        service="ec2",
        resource_id="i-12345678",
        resource_type="instance",
        region="us-east-1",
        severity=Severity.HIGH,
        title="Test finding",
        description="A test finding",
        evidence="Test evidence",
        estimated_monthly_cost=10.50,
        currency="USD",
        confidence=Confidence.HIGH,
        metadata={"key": "value"},
    )
    
    assert finding.service == "ec2"
    assert finding.resource_id == "i-12345678"
    assert finding.severity == Severity.HIGH
    assert finding.title == "Test finding"
    assert finding.estimated_monthly_cost == 10.50
    assert finding.currency == "USD"
    assert finding.confidence == Confidence.HIGH
    assert finding.metadata == {"key": "value"}
    
    # Test to_dict conversion
    d = finding.to_dict()
    assert d["severity"] == "high"
    assert d["confidence"] == "high"
    
    # Test from_dict roundtrip
    finding2 = Finding.from_dict(d)
    assert finding2 == finding


def test_finding_defaults():
    """Test finding with default values."""
    finding = Finding(
        service="s3",
        resource_id="bucket-name",
        resource_type="bucket",
        region="us-east-1",
        severity=Severity.LOW,
        title="Low finding",
        description="A low severity finding",
    )
    
    assert finding.estimated_monthly_cost == 0.0
    assert finding.currency == "USD"
    assert finding.confidence == Confidence.MEDIUM
    assert finding.evidence == ""
    assert finding.metadata == {}


def test_severity_enum():
    """Test severity enum values."""
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"


def test_confidence_enum():
    """Test confidence enum values."""
    assert Confidence.HIGH.value == "high"
    assert Confidence.MEDIUM.value == "medium"
    assert Confidence.LOW.value == "low"
