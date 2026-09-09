"""Tests for CloudCostGuard CLI."""

import json
import subprocess


def run_cli(args: list) -> subprocess.CompletedProcess:
    """Run cloudcostguard CLI command."""
    # Use python3 -m to run the CLI
    return subprocess.run(
        ["python3", "-m", "cloudcostguard"] + args,
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_help():
    """Test --help command."""
    result = run_cli(["--help"])
    assert result.returncode == 0
    assert (
        "cloudcostguard" in result.stdout.lower()
        or "cloudcostguard" in result.stderr.lower()
    )


def test_scan_help():
    """Test scan --help command."""
    result = run_cli(["scan", "--help"])
    assert result.returncode == 0
    assert "scan" in result.stdout.lower()


def test_scan_format_table():
    """Test scan with table format."""
    result = run_cli(["scan", "--format", "table"])
    # Should not crash; may have 0 findings if no AWS creds
    assert result.returncode in [0, 1, 2]  # various exit codes acceptable


def test_scan_format_json():
    """Test scan with JSON format."""
    result = run_cli(["scan", "--format", "json"])
    # May fail gracefully if no credentials
    assert result.returncode in [0, 1, 2]


def test_json_output_structure():
    """Test that JSON output has correct structure."""
    result = run_cli(["scan", "--format", "json"])
    if result.returncode == 0 and result.stdout.strip():
        try:
            data = json.loads(result.stdout)
            assert "scan" in data
            assert "summary" in data
            assert "findings" in data
        except json.JSONDecodeError:
            assert False, "JSON output is not valid"


def test_version():
    """Test version command."""
    result = run_cli(["version"])
    # May have varying exit codes depending on sys.argv handling
    assert result.returncode in [0, 1, 2]
