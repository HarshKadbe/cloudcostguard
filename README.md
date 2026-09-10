# CloudCostGuard

[![CI](https://github.com/HarshKadbe/cloudcostguard/actions/workflows/ci.yml/badge.svg)](https://github.com/HarshKadbe/cloudcostguard/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-yellow.svg)](https://www.apache.org/licenses/LICENSE-2.0)

AWS Cost & Waste Scanner CLI

## Description

CloudCostGuard is an open-source tool for identifying AWS resources that are unused, misconfigured, or likely wasting money. It helps developers, DevOps engineers, and AWS teams discover cost-saving opportunities across their AWS environment.

## Features

- **EC2 analyzer**: Detects stopped instances, stale instances, and low-activity instances
- **EBS analyzer**: Identifies unattached volumes and obviously stale volumes
- **Elastic IP analyzer**: Finds unused/unassociated Elastic IPs
- **S3 analyzer**: Detects potentially unused/empty buckets
- **Multiple output formats**: Table (terminal), JSON, and HTML reports
- **Configurable regions and services**: Scan specific regions and/or services
- **Approximate cost estimates**: Clearly labeled as estimates, not actual billing data
- **Read-only by default**: No resource modification or deletion

## Architecture

```
CloudCostGuard CLI
├── EC2 Analyzer
├── EBS Analyzer
├── Elastic IP Analyzer
└── S3 Analyzer

│
└── Reporting
    ├── Terminal (Rich-based table output)
    ├── JSON (machine-readable)
    └── HTML (standalone report)
```

## Installation

```bash
git clone https://github.com/HarshKadbe/cloudcostguard.git
cd cloudcostguard
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

## Quick Start

```bash
# Basic scan
cloudcostguard scan

# Scan specific region
cloudcostguard scan --region us-east-1

# Scan specific services
cloudcostguard scan --services ec2,s3

# JSON output
cloudcostguard scan --format json --output report.json

# HTML output
cloudcostguard scan --format html --output report.html

# Verbose mode with cost estimates
cloudcostguard scan --verbose

# Show version
cloudcostguard version
```

## AWS IAM Permissions

Minimum read-only policy required:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity",
                "ec2:DescribeInstances",
                "ec2:DescribeInstancesStatus",
                "ec2:DescribeVolumes",
                "ec2:DescribeAddresses",
                "ec2:DescribeTags",
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:ListBucket",
                "s3:ListBucketVersions"
            ],
            "Resource": "*"
        }
    ]
}
```

## CLI Examples

```bash
# Scan all services in us-east-1
cloudcostguard scan --region us-east-1

# Scan only EC2 and EBS
cloudcostguard scan --services ec2,ebs

# JSON output to file
cloudcostguard scan --format json --output findings.json

# HTML report
cloudcostguard scan --format html --output report.html

# Verbose mode with estimated costs
cloudcostguard scan --verbose

# Show version
cloudcostguard version
```

## JSON Output Example

```bash
$ cloudcostguard scan --format json
{
"scan": {
    "timestamp": "2024-01-15T10:30:00Z",
    "account_id": "123456789012",
    "regions": ["us-east-1"]
},
"summary": {
    "resources_scanned": 42,
    "potential_monthly_waste": 79.50
},
"findings": []
}
```

## Docker Usage

```bash
# Build
docker build -t cloudcostguard .

# Run with AWS profile
docker run --rm \
  -e AWS_PROFILE=default \
  -e AWS_DEFAULT_REGION=us-east-1 \
  cloudcostguard scan

# Run with access keys
docker run --rm \
  -e AWS_ACCESS_KEY_ID=AKIA... \
  -e AWS_SECRET_ACCESS_KEY=... \
  -e AWS_DEFAULT_REGION=us-east-1 \
  cloudcostguard scan
```

## GitHub Actions

```yaml
# Example workflow running CloudCostGuard
name: Cost Scan

on:
  schedule:
    cron: '0 2 * * *'  # Daily at 2 AM
  push:
    branches: [main]

jobs:
  cost-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      
      - name: Install dependencies
        run: |
          pip install -e ".[dev]"
      
      - name: Run CloudCostGuard
        run: cloudcostguard scan --format json --output cost-report.json
```

## Security

- Credentials are never stored in source code
- Uses boto3's standard credential chain (env vars, shared credentials, IAM roles)
- Default read-only mode - no resources are modified or deleted
- See SECURITY.md for details

## Cost Estimation Disclaimer

All cost values displayed by CloudCostGuard are **estimates only**. They are calculated from resource metadata using approximate pricing and should NOT be treated as actual AWS billing data.

- EC2 costs: estimated based on instance type hourly rate * 24 * 30 days
- EBS costs: estimated based on GB-monthly rate
- Elastic IP costs: based on AWS standard unassociated IP monthly fee
- S3 costs: not displayed as estimates vary greatly by storage class and region

Always review your actual AWS billing dashboard before making financial decisions.

## Development Setup

```bash
# Clone and install
git clone https://github.com/HarshKadbe/cloudcostguard.git
cd cloudcostguard
pip install -e ".[dev]"

# Run tests
pytest -q

# Lint check
ruff check .

# Type check
mypy .

# Run the CLI
cloudcostguard scan
```

## Testing

Tests use `moto` to mock AWS API calls. Every analyzer has test coverage for:

- Normal resources
- Waste findings
- Empty account
- AWS API errors
- Missing permissions
- Multiple regions

Run all tests: `pytest -q`

## Roadmap

| Version | Features |
|---------|----------|
| v0.1 | EC2, EBS, Elastic IP, S3, CLI, JSON, HTML, tests, Docker, CI |
| v0.2 | RDS, NAT Gateway, Load Balancer, CloudWatch utilization analysis |
| v0.3 | AWS Pricing API, Cost Explorer integration, better regional pricing |
| v0.4 | GitHub Action, PR cost comments |
| v0.5 | Multi-account support, AWS Organizations |

## Contributing

See CONTRIBUTING.md for development guidelines, coding standards, and pull request process.

## License

Apache-2.0