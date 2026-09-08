# Contributing to CloudCostGuard

Thank you for considering contributing! This guide outlines how you can help improve CloudCostGuard.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/nvidia/CloudCostGuard.git
cd CloudCostGuard

# Install dependencies
pip install -e ".[dev]"

# Verify installation
cloudcostguard --help
```

## Coding Standards

- Follow the existing code style (PEP 8, black via ruff)
- Add type hints to all new functions
- Use docstrings for all public modules and functions
- Keep modules focused and small (one concern per module)
- Use the finding model consistently
- Document any pricing assumptions
- Write tests for new analyzers

## Testing

- Add tests for new analyzers using `moto` to mock AWS
- Ensure tests cover: normal resources, waste findings, empty accounts, API errors
- Run the full test suite: `pytest -q`
- Tests must not depend on real AWS credentials

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-analyzer`)
3. Implement your analyzer following the existing patterns
4. Add tests for your analyzer
5. Run `ruff check .` and `mypy .` to verify code quality
6. Commit your changes (`git commit -m 'Add amazing analyzer'`)
7. Push to your branch (`git push origin feature/amazing-analyzer`)
8. Open a Pull Request

## Adding a New Analyzer

1. Create a new file in `cloudcostguard/analyzers/` following the naming convention `xxx.py`
2. Implement a class inheriting from `BaseAnalyzer`
3. Implement the `scan(region, verbose)` method
4. Create findings using `self._create_finding()` from the base class
5. Add tests in `tests/test_xxx.py`
6. Update `pyproject.toml` if adding new dependencies
7. Update this contributing guide if needed

## Issue Reporting

- Use the issue tracker for bug reports and feature requests
- Include your AWS region and relevant resource details
- Do not include real credentials in issues
- Check existing issues before creating new ones
