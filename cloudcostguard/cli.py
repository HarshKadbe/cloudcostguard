"""CloudCostGuard CLI entry point."""

from __future__ import annotations

import sys

from cloudcostguard.cli_commands import app

# Set the app name so Typer can introspect it
app.__name__ = "cloudcostguard"


def run() -> None:
    """Run the CLI."""
    sys.exit(app())
