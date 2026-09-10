"""Formatting utilities for CloudCostGuard."""

from __future__ import annotations


def format_currency(amount: float, currency: str = "USD") -> str:
    """Format a currency amount."""
    if amount == 0:
        return f"~{currency}~"
    return f"${amount:.2f} {currency}"


def format_bytes(size_bytes: float) -> str:
    """Format bytes into human-readable size."""
    if size_bytes == 0:
        return "0 B"
    name = ("B", "KB", "MB", "GB", "TB")
    i = 0
    while size_bytes >= 1024 and i < len(name) - 1:
        size_bytes /= 1024
        i += 1
    return f"{size_bytes:.1f} {name[i]}"


def format_duration(days: int) -> str:
    """Format duration in days to human-readable string."""
    if days == 0:
        return "0 days"
    if days < 30:
        return f"{days} days"
    months = days // 30
    remaining_days = days % 30
    if remaining_days == 0:
        return f"{months} months"
    return f"{months} months and {remaining_days} days"
