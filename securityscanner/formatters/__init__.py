"""
Output formatters for scan results.

Provides multiple output formats including:
- Human-readable CLI output
- JSON for machine processing
- SARIF for IDE integration
"""

from securityscanner.formatters.cli import CLIFormatter
from securityscanner.formatters.json_formatter import JSONFormatter
from securityscanner.formatters.sarif import SARIFFormatter

__all__ = [
    "CLIFormatter",
    "JSONFormatter",
    "SARIFFormatter",
]


def get_formatter(format_name: str):
    """Get a formatter by name."""
    formatters = {
        "text": CLIFormatter,
        "cli": CLIFormatter,
        "json": JSONFormatter,
        "sarif": SARIFFormatter,
    }
    
    formatter_class = formatters.get(format_name.lower())
    if formatter_class:
        return formatter_class()
    
    raise ValueError(f"Unknown format: {format_name}")
