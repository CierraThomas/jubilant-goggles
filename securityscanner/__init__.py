"""
Multi-Language Security Scanner

A comprehensive static analysis tool for security vulnerability detection,
code quality enforcement, and AI-powered remediation across modern software stacks.
"""

__version__ = "1.0.0"
__author__ = "Security Scanner Team"

from securityscanner.core.engine import ScanEngine
from securityscanner.core.findings import Finding, Severity, Confidence
from securityscanner.config import ScanConfig

__all__ = [
    "ScanEngine",
    "Finding",
    "Severity",
    "Confidence",
    "ScanConfig",
]
