"""
AI-powered remediation engine.

Provides secure code fixes, before/after diffs, and automatic
fix application capabilities.
"""

from securityscanner.remediation.engine import RemediationEngine
from securityscanner.remediation.fixers import BaseFixer, get_fixer

__all__ = [
    "RemediationEngine",
    "BaseFixer",
    "get_fixer",
]
