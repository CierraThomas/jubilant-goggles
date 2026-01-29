"""
Security and code quality rules.

This module contains all the rules for detecting security vulnerabilities
and code quality issues.
"""

# Import all rules to register them
from securityscanner.rules.security import injection, xss, secrets, crypto, deserialization
from securityscanner.rules.quality import complexity, naming, error_handling

__all__ = [
    "injection",
    "xss",
    "secrets",
    "crypto",
    "deserialization",
    "complexity",
    "naming",
    "error_handling",
]
