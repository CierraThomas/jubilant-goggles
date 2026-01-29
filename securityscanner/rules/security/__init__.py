"""
Security vulnerability detection rules.
"""

from securityscanner.rules.security import injection
from securityscanner.rules.security import xss
from securityscanner.rules.security import secrets
from securityscanner.rules.security import crypto
from securityscanner.rules.security import deserialization

__all__ = [
    "injection",
    "xss",
    "secrets",
    "crypto",
    "deserialization",
]
