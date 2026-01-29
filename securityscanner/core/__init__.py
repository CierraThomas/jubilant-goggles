"""Core scanning engine and data structures."""

from securityscanner.core.findings import Finding, Severity, Confidence, FindingCategory
from securityscanner.core.engine import ScanEngine
from securityscanner.core.rules import Rule, RuleRegistry
from securityscanner.core.taint import TaintAnalyzer, TaintSource, TaintSink

__all__ = [
    "Finding",
    "Severity",
    "Confidence",
    "FindingCategory",
    "ScanEngine",
    "Rule",
    "RuleRegistry",
    "TaintAnalyzer",
    "TaintSource",
    "TaintSink",
]
