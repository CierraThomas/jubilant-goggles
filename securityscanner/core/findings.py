"""
Finding data structures for the security scanner.

This module defines the core data structures used to represent
security findings, code quality issues, and their metadata.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
import json


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    def __lt__(self, other):
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)
    
    def __le__(self, other):
        return self == other or self < other


class Confidence(Enum):
    """Confidence levels for findings."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingCategory(Enum):
    """Categories of findings."""
    # Security categories
    INJECTION = "injection"
    XSS = "xss"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHY = "cryptography"
    SECRETS = "secrets"
    DESERIALIZATION = "deserialization"
    FILE_HANDLING = "file_handling"
    DEPENDENCY = "dependency"
    INFORMATION_LEAKAGE = "information_leakage"
    
    # Code quality categories
    COMPLEXITY = "complexity"
    DUPLICATION = "duplication"
    DEAD_CODE = "dead_code"
    NAMING = "naming"
    ERROR_HANDLING = "error_handling"
    RESOURCE_MANAGEMENT = "resource_management"
    CONCURRENCY = "concurrency"
    BEST_PRACTICES = "best_practices"


@dataclass
class CodeLocation:
    """Represents a location in source code."""
    file_path: str
    start_line: int
    end_line: int
    start_column: int = 0
    end_column: int = 0
    
    def __str__(self) -> str:
        return f"{self.file_path}:{self.start_line}"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_column": self.start_column,
            "end_column": self.end_column,
        }


@dataclass
class CodeSnippet:
    """A snippet of code with context."""
    code: str
    highlighted_line: int
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "highlighted_line": self.highlighted_line,
            "context_before": self.context_before,
            "context_after": self.context_after,
        }


@dataclass
class TaintFlow:
    """Represents a data flow from source to sink."""
    source: CodeLocation
    sink: CodeLocation
    path: List[CodeLocation] = field(default_factory=list)
    sanitizers: List[CodeLocation] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "path": [loc.to_dict() for loc in self.path],
            "sanitizers": [loc.to_dict() for loc in self.sanitizers],
        }


@dataclass
class Remediation:
    """Remediation information for a finding."""
    description: str
    fix_code: Optional[str] = None
    before_code: Optional[str] = None
    after_code: Optional[str] = None
    references: List[str] = field(default_factory=list)
    owasp_reference: Optional[str] = None
    cwe_id: Optional[str] = None
    auto_fixable: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "fix_code": self.fix_code,
            "before_code": self.before_code,
            "after_code": self.after_code,
            "references": self.references,
            "owasp_reference": self.owasp_reference,
            "cwe_id": self.cwe_id,
            "auto_fixable": self.auto_fixable,
        }


@dataclass
class Finding:
    """
    Represents a security or code quality finding.
    
    This is the core data structure returned by all analyzers and rules.
    """
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    category: FindingCategory
    location: CodeLocation
    snippet: Optional[CodeSnippet] = None
    taint_flow: Optional[TaintFlow] = None
    remediation: Optional[Remediation] = None
    language: str = "unknown"
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    suppressed: bool = False
    suppression_reason: Optional[str] = None
    
    def __post_init__(self):
        """Validate and normalize the finding."""
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        if isinstance(self.confidence, str):
            self.confidence = Confidence(self.confidence)
        if isinstance(self.category, str):
            self.category = FindingCategory(self.category)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to a dictionary."""
        result = {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category.value,
            "location": self.location.to_dict(),
            "language": self.language,
            "tags": self.tags,
            "metadata": self.metadata,
            "suppressed": self.suppressed,
        }
        
        if self.snippet:
            result["snippet"] = self.snippet.to_dict()
        if self.taint_flow:
            result["taint_flow"] = self.taint_flow.to_dict()
        if self.remediation:
            result["remediation"] = self.remediation.to_dict()
        if self.suppression_reason:
            result["suppression_reason"] = self.suppression_reason
            
        return result
    
    def to_json(self, indent: int = 2) -> str:
        """Convert finding to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Create a Finding from a dictionary."""
        location = CodeLocation(**data.pop("location"))
        
        snippet = None
        if "snippet" in data and data["snippet"]:
            snippet = CodeSnippet(**data.pop("snippet"))
        else:
            data.pop("snippet", None)
        
        taint_flow = None
        if "taint_flow" in data and data["taint_flow"]:
            tf_data = data.pop("taint_flow")
            taint_flow = TaintFlow(
                source=CodeLocation(**tf_data["source"]),
                sink=CodeLocation(**tf_data["sink"]),
                path=[CodeLocation(**p) for p in tf_data.get("path", [])],
                sanitizers=[CodeLocation(**s) for s in tf_data.get("sanitizers", [])],
            )
        else:
            data.pop("taint_flow", None)
        
        remediation = None
        if "remediation" in data and data["remediation"]:
            remediation = Remediation(**data.pop("remediation"))
        else:
            data.pop("remediation", None)
        
        return cls(
            location=location,
            snippet=snippet,
            taint_flow=taint_flow,
            remediation=remediation,
            **data
        )


@dataclass
class ScanResult:
    """Results from a complete scan."""
    findings: List[Finding]
    files_scanned: int
    scan_time_seconds: float
    languages_detected: List[str]
    rules_applied: List[str]
    errors: List[str] = field(default_factory=list)
    
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL and not f.suppressed)
    
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH and not f.suppressed)
    
    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM and not f.suppressed)
    
    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW and not f.suppressed)
    
    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO and not f.suppressed)
    
    @property
    def total_findings(self) -> int:
        return sum(1 for f in self.findings if not f.suppressed)
    
    @property
    def suppressed_count(self) -> int:
        return sum(1 for f in self.findings if f.suppressed)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": {
                "files_scanned": self.files_scanned,
                "scan_time_seconds": self.scan_time_seconds,
                "languages_detected": self.languages_detected,
                "rules_applied": self.rules_applied,
                "total_findings": self.total_findings,
                "suppressed_findings": self.suppressed_count,
                "by_severity": {
                    "critical": self.critical_count,
                    "high": self.high_count,
                    "medium": self.medium_count,
                    "low": self.low_count,
                    "info": self.info_count,
                },
            },
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
