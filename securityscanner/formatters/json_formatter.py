"""
JSON output formatter for machine-readable results.
"""

import json
from typing import Optional

from securityscanner.core.findings import Finding, ScanResult


class JSONFormatter:
    """
    Formats scan results as JSON for machine consumption.
    """
    
    def __init__(self, indent: int = 2, include_suppressed: bool = False):
        self.indent = indent
        self.include_suppressed = include_suppressed
    
    def format_result(self, result: ScanResult) -> str:
        """Format a complete scan result as JSON."""
        data = result.to_dict()
        
        # Filter suppressed findings if not included
        if not self.include_suppressed:
            data["findings"] = [
                f for f in data["findings"] 
                if not f.get("suppressed", False)
            ]
        
        return json.dumps(data, indent=self.indent, default=str)
    
    def format_finding(self, finding: Finding) -> str:
        """Format a single finding as JSON."""
        return json.dumps(finding.to_dict(), indent=self.indent, default=str)
    
    def format_findings(self, findings: list) -> str:
        """Format a list of findings as JSON."""
        data = [f.to_dict() for f in findings]
        
        if not self.include_suppressed:
            data = [f for f in data if not f.get("suppressed", False)]
        
        return json.dumps(data, indent=self.indent, default=str)
