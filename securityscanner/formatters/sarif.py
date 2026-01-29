"""
SARIF output formatter for IDE integration.

SARIF (Static Analysis Results Interchange Format) is a standard
format for static analysis tool output, supported by many IDEs
and code review tools.
"""

import json
from typing import Dict, Any, List
from datetime import datetime

from securityscanner.core.findings import Finding, ScanResult, Severity


# SARIF severity mapping
SARIF_SEVERITY = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


class SARIFFormatter:
    """
    Formats scan results in SARIF format.
    
    SARIF is supported by:
    - GitHub Code Scanning
    - VS Code SARIF Viewer
    - Azure DevOps
    - Many other tools
    """
    
    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    
    def __init__(self, include_suppressed: bool = False):
        self.include_suppressed = include_suppressed
    
    def format_result(self, result: ScanResult) -> str:
        """Format a complete scan result in SARIF format."""
        sarif = {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [self._create_run(result)],
        }
        
        return json.dumps(sarif, indent=2)
    
    def _create_run(self, result: ScanResult) -> Dict[str, Any]:
        """Create a SARIF run object."""
        # Collect unique rules from findings
        rules = self._collect_rules(result.findings)
        
        return {
            "tool": self._create_tool(rules),
            "results": [
                self._create_result(finding)
                for finding in result.findings
                if self.include_suppressed or not finding.suppressed
            ],
            "invocations": [self._create_invocation(result)],
        }
    
    def _create_tool(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a SARIF tool object."""
        return {
            "driver": {
                "name": "SecurityScanner",
                "version": "1.0.0",
                "informationUri": "https://github.com/securityscanner",
                "rules": rules,
            }
        }
    
    def _collect_rules(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Collect unique rules from findings."""
        rules_seen = set()
        rules = []
        
        for finding in findings:
            if finding.rule_id not in rules_seen:
                rules_seen.add(finding.rule_id)
                rules.append(self._create_rule(finding))
        
        return rules
    
    def _create_rule(self, finding: Finding) -> Dict[str, Any]:
        """Create a SARIF rule object from a finding."""
        rule = {
            "id": finding.rule_id,
            "name": finding.title,
            "shortDescription": {
                "text": finding.title,
            },
            "fullDescription": {
                "text": finding.description,
            },
            "defaultConfiguration": {
                "level": SARIF_LEVEL.get(finding.severity, "warning"),
            },
            "properties": {
                "tags": finding.tags,
                "category": finding.category.value,
            },
        }
        
        if finding.remediation:
            rule["help"] = {
                "text": finding.remediation.description,
            }
            
            if finding.remediation.cwe_id:
                rule["properties"]["cwe"] = finding.remediation.cwe_id
            
            if finding.remediation.owasp_reference:
                rule["helpUri"] = finding.remediation.owasp_reference
        
        return rule
    
    def _create_result(self, finding: Finding) -> Dict[str, Any]:
        """Create a SARIF result object from a finding."""
        result = {
            "ruleId": finding.rule_id,
            "level": SARIF_LEVEL.get(finding.severity, "warning"),
            "message": {
                "text": finding.description,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.location.file_path,
                        },
                        "region": {
                            "startLine": finding.location.start_line,
                            "endLine": finding.location.end_line,
                            "startColumn": finding.location.start_column + 1,  # SARIF is 1-indexed
                            "endColumn": finding.location.end_column + 1,
                        },
                    },
                }
            ],
            "properties": {
                "confidence": finding.confidence.value,
                "language": finding.language,
            },
        }
        
        # Add code snippet if available
        if finding.snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": finding.snippet.code,
            }
        
        # Add suppression info
        if finding.suppressed:
            result["suppressions"] = [
                {
                    "kind": "inSource",
                    "justification": finding.suppression_reason or "Suppressed by inline comment",
                }
            ]
        
        # Add taint flow as code flows
        if finding.taint_flow:
            result["codeFlows"] = [self._create_code_flow(finding)]
        
        # Add fix if available
        if finding.remediation and finding.remediation.after_code:
            result["fixes"] = [
                {
                    "description": {
                        "text": finding.remediation.description,
                    },
                    "artifactChanges": [
                        {
                            "artifactLocation": {
                                "uri": finding.location.file_path,
                            },
                            "replacements": [
                                {
                                    "deletedRegion": {
                                        "startLine": finding.location.start_line,
                                        "endLine": finding.location.end_line,
                                    },
                                    "insertedContent": {
                                        "text": finding.remediation.after_code,
                                    },
                                }
                            ],
                        }
                    ],
                }
            ]
        
        return result
    
    def _create_code_flow(self, finding: Finding) -> Dict[str, Any]:
        """Create a SARIF code flow from a taint flow."""
        thread_flow_locations = []
        
        if finding.taint_flow:
            # Source
            thread_flow_locations.append({
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.taint_flow.source.file_path,
                        },
                        "region": {
                            "startLine": finding.taint_flow.source.start_line,
                        },
                    },
                    "message": {
                        "text": "Taint source: user input enters here",
                    },
                },
            })
            
            # Intermediate path
            for loc in finding.taint_flow.path:
                thread_flow_locations.append({
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": loc.file_path,
                            },
                            "region": {
                                "startLine": loc.start_line,
                            },
                        },
                    },
                })
            
            # Sink
            thread_flow_locations.append({
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.taint_flow.sink.file_path,
                        },
                        "region": {
                            "startLine": finding.taint_flow.sink.start_line,
                        },
                    },
                    "message": {
                        "text": "Taint sink: dangerous function called with tainted data",
                    },
                },
            })
        
        return {
            "threadFlows": [
                {
                    "locations": thread_flow_locations,
                }
            ],
        }
    
    def _create_invocation(self, result: ScanResult) -> Dict[str, Any]:
        """Create a SARIF invocation object."""
        return {
            "executionSuccessful": len(result.errors) == 0,
            "endTimeUtc": datetime.utcnow().isoformat() + "Z",
            "toolExecutionNotifications": [
                {
                    "message": {
                        "text": error,
                    },
                    "level": "error",
                }
                for error in result.errors
            ],
        }
