 from __future__ import annotations
 
 import json
 from typing import Iterable
 
 from mlsecscan.core.finding import Finding
 
 
 def format_text(findings: Iterable[Finding], suppressed: int, applied: int, skipped: int) -> str:
     lines = []
     for finding in findings:
         loc = finding.location
         lines.append(
             f"[{finding.severity}/{finding.confidence}] {finding.rule_id}: {finding.title}"
         )
         lines.append(f"  Location: {loc.path}:{loc.line}:{loc.column}")
         lines.append(f"  Snippet: {loc.snippet}")
         lines.append(f"  Message: {finding.message}")
         lines.append(f"  Remediation: {finding.remediation}")
         if finding.references:
             lines.append("  References:")
             for ref in finding.references:
                 lines.append(f"    - {ref}")
         if finding.fix:
             lines.append("  Suggested Fix:")
             lines.append(f"    {finding.fix.description}")
             if finding.fix.diff:
                 lines.append("    Diff:")
                 for diff_line in finding.fix.diff.splitlines():
                     lines.append(f"      {diff_line}")
         lines.append("")
     lines.append(f"Suppressed findings: {suppressed}")
     lines.append(f"Auto-fixes applied: {applied}")
     lines.append(f"Auto-fixes skipped: {skipped}")
     return "\n".join(lines).strip() + "\n"
 
 
 def format_json(findings: Iterable[Finding], suppressed: int, applied: int, skipped: int) -> str:
    findings_list = list(findings)
     data = {
         "summary": {
            "count": len(findings_list),
             "suppressed": suppressed,
             "auto_fixes_applied": applied,
             "auto_fixes_skipped": skipped,
         },
        "findings": [
             {
                 "rule_id": finding.rule_id,
                 "title": finding.title,
                 "severity": finding.severity,
                 "confidence": finding.confidence,
                 "message": finding.message,
                 "location": {
                     "path": finding.location.path,
                     "line": finding.location.line,
                     "column": finding.location.column,
                     "snippet": finding.location.snippet,
                 },
                 "remediation": finding.remediation,
                 "references": finding.references,
                 "fix": (
                     {
                         "description": finding.fix.description,
                         "before": finding.fix.before,
                         "after": finding.fix.after,
                         "diff": finding.fix.diff,
                         "auto_applicable": finding.fix.auto_applicable,
                     }
                     if finding.fix
                     else None
                 ),
             }
            for finding in findings_list
         ],
     }
     return json.dumps(data, indent=2)
 
 
 def format_sarif(findings: Iterable[Finding]) -> str:
    findings_list = list(findings)
     rules = {}
     results = []
    for finding in findings_list:
         rules[finding.rule_id] = {
             "id": finding.rule_id,
             "name": finding.title,
             "shortDescription": {"text": finding.title},
             "fullDescription": {"text": finding.message},
             "help": {"text": finding.remediation},
             "properties": {
                 "severity": finding.severity,
                 "confidence": finding.confidence,
             },
         }
         loc = finding.location
         results.append(
             {
                 "ruleId": finding.rule_id,
                 "level": _sarif_level(finding.severity),
                 "message": {"text": finding.message},
                 "locations": [
                     {
                         "physicalLocation": {
                             "artifactLocation": {"uri": loc.path},
                             "region": {
                                 "startLine": loc.line,
                                 "startColumn": loc.column,
                                 "snippet": {"text": loc.snippet},
                             },
                         }
                     }
                 ],
             }
         )
     sarif = {
         "version": "2.1.0",
         "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
         "runs": [
             {
                 "tool": {
                     "driver": {
                         "name": "mlsecscan",
                         "informationUri": "https://example.com/mlsecscan",
                         "rules": list(rules.values()),
                     }
                 },
                 "results": results,
             }
         ],
     }
     return json.dumps(sarif, indent=2)
 
 
 def _sarif_level(severity: str) -> str:
     severity = severity.lower()
     if severity in {"critical", "high"}:
         return "error"
     if severity in {"medium"}:
         return "warning"
     return "note"
