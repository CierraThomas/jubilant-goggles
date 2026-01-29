"""
Remediation engine for generating and applying security fixes.

This module provides:
- Secure code fix generation for detected vulnerabilities
- Before/after diff visualization
- Automatic fix application with dry-run support
- Security rationale and best practice references
"""

import os
import difflib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

from securityscanner.core.findings import Finding, Remediation, ScanResult


@dataclass
class FixResult:
    """Result of applying a fix."""
    finding: Finding
    success: bool
    original_code: str
    fixed_code: str
    diff: str
    error_message: Optional[str] = None
    file_path: str = ""
    line_number: int = 0


@dataclass
class RemediationPlan:
    """A plan for remediating findings in a codebase."""
    findings: List[Finding]
    fixes: List[FixResult]
    auto_fixable_count: int
    manual_fix_count: int
    total_findings: int
    
    @property
    def success_rate(self) -> float:
        """Calculate the success rate of applied fixes."""
        if not self.fixes:
            return 0.0
        successful = sum(1 for f in self.fixes if f.success)
        return successful / len(self.fixes)


class RemediationEngine:
    """
    Engine for generating and applying security remediations.
    
    The remediation engine:
    1. Analyzes findings and determines applicable fixes
    2. Generates secure code alternatives
    3. Creates before/after diffs
    4. Optionally applies fixes with dry-run support
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.dry_run = self.config.get("dry_run", True)
        self.backup = self.config.get("backup", True)
        self._file_cache: Dict[str, str] = {}
    
    def generate_remediation_plan(self, scan_result: ScanResult) -> RemediationPlan:
        """
        Generate a remediation plan for all findings.
        
        Args:
            scan_result: The result from a security scan.
            
        Returns:
            A RemediationPlan with all proposed fixes.
        """
        fixes = []
        auto_fixable = 0
        manual_fix = 0
        
        for finding in scan_result.findings:
            if finding.suppressed:
                continue
            
            if finding.remediation and finding.remediation.auto_fixable:
                auto_fixable += 1
                fix_result = self.generate_fix(finding)
                if fix_result:
                    fixes.append(fix_result)
            else:
                manual_fix += 1
        
        return RemediationPlan(
            findings=scan_result.findings,
            fixes=fixes,
            auto_fixable_count=auto_fixable,
            manual_fix_count=manual_fix,
            total_findings=len(scan_result.findings),
        )
    
    def generate_fix(self, finding: Finding) -> Optional[FixResult]:
        """
        Generate a fix for a single finding.
        
        Args:
            finding: The finding to fix.
            
        Returns:
            A FixResult with the proposed fix, or None if no fix is available.
        """
        if not finding.remediation:
            return None
        
        # Get the original code
        original_code = self._get_code_at_location(finding)
        if original_code is None:
            return FixResult(
                finding=finding,
                success=False,
                original_code="",
                fixed_code="",
                diff="",
                error_message="Could not read source file",
                file_path=finding.location.file_path,
                line_number=finding.location.start_line,
            )
        
        # Generate the fix
        fixed_code = self._apply_fix_pattern(finding, original_code)
        
        if fixed_code == original_code:
            return FixResult(
                finding=finding,
                success=False,
                original_code=original_code,
                fixed_code=fixed_code,
                diff="",
                error_message="No automatic fix available for this pattern",
                file_path=finding.location.file_path,
                line_number=finding.location.start_line,
            )
        
        # Generate diff
        diff = self._generate_diff(original_code, fixed_code, finding.location.file_path)
        
        return FixResult(
            finding=finding,
            success=True,
            original_code=original_code,
            fixed_code=fixed_code,
            diff=diff,
            file_path=finding.location.file_path,
            line_number=finding.location.start_line,
        )
    
    def apply_fixes(
        self, 
        fixes: List[FixResult], 
        dry_run: Optional[bool] = None
    ) -> List[FixResult]:
        """
        Apply fixes to the codebase.
        
        Args:
            fixes: List of fixes to apply.
            dry_run: If True, don't actually modify files. Overrides instance setting.
            
        Returns:
            List of FixResults with updated success status.
        """
        if dry_run is None:
            dry_run = self.dry_run
        
        results = []
        
        # Group fixes by file
        fixes_by_file: Dict[str, List[FixResult]] = {}
        for fix in fixes:
            if fix.success and fix.file_path:
                if fix.file_path not in fixes_by_file:
                    fixes_by_file[fix.file_path] = []
                fixes_by_file[fix.file_path].append(fix)
        
        # Apply fixes file by file
        for file_path, file_fixes in fixes_by_file.items():
            if dry_run:
                # In dry-run mode, just mark as success
                results.extend(file_fixes)
            else:
                # Sort fixes by line number (descending) to avoid offset issues
                file_fixes.sort(key=lambda f: f.line_number, reverse=True)
                
                try:
                    # Read the file
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Backup if configured
                    if self.backup:
                        backup_path = file_path + '.bak'
                        with open(backup_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                    
                    # Apply each fix
                    lines = content.splitlines(keepends=True)
                    
                    for fix in file_fixes:
                        try:
                            line_idx = fix.line_number - 1
                            if 0 <= line_idx < len(lines):
                                # Replace the line
                                lines[line_idx] = fix.fixed_code
                                if not lines[line_idx].endswith('\n'):
                                    lines[line_idx] += '\n'
                                results.append(fix)
                            else:
                                fix.success = False
                                fix.error_message = f"Line {fix.line_number} out of range"
                                results.append(fix)
                        except Exception as e:
                            fix.success = False
                            fix.error_message = str(e)
                            results.append(fix)
                    
                    # Write the modified file
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(''.join(lines))
                        
                except Exception as e:
                    for fix in file_fixes:
                        fix.success = False
                        fix.error_message = f"Error modifying file: {str(e)}"
                        results.append(fix)
        
        return results
    
    def _get_code_at_location(self, finding: Finding) -> Optional[str]:
        """Get the source code at a finding's location."""
        file_path = finding.location.file_path
        
        if file_path in self._file_cache:
            content = self._file_cache[file_path]
        else:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self._file_cache[file_path] = content
            except Exception:
                return None
        
        lines = content.splitlines()
        start = finding.location.start_line - 1
        end = finding.location.end_line
        
        if 0 <= start < len(lines):
            return '\n'.join(lines[start:end])
        
        return None
    
    def _apply_fix_pattern(self, finding: Finding, original_code: str) -> str:
        """Apply a fix pattern to the original code."""
        from securityscanner.remediation.fixers import get_fixer
        
        fixer = get_fixer(finding.rule_id)
        if fixer:
            return fixer.fix(original_code, finding)
        
        # Fallback: use the remediation's after_code if available
        if finding.remediation and finding.remediation.after_code:
            return finding.remediation.after_code
        
        return original_code
    
    def _generate_diff(self, original: str, fixed: str, file_path: str) -> str:
        """Generate a unified diff between original and fixed code."""
        original_lines = original.splitlines(keepends=True)
        fixed_lines = fixed.splitlines(keepends=True)
        
        diff = difflib.unified_diff(
            original_lines,
            fixed_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
        
        return ''.join(diff)
    
    def format_remediation_report(self, plan: RemediationPlan) -> str:
        """
        Format a remediation plan as a human-readable report.
        
        Args:
            plan: The remediation plan to format.
            
        Returns:
            A formatted string report.
        """
        lines = [
            "=" * 60,
            "REMEDIATION REPORT",
            "=" * 60,
            "",
            f"Total findings: {plan.total_findings}",
            f"Auto-fixable: {plan.auto_fixable_count}",
            f"Manual fix required: {plan.manual_fix_count}",
            "",
        ]
        
        if plan.fixes:
            lines.append("-" * 60)
            lines.append("PROPOSED FIXES")
            lines.append("-" * 60)
            
            for i, fix in enumerate(plan.fixes, 1):
                lines.append(f"\n[{i}] {fix.finding.title}")
                lines.append(f"    File: {fix.file_path}:{fix.line_number}")
                lines.append(f"    Severity: {fix.finding.severity.value}")
                
                if fix.success:
                    lines.append("    Status: Fix available")
                    
                    if fix.finding.remediation:
                        lines.append(f"    Explanation: {fix.finding.remediation.description}")
                    
                    lines.append("\n    Diff:")
                    for line in fix.diff.splitlines():
                        lines.append(f"    {line}")
                else:
                    lines.append(f"    Status: Manual fix required")
                    if fix.error_message:
                        lines.append(f"    Reason: {fix.error_message}")
                
                lines.append("")
        
        # Add findings that need manual remediation
        manual_findings = [
            f for f in plan.findings 
            if not f.suppressed and (not f.remediation or not f.remediation.auto_fixable)
        ]
        
        if manual_findings:
            lines.append("-" * 60)
            lines.append("MANUAL REMEDIATION REQUIRED")
            lines.append("-" * 60)
            
            for finding in manual_findings:
                lines.append(f"\n• {finding.title}")
                lines.append(f"  File: {finding.location.file_path}:{finding.location.start_line}")
                lines.append(f"  Severity: {finding.severity.value}")
                
                if finding.remediation:
                    lines.append(f"  Guidance: {finding.remediation.description}")
                    
                    if finding.remediation.references:
                        lines.append("  References:")
                        for ref in finding.remediation.references[:3]:
                            lines.append(f"    - {ref}")
        
        lines.append("\n" + "=" * 60)
        
        return '\n'.join(lines)
    
    def get_fix_rationale(self, finding: Finding) -> Dict[str, Any]:
        """
        Get a detailed security rationale for a fix.
        
        Returns a dictionary with:
        - explanation: Why this is a security issue
        - impact: What could happen if exploited
        - fix_description: How the fix addresses the issue
        - references: Links to security resources
        """
        rationale = {
            "explanation": finding.description,
            "impact": self._get_impact_description(finding),
            "fix_description": "",
            "references": [],
            "cwe_id": "",
            "owasp_id": "",
        }
        
        if finding.remediation:
            rationale["fix_description"] = finding.remediation.description
            rationale["references"] = finding.remediation.references
            rationale["cwe_id"] = finding.remediation.cwe_id or ""
            rationale["owasp_id"] = finding.remediation.owasp_reference or ""
        
        return rationale
    
    def _get_impact_description(self, finding: Finding) -> str:
        """Get a description of the potential impact of a vulnerability."""
        impacts = {
            "sql_injection": "Attackers could read, modify, or delete database data, bypass authentication, or execute system commands.",
            "command_injection": "Attackers could execute arbitrary system commands, potentially gaining full control of the server.",
            "xss": "Attackers could steal user sessions, perform actions on behalf of users, or redirect users to malicious sites.",
            "secrets": "Exposed credentials could allow unauthorized access to systems, data breaches, or lateral movement.",
            "deserialization": "Attackers could execute arbitrary code on the server, leading to complete system compromise.",
            "cryptography": "Weak cryptography could allow attackers to decrypt sensitive data or forge authentication tokens.",
        }
        
        category = finding.category.value
        return impacts.get(category, f"This {finding.severity.value} severity issue could compromise application security.")
