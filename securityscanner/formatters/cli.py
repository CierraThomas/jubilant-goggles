"""
CLI output formatter for human-readable results.
"""

from typing import Optional
import sys

from securityscanner.core.findings import Finding, ScanResult, Severity


# ANSI color codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    
    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"


def supports_color() -> bool:
    """Check if the terminal supports color output."""
    if not hasattr(sys.stdout, "isatty"):
        return False
    if not sys.stdout.isatty():
        return False
    return True


class CLIFormatter:
    """
    Formats scan results for human-readable CLI output.
    """
    
    def __init__(self, use_color: bool = True, verbose: bool = False):
        self.use_color = use_color and supports_color()
        self.verbose = verbose
    
    def _color(self, text: str, color: str) -> str:
        """Apply color to text if colors are enabled."""
        if self.use_color:
            return f"{color}{text}{Colors.RESET}"
        return text
    
    def _severity_color(self, severity: Severity) -> str:
        """Get the color for a severity level."""
        colors = {
            Severity.CRITICAL: Colors.BG_RED + Colors.WHITE,
            Severity.HIGH: Colors.RED,
            Severity.MEDIUM: Colors.YELLOW,
            Severity.LOW: Colors.BLUE,
            Severity.INFO: Colors.DIM,
        }
        return colors.get(severity, "")
    
    def _severity_label(self, severity: Severity) -> str:
        """Get a formatted severity label."""
        labels = {
            Severity.CRITICAL: "CRITICAL",
            Severity.HIGH: "HIGH",
            Severity.MEDIUM: "MEDIUM",
            Severity.LOW: "LOW",
            Severity.INFO: "INFO",
        }
        label = labels.get(severity, "UNKNOWN")
        return self._color(f"[{label}]", self._severity_color(severity))
    
    def format_result(self, result: ScanResult) -> str:
        """Format a complete scan result."""
        lines = []
        
        # Header
        lines.append("")
        lines.append(self._color("=" * 70, Colors.DIM))
        lines.append(self._color(" SECURITY SCAN RESULTS ", Colors.BOLD))
        lines.append(self._color("=" * 70, Colors.DIM))
        lines.append("")
        
        # Summary
        lines.append(self._color("Summary", Colors.BOLD))
        lines.append(self._color("-" * 40, Colors.DIM))
        lines.append(f"  Files scanned:     {result.files_scanned}")
        lines.append(f"  Languages:         {', '.join(result.languages_detected)}")
        lines.append(f"  Scan time:         {result.scan_time_seconds:.2f}s")
        lines.append(f"  Rules applied:     {len(result.rules_applied)}")
        lines.append("")
        
        # Findings summary
        lines.append(self._color("Findings", Colors.BOLD))
        lines.append(self._color("-" * 40, Colors.DIM))
        
        if result.total_findings == 0:
            lines.append(self._color("  No issues found!", Colors.GREEN))
        else:
            lines.append(f"  {self._severity_label(Severity.CRITICAL)} {result.critical_count}")
            lines.append(f"  {self._severity_label(Severity.HIGH)} {result.high_count}")
            lines.append(f"  {self._severity_label(Severity.MEDIUM)} {result.medium_count}")
            lines.append(f"  {self._severity_label(Severity.LOW)} {result.low_count}")
            lines.append(f"  {self._severity_label(Severity.INFO)} {result.info_count}")
            
            if result.suppressed_count > 0:
                lines.append(f"  Suppressed:        {result.suppressed_count}")
        
        lines.append("")
        
        # Detailed findings
        if result.total_findings > 0:
            lines.append(self._color("=" * 70, Colors.DIM))
            lines.append(self._color(" DETAILED FINDINGS ", Colors.BOLD))
            lines.append(self._color("=" * 70, Colors.DIM))
            lines.append("")
            
            # Group by file
            findings_by_file = {}
            for finding in result.findings:
                if finding.suppressed and not self.verbose:
                    continue
                file_path = finding.location.file_path
                if file_path not in findings_by_file:
                    findings_by_file[file_path] = []
                findings_by_file[file_path].append(finding)
            
            for file_path, findings in findings_by_file.items():
                lines.append(self._color(f"📁 {file_path}", Colors.CYAN))
                lines.append("")
                
                for finding in findings:
                    lines.extend(self._format_finding(finding))
                    lines.append("")
        
        # Errors
        if result.errors:
            lines.append(self._color("=" * 70, Colors.DIM))
            lines.append(self._color(" ERRORS ", Colors.RED))
            lines.append(self._color("=" * 70, Colors.DIM))
            for error in result.errors:
                lines.append(f"  • {error}")
            lines.append("")
        
        return "\n".join(lines)
    
    def _format_finding(self, finding: Finding) -> list:
        """Format a single finding."""
        lines = []
        
        # Title and location
        severity_label = self._severity_label(finding.severity)
        location = f"{finding.location.file_path}:{finding.location.start_line}"
        
        if finding.suppressed:
            title = self._color(f"[SUPPRESSED] {finding.title}", Colors.DIM)
        else:
            title = self._color(finding.title, Colors.BOLD)
        
        lines.append(f"  {severity_label} {title}")
        lines.append(f"  {self._color('Location:', Colors.DIM)} {location}")
        lines.append(f"  {self._color('Rule:', Colors.DIM)} {finding.rule_id}")
        
        # Description
        lines.append("")
        lines.append(f"  {finding.description}")
        
        # Code snippet
        if finding.snippet:
            lines.append("")
            lines.append(self._color("  Code:", Colors.DIM))
            
            # Context before
            for i, ctx_line in enumerate(finding.snippet.context_before[-3:]):
                line_num = finding.snippet.highlighted_line - len(finding.snippet.context_before[-3:]) + i
                lines.append(self._color(f"    {line_num:4} │ {ctx_line}", Colors.DIM))
            
            # Highlighted line
            lines.append(self._color(
                f"  → {finding.snippet.highlighted_line:4} │ {finding.snippet.code}",
                Colors.RED if finding.severity >= Severity.HIGH else Colors.YELLOW
            ))
            
            # Context after
            for i, ctx_line in enumerate(finding.snippet.context_after[:3]):
                line_num = finding.snippet.highlighted_line + 1 + i
                lines.append(self._color(f"    {line_num:4} │ {ctx_line}", Colors.DIM))
        
        # Taint flow
        if finding.taint_flow and self.verbose:
            lines.append("")
            lines.append(self._color("  Data Flow:", Colors.DIM))
            lines.append(f"    Source: {finding.taint_flow.source}")
            lines.append(f"    Sink:   {finding.taint_flow.sink}")
        
        # Remediation
        if finding.remediation:
            lines.append("")
            lines.append(self._color("  Remediation:", Colors.GREEN))
            lines.append(f"    {finding.remediation.description}")
            
            if finding.remediation.before_code and finding.remediation.after_code:
                lines.append("")
                lines.append(self._color("    Before:", Colors.DIM))
                lines.append(self._color(f"      {finding.remediation.before_code}", Colors.RED))
                lines.append(self._color("    After:", Colors.DIM))
                lines.append(self._color(f"      {finding.remediation.after_code}", Colors.GREEN))
            
            if finding.remediation.references and self.verbose:
                lines.append("")
                lines.append(self._color("    References:", Colors.DIM))
                for ref in finding.remediation.references[:3]:
                    lines.append(f"      • {ref}")
        
        lines.append(self._color("  " + "-" * 66, Colors.DIM))
        
        return lines
    
    def format_finding(self, finding: Finding) -> str:
        """Format a single finding."""
        return "\n".join(self._format_finding(finding))
    
    def format_progress(self, current: int, total: int, file_path: str) -> str:
        """Format a progress update."""
        percentage = (current / total) * 100 if total > 0 else 0
        bar_width = 30
        filled = int(bar_width * current / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_width - filled)
        
        return f"\r{self._color('[', Colors.DIM)}{bar}{self._color(']', Colors.DIM)} {percentage:5.1f}% {file_path[:40]:<40}"
