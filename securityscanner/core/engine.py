"""
Main scanning engine for the security scanner.

This module orchestrates the scanning process, coordinating between
parsers, analyzers, rules, and formatters.
"""

import os
import time
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed
import fnmatch

from securityscanner.core.findings import (
    Finding, ScanResult, Severity, CodeLocation
)
from securityscanner.core.rules import (
    Rule, RuleRegistry, RuleType, AnalysisContext, registry
)
from securityscanner.core.taint import TaintAnalyzer

# Import rules to register them with the registry
import securityscanner.rules  # noqa: F401


# Language detection by file extension
LANGUAGE_EXTENSIONS: Dict[str, List[str]] = {
    "python": [".py", ".pyw", ".pyi"],
    "javascript": [".js", ".mjs", ".cjs"],
    "typescript": [".ts", ".tsx"],
    "java": [".java"],
    "kotlin": [".kt", ".kts"],
    "go": [".go"],
    "ruby": [".rb", ".erb", ".rake"],
    "rust": [".rs"],
    "swift": [".swift"],
    "c": [".c", ".h"],
    "cpp": [".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx", ".h"],
    "csharp": [".cs"],
    "php": [".php"],
    "scala": [".scala"],
}

# Reverse mapping for quick lookup
EXTENSION_TO_LANGUAGE: Dict[str, str] = {}
for lang, exts in LANGUAGE_EXTENSIONS.items():
    for ext in exts:
        EXTENSION_TO_LANGUAGE[ext] = lang


# Default ignore patterns
DEFAULT_IGNORE_PATTERNS = [
    "node_modules/**",
    ".git/**",
    ".svn/**",
    "__pycache__/**",
    "*.pyc",
    ".tox/**",
    "venv/**",
    "env/**",
    ".venv/**",
    ".env/**",
    "vendor/**",
    "dist/**",
    "build/**",
    "target/**",
    "*.min.js",
    "*.bundle.js",
    ".idea/**",
    ".vscode/**",
    "coverage/**",
    ".coverage/**",
    "*.egg-info/**",
]


class ScanEngine:
    """
    Main scanning engine that orchestrates the analysis process.
    
    The engine:
    1. Discovers files in the target directory
    2. Detects languages based on file extensions
    3. Parses files using appropriate parsers
    4. Runs applicable rules on each file
    5. Collects and returns findings
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.registry = registry
        self.parsers: Dict[str, Any] = {}
        self.errors: List[str] = []
        
        # Configuration options
        self.max_file_size = self.config.get("max_file_size", 10 * 1024 * 1024)  # 10MB
        self.max_workers = self.config.get("max_workers", 4)
        self.ignore_patterns = self.config.get("ignore_patterns", DEFAULT_IGNORE_PATTERNS)
        self.include_patterns = self.config.get("include_patterns", None)
        self.severity_threshold = Severity(self.config.get("severity_threshold", "info"))
        self.enable_taint_analysis = self.config.get("enable_taint_analysis", True)
        self.rule_config = self.config.get("rules", {})
        
        # Apply rule configuration
        self._configure_rules()
    
    def _configure_rules(self):
        """Apply configuration to rules."""
        # Disable rules specified in config
        disabled_rules = self.rule_config.get("disabled", [])
        for rule_id in disabled_rules:
            self.registry.disable_rule(rule_id)
        
        # Enable rules specified in config
        enabled_rules = self.rule_config.get("enabled", [])
        for rule_id in enabled_rules:
            self.registry.enable_rule(rule_id)
    
    def detect_language(self, file_path: str) -> Optional[str]:
        """Detect the programming language of a file."""
        ext = os.path.splitext(file_path)[1].lower()
        return EXTENSION_TO_LANGUAGE.get(ext)
    
    def should_ignore(self, file_path: str, base_path: str) -> bool:
        """Check if a file should be ignored based on patterns."""
        rel_path = os.path.relpath(file_path, base_path)
        
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(os.path.basename(file_path), pattern):
                return True
        
        if self.include_patterns:
            included = False
            for pattern in self.include_patterns:
                if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(os.path.basename(file_path), pattern):
                    included = True
                    break
            if not included:
                return True
        
        return False
    
    def discover_files(self, target_path: str) -> Generator[str, None, None]:
        """Discover all files to scan in the target path."""
        target = Path(target_path)
        
        if target.is_file():
            yield str(target)
            return
        
        for root, dirs, files in os.walk(target):
            # Filter out ignored directories
            dirs[:] = [d for d in dirs if not self.should_ignore(os.path.join(root, d), target_path)]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                if self.should_ignore(file_path, target_path):
                    continue
                
                # Check file size
                try:
                    if os.path.getsize(file_path) > self.max_file_size:
                        continue
                except OSError:
                    continue
                
                # Only include files with recognized extensions
                if self.detect_language(file_path):
                    yield file_path
    
    def read_file(self, file_path: str) -> Optional[str]:
        """Read a file's contents."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception as e:
            self.errors.append(f"Error reading {file_path}: {str(e)}")
            return None
    
    def parse_file(self, file_path: str, content: str, language: str) -> Optional[Any]:
        """
        Parse a file into an AST.
        
        Returns the AST or None if parsing fails/not available.
        """
        # Import the appropriate parser
        try:
            from securityscanner.parsers import get_parser
            parser = get_parser(language)
            if parser:
                return parser.parse(content, file_path)
        except ImportError:
            pass
        except Exception as e:
            self.errors.append(f"Error parsing {file_path}: {str(e)}")
        
        return None
    
    def create_context(
        self,
        file_path: str,
        content: str,
        language: str,
        ast: Optional[Any] = None,
    ) -> AnalysisContext:
        """Create an analysis context for a file."""
        taint_analyzer = None
        if self.enable_taint_analysis:
            taint_analyzer = TaintAnalyzer(language, self.config)
        
        return AnalysisContext(
            file_path=file_path,
            content=content,
            language=language,
            ast=ast,
            taint_analyzer=taint_analyzer,
            config=self.config,
        )
    
    def scan_file(self, file_path: str) -> List[Finding]:
        """Scan a single file and return findings."""
        findings: List[Finding] = []
        
        # Read file
        content = self.read_file(file_path)
        if content is None:
            return findings
        
        # Detect language
        language = self.detect_language(file_path)
        if not language:
            return findings
        
        # Parse file (optional - some rules don't need AST)
        ast = self.parse_file(file_path, content, language)
        
        # Create analysis context
        context = self.create_context(file_path, content, language, ast)
        
        # Get applicable rules
        rules = self.registry.get_rules_for_language(language, config=self.rule_config)
        
        # Run each rule
        for rule in rules:
            try:
                for finding in rule.analyze(context):
                    # Set the language
                    finding.language = language
                    
                    # Check suppression
                    if context.is_line_suppressed(finding.location.start_line):
                        finding.suppressed = True
                        finding.suppression_reason = "Inline suppression comment"
                    
                    # Filter by severity threshold
                    if finding.severity >= self.severity_threshold:
                        findings.append(finding)
                        
            except Exception as e:
                self.errors.append(f"Error running rule {rule.metadata.rule_id} on {file_path}: {str(e)}")
        
        return findings
    
    def scan(self, target_path: str) -> ScanResult:
        """
        Scan a target path and return results.
        
        Args:
            target_path: Path to a file or directory to scan.
            
        Returns:
            ScanResult containing all findings and metadata.
        """
        start_time = time.time()
        all_findings: List[Finding] = []
        languages_detected: Set[str] = set()
        rules_applied: Set[str] = set()
        files_scanned = 0
        
        # Discover files
        files = list(self.discover_files(target_path))
        
        # Scan files (parallel if multiple)
        if len(files) > 1 and self.max_workers > 1:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {executor.submit(self.scan_file, f): f for f in files}
                
                for future in as_completed(futures):
                    file_path = futures[future]
                    try:
                        findings = future.result()
                        all_findings.extend(findings)
                        files_scanned += 1
                        
                        # Track languages
                        lang = self.detect_language(file_path)
                        if lang:
                            languages_detected.add(lang)
                            
                    except Exception as e:
                        self.errors.append(f"Error scanning {file_path}: {str(e)}")
        else:
            for file_path in files:
                try:
                    findings = self.scan_file(file_path)
                    all_findings.extend(findings)
                    files_scanned += 1
                    
                    lang = self.detect_language(file_path)
                    if lang:
                        languages_detected.add(lang)
                        
                except Exception as e:
                    self.errors.append(f"Error scanning {file_path}: {str(e)}")
        
        # Collect rules that were applied
        for finding in all_findings:
            rules_applied.add(finding.rule_id)
        
        # Sort findings by severity (critical first)
        all_findings.sort(key=lambda f: f.severity, reverse=True)
        
        elapsed_time = time.time() - start_time
        
        return ScanResult(
            findings=all_findings,
            files_scanned=files_scanned,
            scan_time_seconds=round(elapsed_time, 3),
            languages_detected=sorted(languages_detected),
            rules_applied=sorted(rules_applied),
            errors=self.errors,
        )
    
    def scan_content(self, content: str, language: str, file_path: str = "<stdin>") -> List[Finding]:
        """
        Scan code content directly without reading from a file.
        
        Useful for editor integrations and testing.
        """
        findings: List[Finding] = []
        
        # Parse content
        ast = self.parse_file(file_path, content, language)
        
        # Create context
        context = self.create_context(file_path, content, language, ast)
        
        # Get applicable rules
        rules = self.registry.get_rules_for_language(language, config=self.rule_config)
        
        # Run each rule
        for rule in rules:
            try:
                for finding in rule.analyze(context):
                    finding.language = language
                    
                    if context.is_line_suppressed(finding.location.start_line):
                        finding.suppressed = True
                        finding.suppression_reason = "Inline suppression comment"
                    
                    if finding.severity >= self.severity_threshold:
                        findings.append(finding)
                        
            except Exception as e:
                self.errors.append(f"Error running rule {rule.metadata.rule_id}: {str(e)}")
        
        return findings


def create_engine(config_path: Optional[str] = None, **kwargs) -> ScanEngine:
    """
    Create a scan engine with configuration.
    
    Args:
        config_path: Optional path to a configuration file.
        **kwargs: Additional configuration options.
        
    Returns:
        Configured ScanEngine instance.
    """
    config = {}
    
    if config_path:
        from securityscanner.config import load_config
        config = load_config(config_path)
    
    config.update(kwargs)
    
    return ScanEngine(config)
