"""
Rule engine for the security scanner.

This module provides the base classes for defining security and code quality rules,
as well as the registry for managing and discovering rules.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Type, Set, Generator
from enum import Enum
import re

from securityscanner.core.findings import (
    Finding, Severity, Confidence, FindingCategory, CodeLocation, 
    CodeSnippet, Remediation
)


class RuleType(Enum):
    """Types of rules."""
    SECURITY = "security"
    CODE_QUALITY = "quality"
    BEST_PRACTICE = "best_practice"


@dataclass
class RuleMetadata:
    """Metadata for a rule."""
    rule_id: str
    name: str
    description: str
    severity: Severity
    confidence: Confidence
    category: FindingCategory
    rule_type: RuleType
    languages: List[str]
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None
    auto_fixable: bool = False
    enabled_by_default: bool = True


class Rule(ABC):
    """
    Base class for all security and code quality rules.
    
    Each rule is responsible for detecting a specific type of issue
    in source code. Rules can be language-specific or cross-language.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._enabled = self.metadata.enabled_by_default
    
    @property
    @abstractmethod
    def metadata(self) -> RuleMetadata:
        """Return rule metadata."""
        pass
    
    @abstractmethod
    def analyze(self, context: "AnalysisContext") -> Generator[Finding, None, None]:
        """
        Analyze the code and yield findings.
        
        Args:
            context: The analysis context containing parsed code and utilities.
            
        Yields:
            Finding objects for each detected issue.
        """
        pass
    
    def get_remediation(self, finding: Finding) -> Optional[Remediation]:
        """
        Get remediation information for a finding.
        
        Override this method to provide fix suggestions.
        """
        return None
    
    def is_enabled(self) -> bool:
        """Check if this rule is enabled."""
        return self._enabled
    
    def enable(self):
        """Enable this rule."""
        self._enabled = True
    
    def disable(self):
        """Disable this rule."""
        self._enabled = False
    
    def supports_language(self, language: str) -> bool:
        """Check if this rule supports a given language."""
        languages = self.metadata.languages
        return "*" in languages or language.lower() in [l.lower() for l in languages]
    
    def create_finding(
        self,
        location: CodeLocation,
        title: Optional[str] = None,
        description: Optional[str] = None,
        severity: Optional[Severity] = None,
        confidence: Optional[Confidence] = None,
        snippet: Optional[CodeSnippet] = None,
        remediation: Optional[Remediation] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Finding:
        """
        Create a finding using the rule's metadata as defaults.
        """
        return Finding(
            rule_id=self.metadata.rule_id,
            title=title or self.metadata.name,
            description=description or self.metadata.description,
            severity=severity or self.metadata.severity,
            confidence=confidence or self.metadata.confidence,
            category=self.metadata.category,
            location=location,
            snippet=snippet,
            remediation=remediation,
            language="unknown",  # Will be set by analyzer
            tags=tags or list(self.metadata.tags),
            metadata=metadata or {},
        )


class PatternRule(Rule):
    """
    A rule that uses regex patterns to detect issues.
    
    This is simpler but less accurate than AST-based rules.
    Use for simple pattern matching like hardcoded secrets.
    """
    
    @property
    @abstractmethod
    def patterns(self) -> List[re.Pattern]:
        """Return the regex patterns to match."""
        pass
    
    @property
    def exclude_patterns(self) -> List[re.Pattern]:
        """Return patterns that should exclude matches."""
        return []
    
    def analyze(self, context: "AnalysisContext") -> Generator[Finding, None, None]:
        """Analyze using pattern matching."""
        for line_num, line in enumerate(context.lines, start=1):
            for pattern in self.patterns:
                for match in pattern.finditer(line):
                    # Check exclusion patterns
                    excluded = False
                    for exclude in self.exclude_patterns:
                        if exclude.search(line):
                            excluded = True
                            break
                    
                    if not excluded:
                        location = CodeLocation(
                            file_path=context.file_path,
                            start_line=line_num,
                            end_line=line_num,
                            start_column=match.start(),
                            end_column=match.end(),
                        )
                        
                        snippet = context.get_snippet(line_num, context_lines=3)
                        
                        finding = self.create_finding(
                            location=location,
                            snippet=snippet,
                            metadata={"matched_text": match.group()},
                        )
                        
                        # Get remediation if available
                        remediation = self.get_remediation(finding)
                        if remediation:
                            finding.remediation = remediation
                        
                        yield finding


class ASTRule(Rule):
    """
    A rule that uses AST analysis to detect issues.
    
    This provides more accurate detection by understanding code structure.
    """
    
    @property
    def node_types(self) -> List[str]:
        """Return the AST node types this rule is interested in."""
        return []
    
    def visit_node(self, node: Any, context: "AnalysisContext") -> Generator[Finding, None, None]:
        """
        Visit an AST node and yield findings.
        
        Override this method to implement AST-based detection.
        """
        yield from []
    
    def analyze(self, context: "AnalysisContext") -> Generator[Finding, None, None]:
        """Analyze using AST traversal."""
        if not context.ast:
            return
        
        for node in context.traverse_ast(self.node_types):
            yield from self.visit_node(node, context)


class TaintRule(Rule):
    """
    A rule that uses taint analysis to detect data flow issues.
    
    This tracks user-controlled inputs (sources) to dangerous functions (sinks).
    """
    
    @property
    @abstractmethod
    def sources(self) -> List[str]:
        """Return the taint sources (user input functions)."""
        pass
    
    @property
    @abstractmethod
    def sinks(self) -> List[str]:
        """Return the taint sinks (dangerous functions)."""
        pass
    
    @property
    def sanitizers(self) -> List[str]:
        """Return functions that sanitize tainted data."""
        return []
    
    def analyze(self, context: "AnalysisContext") -> Generator[Finding, None, None]:
        """Analyze using taint tracking."""
        if not context.taint_analyzer:
            return
        
        flows = context.taint_analyzer.find_flows(
            sources=self.sources,
            sinks=self.sinks,
            sanitizers=self.sanitizers,
        )
        
        for flow in flows:
            yield from self.on_taint_flow(flow, context)
    
    def on_taint_flow(self, flow: Any, context: "AnalysisContext") -> Generator[Finding, None, None]:
        """
        Called when a taint flow is detected.
        
        Override to customize finding creation.
        """
        from securityscanner.core.findings import TaintFlow
        
        taint_flow = TaintFlow(
            source=flow.source_location,
            sink=flow.sink_location,
            path=flow.path,
            sanitizers=flow.sanitizers,
        )
        
        finding = self.create_finding(
            location=flow.sink_location,
            snippet=context.get_snippet(flow.sink_location.start_line),
        )
        finding.taint_flow = taint_flow
        
        yield finding


class RuleRegistry:
    """
    Registry for managing and discovering rules.
    
    Rules are registered by category and can be enabled/disabled
    based on configuration.
    """
    
    _instance: Optional["RuleRegistry"] = None
    
    def __init__(self):
        self._rules: Dict[str, Type[Rule]] = {}
        self._instances: Dict[str, Rule] = {}
        self._enabled_rules: Set[str] = set()
        self._disabled_rules: Set[str] = set()
    
    @classmethod
    def get_instance(cls) -> "RuleRegistry":
        """Get the singleton registry instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    @classmethod
    def reset(cls):
        """Reset the singleton instance."""
        cls._instance = None
    
    def register(self, rule_class: Type[Rule]) -> Type[Rule]:
        """
        Register a rule class.
        
        Can be used as a decorator:
        
        @registry.register
        class MyRule(Rule):
            ...
        """
        # Create a temporary instance to get the rule_id
        temp_instance = rule_class.__new__(rule_class)
        # Initialize with None config to get metadata
        if hasattr(rule_class, '__init__'):
            try:
                temp_instance.__init__(None)
            except:
                pass
        
        rule_id = temp_instance.metadata.rule_id
        self._rules[rule_id] = rule_class
        
        if temp_instance.metadata.enabled_by_default:
            self._enabled_rules.add(rule_id)
        
        return rule_class
    
    def get_rule(self, rule_id: str, config: Optional[Dict[str, Any]] = None) -> Optional[Rule]:
        """Get a rule instance by ID."""
        if rule_id not in self._rules:
            return None
        
        cache_key = f"{rule_id}:{hash(str(config))}"
        if cache_key not in self._instances:
            self._instances[cache_key] = self._rules[rule_id](config)
        
        return self._instances[cache_key]
    
    def get_rules_for_language(
        self, 
        language: str, 
        rule_type: Optional[RuleType] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> List[Rule]:
        """Get all enabled rules for a given language."""
        rules = []
        
        for rule_id, rule_class in self._rules.items():
            if rule_id in self._disabled_rules:
                continue
            
            rule = self.get_rule(rule_id, config)
            if rule and rule.supports_language(language):
                if rule_type is None or rule.metadata.rule_type == rule_type:
                    if rule.is_enabled():
                        rules.append(rule)
        
        return rules
    
    def get_all_rules(self, config: Optional[Dict[str, Any]] = None) -> List[Rule]:
        """Get all registered rules."""
        return [
            self.get_rule(rule_id, config)
            for rule_id in self._rules
        ]
    
    def enable_rule(self, rule_id: str):
        """Enable a rule by ID."""
        self._enabled_rules.add(rule_id)
        self._disabled_rules.discard(rule_id)
    
    def disable_rule(self, rule_id: str):
        """Disable a rule by ID."""
        self._disabled_rules.add(rule_id)
        self._enabled_rules.discard(rule_id)
    
    def enable_category(self, category: FindingCategory):
        """Enable all rules in a category."""
        for rule_id, rule_class in self._rules.items():
            rule = self.get_rule(rule_id)
            if rule and rule.metadata.category == category:
                self.enable_rule(rule_id)
    
    def disable_category(self, category: FindingCategory):
        """Disable all rules in a category."""
        for rule_id, rule_class in self._rules.items():
            rule = self.get_rule(rule_id)
            if rule and rule.metadata.category == category:
                self.disable_rule(rule_id)
    
    @property
    def rule_count(self) -> int:
        """Return the number of registered rules."""
        return len(self._rules)
    
    @property
    def enabled_rule_count(self) -> int:
        """Return the number of enabled rules."""
        return len(self._enabled_rules)


class AnalysisContext:
    """
    Context provided to rules during analysis.
    
    Contains the parsed code, utilities for traversing AST,
    and helpers for creating findings.
    """
    
    def __init__(
        self,
        file_path: str,
        content: str,
        language: str,
        ast: Optional[Any] = None,
        taint_analyzer: Optional[Any] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.file_path = file_path
        self.content = content
        self.language = language
        self.ast = ast
        self.taint_analyzer = taint_analyzer
        self.config = config or {}
        self._lines: Optional[List[str]] = None
        self._suppression_comments: Optional[Set[int]] = None
    
    @property
    def lines(self) -> List[str]:
        """Get the source code lines."""
        if self._lines is None:
            self._lines = self.content.splitlines()
        return self._lines
    
    @property
    def suppressed_lines(self) -> Set[int]:
        """Get line numbers that have suppression comments."""
        if self._suppression_comments is None:
            self._suppression_comments = set()
            suppression_patterns = [
                r"#\s*noqa",
                r"//\s*noqa",
                r"/\*\s*noqa",
                r"#\s*nosec",
                r"//\s*nosec",
                r"#\s*security-scanner-ignore",
                r"//\s*security-scanner-ignore",
            ]
            
            combined_pattern = re.compile("|".join(suppression_patterns), re.IGNORECASE)
            
            for i, line in enumerate(self.lines, start=1):
                if combined_pattern.search(line):
                    self._suppression_comments.add(i)
                    # Also suppress the next line for block comments
                    self._suppression_comments.add(i + 1)
        
        return self._suppression_comments
    
    def is_line_suppressed(self, line_number: int) -> bool:
        """Check if a line has a suppression comment."""
        return line_number in self.suppressed_lines
    
    def get_snippet(self, line_number: int, context_lines: int = 3) -> CodeSnippet:
        """Get a code snippet around a line number."""
        lines = self.lines
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        
        context_before = lines[start:line_number - 1]
        code = lines[line_number - 1] if line_number <= len(lines) else ""
        context_after = lines[line_number:end]
        
        return CodeSnippet(
            code=code,
            highlighted_line=line_number,
            context_before=context_before,
            context_after=context_after,
        )
    
    def traverse_ast(self, node_types: Optional[List[str]] = None) -> Generator[Any, None, None]:
        """
        Traverse the AST and yield nodes of the specified types.
        
        If node_types is None, yields all nodes.
        """
        if not self.ast:
            return
        
        def walk(node):
            if node is None:
                return
            
            node_type = getattr(node, 'type', None) or type(node).__name__
            
            if node_types is None or node_type in node_types:
                yield node
            
            # Handle different AST structures
            if hasattr(node, 'children'):
                for child in node.children:
                    yield from walk(child)
            elif hasattr(node, 'body'):
                body = node.body if isinstance(node.body, list) else [node.body]
                for child in body:
                    yield from walk(child)
        
        yield from walk(self.ast)


# Global registry instance
registry = RuleRegistry.get_instance()


def rule(cls: Type[Rule]) -> Type[Rule]:
    """
    Decorator to register a rule with the global registry.
    
    Usage:
        @rule
        class MyRule(Rule):
            ...
    """
    return registry.register(cls)
