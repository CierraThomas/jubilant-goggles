"""
Naming convention rules.

Enforces consistent naming conventions across code.
"""

import re
from typing import Generator, Dict, List

from securityscanner.core.rules import (
    Rule, RuleMetadata, RuleType, AnalysisContext, rule
)
from securityscanner.core.findings import (
    Finding, Severity, Confidence, FindingCategory, CodeLocation, Remediation
)


# Common naming patterns
NAMING_PATTERNS = {
    "snake_case": re.compile(r'^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$'),
    "camelCase": re.compile(r'^[a-z][a-zA-Z0-9]*$'),
    "PascalCase": re.compile(r'^[A-Z][a-zA-Z0-9]*$'),
    "SCREAMING_SNAKE_CASE": re.compile(r'^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$'),
    "kebab-case": re.compile(r'^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$'),
}


# Language-specific naming conventions
LANGUAGE_CONVENTIONS = {
    "python": {
        "function": "snake_case",
        "variable": "snake_case",
        "class": "PascalCase",
        "constant": "SCREAMING_SNAKE_CASE",
        "method": "snake_case",
        "module": "snake_case",
    },
    "javascript": {
        "function": "camelCase",
        "variable": "camelCase",
        "class": "PascalCase",
        "constant": "SCREAMING_SNAKE_CASE",
        "method": "camelCase",
    },
    "java": {
        "function": "camelCase",
        "variable": "camelCase",
        "class": "PascalCase",
        "constant": "SCREAMING_SNAKE_CASE",
        "method": "camelCase",
        "interface": "PascalCase",
    },
    "go": {
        "function": "camelCase",
        "exported_function": "PascalCase",
        "variable": "camelCase",
        "type": "PascalCase",
        "constant": "camelCase",
        "package": "lowercase",
    },
    "ruby": {
        "method": "snake_case",
        "variable": "snake_case",
        "class": "PascalCase",
        "constant": "SCREAMING_SNAKE_CASE",
        "module": "PascalCase",
    },
    "csharp": {
        "method": "PascalCase",
        "variable": "camelCase",
        "class": "PascalCase",
        "constant": "PascalCase",
        "interface": "PascalCase",
        "private_field": "_camelCase",
    },
}


@rule
class FunctionNamingRule(Rule):
    """
    Enforces function naming conventions.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="QUAL-NAME-001",
            name="Function Naming Convention",
            description="Enforces consistent function naming conventions.",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            category=FindingCategory.NAMING,
            rule_type=RuleType.CODE_QUALITY,
            languages=["python", "javascript", "java", "go", "ruby", "csharp"],
            tags=["naming", "style", "convention"],
            enabled_by_default=False,  # Naming rules are opt-in
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Check function naming conventions."""
        convention = LANGUAGE_CONVENTIONS.get(context.language, {}).get("function", "camelCase")
        pattern = NAMING_PATTERNS.get(convention)
        
        if not pattern:
            return
        
        func_patterns = {
            "python": re.compile(r'^\s*def\s+(\w+)\s*\('),
            "javascript": re.compile(r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\())'),
            "java": re.compile(r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\('),
            "go": re.compile(r'func\s+(?:\([^)]+\)\s+)?(\w+)\s*\('),
            "ruby": re.compile(r'def\s+(\w+)'),
            "csharp": re.compile(r'(?:public|private|protected)?\s*(?:static|async)?\s*\w+\s+(\w+)\s*\('),
        }
        
        func_pattern = func_patterns.get(context.language)
        if not func_pattern:
            return
        
        for line_num, line in enumerate(context.lines, start=1):
            match = func_pattern.match(line)
            if match:
                func_name = next((g for g in match.groups() if g), None)
                
                if func_name and not self._is_valid_name(func_name, pattern, context.language):
                    # Skip dunder methods in Python
                    if context.language == "python" and func_name.startswith("__") and func_name.endswith("__"):
                        continue
                    
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        description=f"Function '{func_name}' does not follow {convention} naming convention.",
                        remediation=Remediation(
                            description=f"Rename function to follow {convention} convention. Example: {self._suggest_name(func_name, convention)}",
                        ),
                        metadata={"function_name": func_name, "expected_convention": convention},
                    )
                    
                    yield finding
    
    def _is_valid_name(self, name: str, pattern: re.Pattern, language: str) -> bool:
        """Check if a name follows the convention."""
        # Allow names starting with underscore (private)
        if name.startswith('_'):
            name = name.lstrip('_')
        
        return bool(pattern.match(name))
    
    def _suggest_name(self, name: str, convention: str) -> str:
        """Suggest a corrected name."""
        # Remove leading underscores temporarily
        prefix = ""
        while name.startswith('_'):
            prefix += '_'
            name = name[1:]
        
        if convention == "snake_case":
            # Convert camelCase to snake_case
            name = re.sub(r'([A-Z])', r'_\1', name).lower().lstrip('_')
        elif convention == "camelCase":
            # Convert snake_case to camelCase
            parts = name.split('_')
            name = parts[0].lower() + ''.join(p.capitalize() for p in parts[1:])
        elif convention == "PascalCase":
            # Convert to PascalCase
            parts = re.split(r'[_\s]+', name)
            name = ''.join(p.capitalize() for p in parts)
        
        return prefix + name


@rule
class ClassNamingRule(Rule):
    """
    Enforces class naming conventions.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="QUAL-NAME-002",
            name="Class Naming Convention",
            description="Enforces consistent class naming conventions (PascalCase).",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            category=FindingCategory.NAMING,
            rule_type=RuleType.CODE_QUALITY,
            languages=["python", "javascript", "java", "ruby", "csharp", "kotlin"],
            tags=["naming", "style", "convention"],
            enabled_by_default=False,
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Check class naming conventions."""
        pattern = NAMING_PATTERNS["PascalCase"]
        class_pattern = re.compile(r'^\s*class\s+(\w+)')
        
        for line_num, line in enumerate(context.lines, start=1):
            match = class_pattern.match(line)
            if match:
                class_name = match.group(1)
                
                if not pattern.match(class_name):
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        description=f"Class '{class_name}' does not follow PascalCase naming convention.",
                        remediation=Remediation(
                            description=f"Rename class to follow PascalCase convention. Example: {self._to_pascal_case(class_name)}",
                        ),
                        metadata={"class_name": class_name},
                    )
                    
                    yield finding
    
    def _to_pascal_case(self, name: str) -> str:
        """Convert a name to PascalCase."""
        parts = re.split(r'[_\s]+', name)
        return ''.join(p.capitalize() for p in parts)


@rule
class ConstantNamingRule(Rule):
    """
    Enforces constant naming conventions.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="QUAL-NAME-003",
            name="Constant Naming Convention",
            description="Enforces consistent constant naming conventions (SCREAMING_SNAKE_CASE).",
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            category=FindingCategory.NAMING,
            rule_type=RuleType.CODE_QUALITY,
            languages=["python", "javascript", "java", "ruby", "csharp"],
            tags=["naming", "style", "convention"],
            enabled_by_default=False,
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Check constant naming conventions."""
        patterns = {
            "python": re.compile(r'^([A-Z_][A-Z0-9_]*)\s*=\s*(?:["\'\d]|True|False|None)'),
            "javascript": re.compile(r'^const\s+([A-Z_][A-Z0-9_]*)\s*='),
            "java": re.compile(r'(?:static\s+)?final\s+\w+\s+([A-Z_][A-Z0-9_]*)\s*='),
        }
        
        lang_pattern = patterns.get(context.language)
        
        if not lang_pattern:
            return
        
        # This rule checks that constants ARE using SCREAMING_SNAKE_CASE
        # We look for module-level assignments that look like constants
        
        for line_num, line in enumerate(context.lines, start=1):
            # Check if this looks like a constant assignment at module level
            if context.language == "python":
                # Skip if indented (not module level)
                if line.startswith(' ') or line.startswith('\t'):
                    continue
                
                # Check for assignment that looks like a constant but doesn't use SCREAMING_SNAKE_CASE
                assignment_match = re.match(r'^(\w+)\s*=\s*(?:["\'\d]|True|False|None)', line)
                if assignment_match:
                    name = assignment_match.group(1)
                    # If name has any lowercase letter but is all caps somewhere
                    if name.isupper() and '_' in name:
                        continue  # Already SCREAMING_SNAKE_CASE
                    
                    # This would flag things that might be constants but aren't named right
                    # For now, we'll skip this as it creates too many false positives


@rule
class VariableNamingRule(Rule):
    """
    Detects poorly named variables.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="QUAL-NAME-004",
            name="Poor Variable Name",
            description="Detects variables with non-descriptive names.",
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            category=FindingCategory.NAMING,
            rule_type=RuleType.CODE_QUALITY,
            languages=["*"],
            tags=["naming", "readability"],
            enabled_by_default=False,
        )
    
    # Common poor variable names
    POOR_NAMES = {
        'x', 'y', 'z', 'a', 'b', 'c', 'd', 'e', 'f', 'n', 'm',
        'tmp', 'temp', 'foo', 'bar', 'baz', 'qux',
        'data', 'val', 'value', 'item', 'thing', 'stuff',
        'result', 'res', 'ret', 'retval',
        'obj', 'object',
    }
    
    # Allow these in specific contexts
    ALLOWED_CONTEXTS = {
        'i': ['for', 'range', 'enumerate'],
        'j': ['for', 'range'],
        'k': ['for', 'range'],
        'e': ['except', 'catch', 'error'],
        '_': ['for', 'lambda'],
    }
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Check for poorly named variables."""
        patterns = {
            "python": re.compile(r'^\s*(\w+)\s*='),
            "javascript": re.compile(r'(?:const|let|var)\s+(\w+)\s*='),
            "java": re.compile(r'\b\w+\s+(\w+)\s*='),
        }
        
        pattern = patterns.get(context.language, re.compile(r'(\w+)\s*='))
        
        for line_num, line in enumerate(context.lines, start=1):
            match = pattern.search(line)
            if match:
                var_name = match.group(1)
                
                if var_name.lower() in self.POOR_NAMES:
                    # Check for allowed contexts
                    allowed = False
                    for allowed_name, allowed_contexts in self.ALLOWED_CONTEXTS.items():
                        if var_name.lower() == allowed_name:
                            if any(ctx in line.lower() for ctx in allowed_contexts):
                                allowed = True
                                break
                    
                    if not allowed:
                        location = CodeLocation(
                            file_path=context.file_path,
                            start_line=line_num,
                            end_line=line_num,
                        )
                        
                        finding = self.create_finding(
                            location=location,
                            snippet=context.get_snippet(line_num),
                            description=f"Variable '{var_name}' is not descriptive. Use meaningful names that describe the purpose.",
                            remediation=Remediation(
                                description="Use descriptive variable names that convey the purpose or content of the variable.",
                            ),
                            metadata={"variable_name": var_name},
                        )
                        
                        yield finding
