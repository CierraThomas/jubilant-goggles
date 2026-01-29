"""
Code complexity rules.

Detects functions that are too complex, too long, or have
too many parameters.
"""

import re
from typing import Generator, List, Dict, Any

from securityscanner.core.rules import (
    Rule, RuleMetadata, RuleType, AnalysisContext, rule
)
from securityscanner.core.findings import (
    Finding, Severity, Confidence, FindingCategory, CodeLocation, Remediation
)


@rule
class HighCyclomaticComplexityRule(Rule):
    """
    Detects functions with high cyclomatic complexity.
    
    Cyclomatic complexity measures the number of linearly independent
    paths through a function. High complexity indicates code that is
    hard to test and maintain.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="QUAL-CMPLX-001",
            name="High Cyclomatic Complexity",
            description="Detects functions with high cyclomatic complexity that may be difficult to test and maintain.",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=FindingCategory.COMPLEXITY,
            rule_type=RuleType.CODE_QUALITY,
            languages=["*"],
            tags=["complexity", "maintainability", "testing"],
            enabled_by_default=True,
        )
    
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.threshold = self.config.get("complexity_threshold", 10)
        self.high_threshold = self.config.get("high_complexity_threshold", 20)
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for high cyclomatic complexity."""
        functions = self._find_functions(context)
        
        for func in functions:
            complexity = self._calculate_complexity(func, context)
            
            if complexity >= self.high_threshold:
                severity = Severity.HIGH
            elif complexity >= self.threshold:
                severity = Severity.MEDIUM
            else:
                continue
            
            location = CodeLocation(
                file_path=context.file_path,
                start_line=func["start_line"],
                end_line=func["end_line"],
            )
            
            finding = self.create_finding(
                location=location,
                snippet=context.get_snippet(func["start_line"]),
                severity=severity,
                description=f"Function '{func['name']}' has cyclomatic complexity of {complexity} (threshold: {self.threshold}). Consider breaking it into smaller functions.",
                remediation=Remediation(
                    description="Reduce complexity by extracting methods, using early returns, replacing conditionals with polymorphism, or simplifying boolean expressions.",
                    references=[
                        "https://en.wikipedia.org/wiki/Cyclomatic_complexity",
                    ],
                ),
                metadata={"complexity": complexity, "function_name": func["name"]},
            )
            
            yield finding
    
    def _find_functions(self, context: AnalysisContext) -> List[Dict[str, Any]]:
        """Find all functions in the code."""
        functions = []
        lines = context.lines
        
        # Language-specific function patterns
        patterns = {
            "python": re.compile(r'^(\s*)(?:async\s+)?def\s+(\w+)\s*\('),
            "javascript": re.compile(r'^(\s*)(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))'),
            "java": re.compile(r'^(\s*)(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\('),
            "go": re.compile(r'^(\s*)func\s+(?:\([^)]+\)\s+)?(\w+)\s*\('),
            "ruby": re.compile(r'^(\s*)def\s+(\w+)'),
            "csharp": re.compile(r'^(\s*)(?:public|private|protected)?\s*(?:static|async)?\s*\w+\s+(\w+)\s*\('),
        }
        
        pattern = patterns.get(context.language, re.compile(r'^(\s*)(?:func|function|def)\s+(\w+)'))
        
        i = 0
        while i < len(lines):
            match = pattern.match(lines[i])
            if match:
                indent = len(match.group(1)) if match.group(1) else 0
                name = match.group(2) or (match.group(3) if len(match.groups()) > 2 else "anonymous")
                
                if name:
                    start_line = i + 1
                    end_line = self._find_function_end(lines, i, indent, context.language)
                    
                    functions.append({
                        "name": name,
                        "start_line": start_line,
                        "end_line": end_line,
                        "indent": indent,
                    })
                    
                    i = end_line - 1
            i += 1
        
        return functions
    
    def _find_function_end(self, lines: List[str], start_idx: int, start_indent: int, language: str) -> int:
        """Find the end of a function."""
        if language in ("python", "ruby"):
            # Indentation-based
            for i in range(start_idx + 1, len(lines)):
                line = lines[i]
                if line.strip() and not line.strip().startswith('#'):
                    indent = len(line) - len(line.lstrip())
                    if indent <= start_indent:
                        return i
            return len(lines)
        else:
            # Brace-based
            brace_count = 0
            found_first = False
            for i in range(start_idx, len(lines)):
                for char in lines[i]:
                    if char == '{':
                        brace_count += 1
                        found_first = True
                    elif char == '}':
                        brace_count -= 1
                
                if found_first and brace_count == 0:
                    return i + 1
            return len(lines)
    
    def _calculate_complexity(self, func: Dict[str, Any], context: AnalysisContext) -> int:
        """Calculate cyclomatic complexity for a function."""
        complexity = 1
        
        decision_patterns = [
            r'\bif\b',
            r'\belif\b',
            r'\belse\s+if\b',
            r'\bfor\b',
            r'\bwhile\b',
            r'\bcase\b',
            r'\bcatch\b',
            r'\bexcept\b',
            r'\?\s*.*\s*:',  # Ternary
            r'\band\b|\&\&',
            r'\bor\b|\|\|',
        ]
        
        for i in range(func["start_line"] - 1, func["end_line"]):
            if i < len(context.lines):
                line = context.lines[i]
                for pattern in decision_patterns:
                    complexity += len(re.findall(pattern, line, re.IGNORECASE))
        
        return complexity


@rule
class LongFunctionRule(Rule):
    """
    Detects functions that are too long.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="QUAL-CMPLX-002",
            name="Long Function",
            description="Detects functions that exceed the recommended line count.",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            category=FindingCategory.COMPLEXITY,
            rule_type=RuleType.CODE_QUALITY,
            languages=["*"],
            tags=["complexity", "maintainability", "readability"],
            enabled_by_default=True,
        )
    
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.threshold = self.config.get("max_function_lines", 50)
        self.high_threshold = self.config.get("high_function_lines", 100)
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for long functions."""
        functions = HighCyclomaticComplexityRule()._find_functions(context)
        
        for func in functions:
            line_count = func["end_line"] - func["start_line"] + 1
            
            if line_count >= self.high_threshold:
                severity = Severity.MEDIUM
            elif line_count >= self.threshold:
                severity = Severity.LOW
            else:
                continue
            
            location = CodeLocation(
                file_path=context.file_path,
                start_line=func["start_line"],
                end_line=func["end_line"],
            )
            
            finding = self.create_finding(
                location=location,
                snippet=context.get_snippet(func["start_line"]),
                severity=severity,
                description=f"Function '{func['name']}' is {line_count} lines long (threshold: {self.threshold}). Consider breaking it into smaller functions.",
                remediation=Remediation(
                    description="Extract logical blocks into separate functions. Each function should do one thing well.",
                ),
                metadata={"line_count": line_count, "function_name": func["name"]},
            )
            
            yield finding


@rule
class DeepNestingRule(Rule):
    """
    Detects deeply nested code blocks.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="QUAL-CMPLX-003",
            name="Deep Nesting",
            description="Detects code with excessive nesting depth.",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=FindingCategory.COMPLEXITY,
            rule_type=RuleType.CODE_QUALITY,
            languages=["*"],
            tags=["complexity", "readability", "nesting"],
            enabled_by_default=True,
        )
    
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.threshold = self.config.get("max_nesting_depth", 4)
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for deep nesting."""
        nesting_keywords = {'if', 'for', 'while', 'try', 'with', 'switch', 'case'}
        
        for line_num, line in enumerate(context.lines, start=1):
            stripped = line.strip()
            
            # Check for nesting keywords
            first_word = stripped.split()[0] if stripped.split() else ""
            first_word = first_word.rstrip(':({')
            
            if first_word.lower() in nesting_keywords:
                # Calculate nesting level
                if context.language in ("python", "ruby"):
                    # Indentation-based
                    indent = len(line) - len(line.lstrip())
                    nesting_level = indent // 4  # Assume 4-space indent
                else:
                    # Count braces in preceding lines
                    nesting_level = self._count_nesting_level(context.lines, line_num - 1)
                
                if nesting_level >= self.threshold:
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        description=f"Code at nesting level {nesting_level} (threshold: {self.threshold}). Deep nesting makes code hard to read and maintain.",
                        remediation=Remediation(
                            description="Reduce nesting by using early returns (guard clauses), extracting nested code to functions, or inverting conditions.",
                        ),
                        metadata={"nesting_level": nesting_level},
                    )
                    
                    yield finding
    
    def _count_nesting_level(self, lines: List[str], current_idx: int) -> int:
        """Count the nesting level at a given line."""
        level = 0
        
        for i in range(current_idx + 1):
            line = lines[i]
            level += line.count('{') - line.count('}')
        
        return max(0, level)


@rule
class TooManyParametersRule(Rule):
    """
    Detects functions with too many parameters.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="QUAL-CMPLX-004",
            name="Too Many Parameters",
            description="Detects functions with excessive number of parameters.",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            category=FindingCategory.COMPLEXITY,
            rule_type=RuleType.CODE_QUALITY,
            languages=["*"],
            tags=["complexity", "design", "parameters"],
            enabled_by_default=True,
        )
    
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.threshold = self.config.get("max_parameters", 5)
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for functions with too many parameters."""
        patterns = {
            "python": re.compile(r'def\s+(\w+)\s*\(([^)]*)\)'),
            "javascript": re.compile(r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function\s*)?\(([^)]*)\))'),
            "java": re.compile(r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\(([^)]*)\)'),
            "go": re.compile(r'func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(([^)]*)\)'),
        }
        
        pattern = patterns.get(context.language, re.compile(r'(?:func|function|def)\s+(\w+)\s*\(([^)]*)\)'))
        
        for line_num, line in enumerate(context.lines, start=1):
            match = pattern.search(line)
            if match:
                groups = [g for g in match.groups() if g]
                if len(groups) >= 2:
                    name = groups[0]
                    params_str = groups[-1]
                elif len(groups) == 1:
                    # Try to get params from the line
                    paren_match = re.search(r'\(([^)]*)\)', line)
                    if paren_match:
                        name = groups[0]
                        params_str = paren_match.group(1)
                    else:
                        continue
                else:
                    continue
                
                # Count parameters
                params = [p.strip() for p in params_str.split(',') if p.strip()]
                # Filter out 'self', 'this', 'cls' from count
                params = [p for p in params if p.split()[0] not in ('self', 'this', 'cls')]
                
                param_count = len(params)
                
                if param_count > self.threshold:
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        description=f"Function '{name}' has {param_count} parameters (threshold: {self.threshold}). Consider using a configuration object or reducing parameters.",
                        remediation=Remediation(
                            description="Group related parameters into an object or class. Use builder pattern for complex object construction.",
                        ),
                        metadata={"parameter_count": param_count, "function_name": name},
                    )
                    
                    yield finding


@rule
class LargeClassRule(Rule):
    """
    Detects classes that are too large.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="QUAL-CMPLX-005",
            name="Large Class",
            description="Detects classes that exceed the recommended size.",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=FindingCategory.COMPLEXITY,
            rule_type=RuleType.CODE_QUALITY,
            languages=["python", "javascript", "java", "csharp", "ruby", "kotlin"],
            tags=["complexity", "design", "class-size"],
            enabled_by_default=True,
        )
    
    def __init__(self, config: dict = None):
        super().__init__(config)
        self.max_lines = self.config.get("max_class_lines", 300)
        self.max_methods = self.config.get("max_class_methods", 20)
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for large classes."""
        class_pattern = re.compile(r'^(\s*)class\s+(\w+)')
        
        i = 0
        while i < len(context.lines):
            match = class_pattern.match(context.lines[i])
            if match:
                indent = len(match.group(1))
                name = match.group(2)
                start_line = i + 1
                
                # Find class end
                end_line = self._find_class_end(context.lines, i, indent, context.language)
                class_lines = end_line - start_line + 1
                
                # Count methods
                method_count = self._count_methods(context.lines, i, end_line - 1, context.language)
                
                issues = []
                if class_lines > self.max_lines:
                    issues.append(f"{class_lines} lines (max: {self.max_lines})")
                if method_count > self.max_methods:
                    issues.append(f"{method_count} methods (max: {self.max_methods})")
                
                if issues:
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=start_line,
                        end_line=end_line,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(start_line),
                        description=f"Class '{name}' is too large: {', '.join(issues)}. Consider splitting into smaller classes.",
                        remediation=Remediation(
                            description="Apply Single Responsibility Principle. Extract related methods into separate classes or modules.",
                        ),
                        metadata={
                            "class_name": name,
                            "line_count": class_lines,
                            "method_count": method_count,
                        },
                    )
                    
                    yield finding
                
                i = end_line
            i += 1
    
    def _find_class_end(self, lines: List[str], start_idx: int, start_indent: int, language: str) -> int:
        """Find the end of a class."""
        if language in ("python", "ruby"):
            for i in range(start_idx + 1, len(lines)):
                line = lines[i]
                if line.strip() and not line.strip().startswith('#'):
                    indent = len(line) - len(line.lstrip())
                    if indent <= start_indent:
                        return i
            return len(lines)
        else:
            brace_count = 0
            found_first = False
            for i in range(start_idx, len(lines)):
                for char in lines[i]:
                    if char == '{':
                        brace_count += 1
                        found_first = True
                    elif char == '}':
                        brace_count -= 1
                
                if found_first and brace_count == 0:
                    return i + 1
            return len(lines)
    
    def _count_methods(self, lines: List[str], start_idx: int, end_idx: int, language: str) -> int:
        """Count methods in a class."""
        method_patterns = {
            "python": re.compile(r'^\s+def\s+'),
            "javascript": re.compile(r'^\s+(?:async\s+)?(?:static\s+)?(?:get\s+|set\s+)?(\w+)\s*\([^)]*\)\s*{'),
            "java": re.compile(r'^\s+(?:public|private|protected)?\s*(?:static)?\s*\w+\s+\w+\s*\('),
            "csharp": re.compile(r'^\s+(?:public|private|protected)?\s*(?:static|async)?\s*\w+\s+\w+\s*\('),
        }
        
        pattern = method_patterns.get(language, re.compile(r'^\s+def\s+'))
        count = 0
        
        for i in range(start_idx, min(end_idx + 1, len(lines))):
            if pattern.match(lines[i]):
                count += 1
        
        return count
