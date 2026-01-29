"""
Base analyzer class for language-specific analysis.

Analyzers provide additional analysis capabilities beyond
pattern matching, such as:
- Complexity analysis
- Dead code detection
- Variable tracking
- Scope analysis
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
import re

from securityscanner.parsers.base import ASTNode


@dataclass
class FunctionInfo:
    """Information about a function."""
    name: str
    start_line: int
    end_line: int
    parameters: List[str]
    complexity: int = 1
    line_count: int = 0
    is_async: bool = False
    is_public: bool = True
    decorators: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)


@dataclass
class ClassInfo:
    """Information about a class."""
    name: str
    start_line: int
    end_line: int
    methods: List[FunctionInfo]
    bases: List[str] = field(default_factory=list)
    is_public: bool = True


@dataclass
class VariableInfo:
    """Information about a variable."""
    name: str
    line: int
    scope: str  # global, local, class
    is_used: bool = False
    is_constant: bool = False
    assigned_value: Optional[str] = None


@dataclass
class ImportInfo:
    """Information about an import."""
    module: str
    names: List[str]
    line: int
    is_used: bool = False


class BaseAnalyzer(ABC):
    """
    Base class for language-specific analyzers.
    
    Analyzers extract semantic information from code that can be
    used for code quality analysis, such as:
    - Function complexity
    - Variable usage tracking
    - Dead code detection
    - Dependency analysis
    """
    
    @property
    @abstractmethod
    def language(self) -> str:
        """Return the language this analyzer handles."""
        pass
    
    def analyze(self, ast: ASTNode, source: str) -> Dict[str, Any]:
        """
        Perform full analysis on the code.
        
        Returns a dictionary with analysis results.
        """
        return {
            "functions": self.extract_functions(ast, source),
            "classes": self.extract_classes(ast, source),
            "imports": self.extract_imports(ast, source),
            "variables": self.extract_variables(ast, source),
            "complexity": self.calculate_complexity(ast, source),
        }
    
    @abstractmethod
    def extract_functions(self, ast: ASTNode, source: str) -> List[FunctionInfo]:
        """Extract function information from the AST."""
        pass
    
    @abstractmethod
    def extract_classes(self, ast: ASTNode, source: str) -> List[ClassInfo]:
        """Extract class information from the AST."""
        pass
    
    @abstractmethod
    def extract_imports(self, ast: ASTNode, source: str) -> List[ImportInfo]:
        """Extract import information from the AST."""
        pass
    
    @abstractmethod
    def extract_variables(self, ast: ASTNode, source: str) -> List[VariableInfo]:
        """Extract variable information from the AST."""
        pass
    
    def calculate_complexity(self, ast: ASTNode, source: str) -> Dict[str, int]:
        """
        Calculate code complexity metrics.
        
        Returns a dictionary with complexity metrics.
        """
        return {
            "cyclomatic": self.calculate_cyclomatic_complexity(ast, source),
            "cognitive": self.calculate_cognitive_complexity(ast, source),
            "lines_of_code": len(source.splitlines()),
            "function_count": len(self.extract_functions(ast, source)),
            "class_count": len(self.extract_classes(ast, source)),
        }
    
    def calculate_cyclomatic_complexity(self, ast: ASTNode, source: str) -> int:
        """
        Calculate cyclomatic complexity.
        
        Cyclomatic complexity = E - N + 2P
        Simplified: count decision points + 1
        """
        complexity = 1
        
        # Decision point patterns (language-agnostic)
        decision_patterns = [
            r'\bif\b',
            r'\belif\b',
            r'\belse\s+if\b',
            r'\bfor\b',
            r'\bwhile\b',
            r'\bcase\b',
            r'\bcatch\b',
            r'\bexcept\b',
            r'\b\?\s*:',  # ternary
            r'\band\b|\&\&',
            r'\bor\b|\|\|',
        ]
        
        for pattern in decision_patterns:
            complexity += len(re.findall(pattern, source, re.IGNORECASE))
        
        return complexity
    
    def calculate_cognitive_complexity(self, ast: ASTNode, source: str) -> int:
        """
        Calculate cognitive complexity.
        
        Cognitive complexity measures how difficult code is to understand,
        accounting for nesting and breaks in linear flow.
        """
        complexity = 0
        lines = source.splitlines()
        nesting_level = 0
        
        nesting_keywords = {'if', 'elif', 'else', 'for', 'while', 'try', 'except', 'with', 'switch', 'case'}
        increment_keywords = {'if', 'elif', 'for', 'while', 'except', 'catch', 'case'}
        
        for line in lines:
            stripped = line.strip()
            
            # Update nesting level based on indentation changes
            indent = len(line) - len(line.lstrip())
            
            # Check for complexity-increasing structures
            for keyword in increment_keywords:
                if re.match(rf'^{keyword}\b', stripped):
                    complexity += 1 + nesting_level
                    break
            
            # Check for nesting changes
            for keyword in nesting_keywords:
                if re.match(rf'^{keyword}\b', stripped):
                    nesting_level = max(0, indent // 4)  # Assume 4-space indent
                    break
        
        return complexity
    
    def find_unused_imports(self, ast: ASTNode, source: str) -> List[ImportInfo]:
        """Find imports that are not used in the code."""
        imports = self.extract_imports(ast, source)
        unused = []
        
        for imp in imports:
            used = False
            for name in imp.names:
                # Check if the imported name is used anywhere in the source
                if re.search(rf'\b{re.escape(name)}\b', source):
                    used = True
                    break
            
            if not used:
                imp.is_used = False
                unused.append(imp)
        
        return unused
    
    def find_unused_variables(self, ast: ASTNode, source: str) -> List[VariableInfo]:
        """Find variables that are assigned but never used."""
        variables = self.extract_variables(ast, source)
        unused = []
        
        for var in variables:
            # Skip if it's a common ignore pattern
            if var.name.startswith('_'):
                continue
            
            # Count usages (excluding the assignment line)
            lines = source.splitlines()
            usage_count = 0
            
            for i, line in enumerate(lines, 1):
                if i == var.line:
                    continue
                if re.search(rf'\b{re.escape(var.name)}\b', line):
                    usage_count += 1
            
            if usage_count == 0:
                var.is_used = False
                unused.append(var)
        
        return unused
    
    def find_duplicate_code(self, ast: ASTNode, source: str, min_lines: int = 5) -> List[Dict[str, Any]]:
        """
        Find duplicate code blocks.
        
        Returns a list of duplicate blocks with their locations.
        """
        lines = source.splitlines()
        duplicates = []
        seen_blocks: Dict[str, List[int]] = {}
        
        # Use a sliding window to find duplicate blocks
        for i in range(len(lines) - min_lines + 1):
            block = '\n'.join(lines[i:i + min_lines])
            # Normalize whitespace
            normalized = re.sub(r'\s+', ' ', block.strip())
            
            if len(normalized) < 50:  # Skip small blocks
                continue
            
            if normalized in seen_blocks:
                seen_blocks[normalized].append(i + 1)
            else:
                seen_blocks[normalized] = [i + 1]
        
        # Collect duplicates
        for block, locations in seen_blocks.items():
            if len(locations) > 1:
                duplicates.append({
                    "lines": locations,
                    "count": len(locations),
                    "size": min_lines,
                })
        
        return duplicates
