"""
Python-specific analyzer for code quality analysis.
"""

import ast as python_ast
import re
from typing import List, Dict, Any, Optional, Set

from securityscanner.analyzers.base import (
    BaseAnalyzer, FunctionInfo, ClassInfo, VariableInfo, ImportInfo
)
from securityscanner.analyzers import register_analyzer
from securityscanner.parsers.base import ASTNode


@register_analyzer("python")
class PythonAnalyzer(BaseAnalyzer):
    """
    Python-specific analyzer using the built-in ast module.
    """
    
    @property
    def language(self) -> str:
        return "python"
    
    def extract_functions(self, ast: ASTNode, source: str) -> List[FunctionInfo]:
        """Extract function information from Python AST."""
        functions = []
        
        try:
            tree = python_ast.parse(source)
        except SyntaxError:
            return functions
        
        for node in python_ast.walk(tree):
            if isinstance(node, (python_ast.FunctionDef, python_ast.AsyncFunctionDef)):
                func_info = self._extract_function_info(node, source)
                functions.append(func_info)
        
        return functions
    
    def _extract_function_info(self, node, source: str) -> FunctionInfo:
        """Extract detailed function information."""
        start_line = node.lineno
        end_line = getattr(node, 'end_lineno', start_line)
        
        # Get parameter names
        params = []
        for arg in node.args.args:
            params.append(arg.arg)
        
        # Get decorators
        decorators = []
        for dec in node.decorator_list:
            if isinstance(dec, python_ast.Name):
                decorators.append(dec.id)
            elif isinstance(dec, python_ast.Attribute):
                decorators.append(dec.attr)
            elif isinstance(dec, python_ast.Call):
                if isinstance(dec.func, python_ast.Name):
                    decorators.append(dec.func.id)
        
        # Get function calls within this function
        calls = []
        for child in python_ast.walk(node):
            if isinstance(child, python_ast.Call):
                if isinstance(child.func, python_ast.Name):
                    calls.append(child.func.id)
                elif isinstance(child.func, python_ast.Attribute):
                    calls.append(child.func.attr)
        
        # Calculate complexity for this function
        complexity = self._calculate_function_complexity(node)
        
        return FunctionInfo(
            name=node.name,
            start_line=start_line,
            end_line=end_line,
            parameters=params,
            complexity=complexity,
            line_count=end_line - start_line + 1,
            is_async=isinstance(node, python_ast.AsyncFunctionDef),
            is_public=not node.name.startswith('_'),
            decorators=decorators,
            calls=calls,
        )
    
    def _calculate_function_complexity(self, node) -> int:
        """Calculate cyclomatic complexity for a function."""
        complexity = 1
        
        for child in python_ast.walk(node):
            if isinstance(child, (python_ast.If, python_ast.While, python_ast.For,
                                  python_ast.AsyncFor, python_ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, python_ast.BoolOp):
                # Each 'and' or 'or' adds complexity
                complexity += len(child.values) - 1
            elif isinstance(child, python_ast.comprehension):
                complexity += 1
                if child.ifs:
                    complexity += len(child.ifs)
        
        return complexity
    
    def extract_classes(self, ast: ASTNode, source: str) -> List[ClassInfo]:
        """Extract class information from Python AST."""
        classes = []
        
        try:
            tree = python_ast.parse(source)
        except SyntaxError:
            return classes
        
        for node in python_ast.walk(tree):
            if isinstance(node, python_ast.ClassDef):
                class_info = self._extract_class_info(node, source)
                classes.append(class_info)
        
        return classes
    
    def _extract_class_info(self, node, source: str) -> ClassInfo:
        """Extract detailed class information."""
        start_line = node.lineno
        end_line = getattr(node, 'end_lineno', start_line)
        
        # Get base classes
        bases = []
        for base in node.bases:
            if isinstance(base, python_ast.Name):
                bases.append(base.id)
            elif isinstance(base, python_ast.Attribute):
                bases.append(base.attr)
        
        # Get methods
        methods = []
        for child in node.body:
            if isinstance(child, (python_ast.FunctionDef, python_ast.AsyncFunctionDef)):
                methods.append(self._extract_function_info(child, source))
        
        return ClassInfo(
            name=node.name,
            start_line=start_line,
            end_line=end_line,
            methods=methods,
            bases=bases,
            is_public=not node.name.startswith('_'),
        )
    
    def extract_imports(self, ast: ASTNode, source: str) -> List[ImportInfo]:
        """Extract import information from Python AST."""
        imports = []
        
        try:
            tree = python_ast.parse(source)
        except SyntaxError:
            return imports
        
        for node in python_ast.walk(tree):
            if isinstance(node, python_ast.Import):
                for alias in node.names:
                    imports.append(ImportInfo(
                        module=alias.name,
                        names=[alias.asname or alias.name],
                        line=node.lineno,
                    ))
            elif isinstance(node, python_ast.ImportFrom):
                module = node.module or ""
                names = [alias.asname or alias.name for alias in node.names]
                imports.append(ImportInfo(
                    module=module,
                    names=names,
                    line=node.lineno,
                ))
        
        return imports
    
    def extract_variables(self, ast: ASTNode, source: str) -> List[VariableInfo]:
        """Extract variable information from Python AST."""
        variables = []
        
        try:
            tree = python_ast.parse(source)
        except SyntaxError:
            return variables
        
        for node in python_ast.walk(tree):
            if isinstance(node, python_ast.Assign):
                for target in node.targets:
                    if isinstance(target, python_ast.Name):
                        # Check if it's a constant (all uppercase)
                        is_const = target.id.isupper()
                        
                        # Get the assigned value as string
                        value = None
                        if isinstance(node.value, python_ast.Constant):
                            value = repr(node.value.value)
                        elif isinstance(node.value, python_ast.Name):
                            value = node.value.id
                        
                        variables.append(VariableInfo(
                            name=target.id,
                            line=node.lineno,
                            scope="global",  # Simplified - would need scope analysis
                            is_constant=is_const,
                            assigned_value=value,
                        ))
            elif isinstance(node, python_ast.AnnAssign):
                if isinstance(node.target, python_ast.Name):
                    variables.append(VariableInfo(
                        name=node.target.id,
                        line=node.lineno,
                        scope="global",
                        is_constant=node.target.id.isupper(),
                    ))
        
        return variables
    
    def find_dangerous_patterns(self, source: str) -> List[Dict[str, Any]]:
        """Find dangerous patterns in Python code."""
        patterns = []
        lines = source.splitlines()
        
        dangerous = [
            (r'\beval\s*\(', "Use of eval() - potential code injection"),
            (r'\bexec\s*\(', "Use of exec() - potential code injection"),
            (r'\b__import__\s*\(', "Use of __import__() - potential code injection"),
            (r'pickle\.loads?\s*\(', "Use of pickle - potential deserialization vulnerability"),
            (r'yaml\.load\s*\([^,]+\)', "Use of yaml.load without Loader - potential code execution"),
            (r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True', "Shell=True in subprocess - potential command injection"),
            (r'os\.system\s*\(', "Use of os.system() - potential command injection"),
            (r'tempfile\.mktemp\s*\(', "Use of mktemp - race condition vulnerability"),
            (r'assert\s+', "Use of assert for validation - can be disabled with -O"),
            (r'input\s*\(.*\)', "Use of input() - ensure proper validation"),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message in dangerous:
                if re.search(pattern, line):
                    patterns.append({
                        "line": line_num,
                        "pattern": pattern,
                        "message": message,
                        "code": line.strip(),
                    })
        
        return patterns
    
    def find_security_issues(self, source: str) -> List[Dict[str, Any]]:
        """Find common security issues in Python code."""
        issues = []
        lines = source.splitlines()
        
        # Hard-coded secrets patterns
        secret_patterns = [
            (r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']+["\']', "Hard-coded password"),
            (r'(?:api_key|apikey|api-key)\s*=\s*["\'][^"\']+["\']', "Hard-coded API key"),
            (r'(?:secret|token)\s*=\s*["\'][^"\']+["\']', "Hard-coded secret/token"),
            (r'(?:aws_access_key_id)\s*=\s*["\'][A-Z0-9]{20}["\']', "Hard-coded AWS access key"),
            (r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----', "Hard-coded private key"),
        ]
        
        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            for pattern, message in secret_patterns:
                if re.search(pattern, line_lower, re.IGNORECASE):
                    issues.append({
                        "line": line_num,
                        "type": "secret",
                        "message": message,
                        "code": line.strip()[:100],  # Truncate to avoid exposing secrets
                    })
        
        return issues
