"""
JavaScript/TypeScript analyzer for code quality analysis.
"""

import re
from typing import List, Dict, Any, Optional

from securityscanner.analyzers.base import (
    BaseAnalyzer, FunctionInfo, ClassInfo, VariableInfo, ImportInfo
)
from securityscanner.analyzers import register_analyzer
from securityscanner.parsers.base import ASTNode


@register_analyzer("javascript")
@register_analyzer("typescript")
class JavaScriptAnalyzer(BaseAnalyzer):
    """
    JavaScript/TypeScript analyzer using regex-based parsing.
    """
    
    @property
    def language(self) -> str:
        return "javascript"
    
    def extract_functions(self, ast: ASTNode, source: str) -> List[FunctionInfo]:
        """Extract function information from JavaScript/TypeScript code."""
        functions = []
        lines = source.splitlines()
        
        # Match various function patterns
        patterns = [
            # Regular functions
            re.compile(r'^(\s*)(async\s+)?function\s+(\w+)\s*\(([^)]*)\)'),
            # Arrow functions
            re.compile(r'^(\s*)(const|let|var)\s+(\w+)\s*=\s*(async\s+)?(?:\([^)]*\)|\w+)\s*=>'),
            # Class methods
            re.compile(r'^(\s*)(async\s+)?(\w+)\s*\(([^)]*)\)\s*{'),
            # Object methods
            re.compile(r'^(\s*)(\w+)\s*:\s*(async\s+)?function\s*\(([^)]*)\)'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in patterns:
                match = pattern.match(line)
                if match:
                    groups = match.groups()
                    
                    # Extract function name and async status
                    name = None
                    is_async = False
                    params = []
                    
                    for g in groups:
                        if g and g.strip() == 'async':
                            is_async = True
                        elif g and re.match(r'^[a-zA-Z_]\w*$', g.strip()):
                            if g.strip() not in ('const', 'let', 'var', 'function', 'async'):
                                name = g.strip()
                        elif g and ',' in (g or ''):
                            params = [p.strip() for p in g.split(',') if p.strip()]
                    
                    if name:
                        # Find function end (simplified - count braces)
                        end_line = self._find_block_end(lines, line_num - 1)
                        
                        func_info = FunctionInfo(
                            name=name,
                            start_line=line_num,
                            end_line=end_line,
                            parameters=params,
                            complexity=self._calculate_function_complexity_range(lines, line_num - 1, end_line - 1),
                            line_count=end_line - line_num + 1,
                            is_async=is_async,
                            is_public=not name.startswith('_'),
                        )
                        functions.append(func_info)
                    break
        
        return functions
    
    def _find_block_end(self, lines: List[str], start_idx: int) -> int:
        """Find the end of a code block by counting braces."""
        brace_count = 0
        found_first = False
        
        for i in range(start_idx, len(lines)):
            line = lines[i]
            for char in line:
                if char == '{':
                    brace_count += 1
                    found_first = True
                elif char == '}':
                    brace_count -= 1
            
            if found_first and brace_count == 0:
                return i + 1
        
        return len(lines)
    
    def _calculate_function_complexity_range(self, lines: List[str], start_idx: int, end_idx: int) -> int:
        """Calculate complexity for a function."""
        complexity = 1
        
        decision_patterns = [
            r'\bif\s*\(',
            r'\belse\s+if\s*\(',
            r'\bfor\s*\(',
            r'\bwhile\s*\(',
            r'\bcase\s+',
            r'\bcatch\s*\(',
            r'\?\s*.*\s*:',  # ternary
            r'\&\&',
            r'\|\|',
        ]
        
        for i in range(start_idx, min(end_idx + 1, len(lines))):
            line = lines[i]
            for pattern in decision_patterns:
                complexity += len(re.findall(pattern, line))
        
        return complexity
    
    def extract_classes(self, ast: ASTNode, source: str) -> List[ClassInfo]:
        """Extract class information from JavaScript/TypeScript code."""
        classes = []
        lines = source.splitlines()
        
        class_pattern = re.compile(r'^(\s*)(?:export\s+)?(?:default\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?')
        
        for line_num, line in enumerate(lines, 1):
            match = class_pattern.match(line)
            if match:
                name = match.group(2)
                base_class = match.group(3)
                end_line = self._find_block_end(lines, line_num - 1)
                
                # Extract methods within the class
                methods = self._extract_class_methods(lines, line_num - 1, end_line - 1)
                
                class_info = ClassInfo(
                    name=name,
                    start_line=line_num,
                    end_line=end_line,
                    methods=methods,
                    bases=[base_class] if base_class else [],
                    is_public=True,
                )
                classes.append(class_info)
        
        return classes
    
    def _extract_class_methods(self, lines: List[str], start_idx: int, end_idx: int) -> List[FunctionInfo]:
        """Extract methods from a class definition."""
        methods = []
        
        method_pattern = re.compile(r'^(\s*)(static\s+)?(async\s+)?(\w+)\s*\(([^)]*)\)\s*{')
        
        for i in range(start_idx + 1, end_idx):
            line = lines[i]
            match = method_pattern.match(line)
            if match:
                is_static = bool(match.group(2))
                is_async = bool(match.group(3))
                name = match.group(4)
                params_str = match.group(5)
                
                if name in ('if', 'for', 'while', 'switch'):
                    continue
                
                params = [p.strip() for p in params_str.split(',') if p.strip()]
                
                method_end = self._find_block_end(lines, i)
                
                methods.append(FunctionInfo(
                    name=name,
                    start_line=i + 1,
                    end_line=method_end,
                    parameters=params,
                    complexity=1,
                    line_count=method_end - i,
                    is_async=is_async,
                    is_public=not name.startswith('_'),
                ))
        
        return methods
    
    def extract_imports(self, ast: ASTNode, source: str) -> List[ImportInfo]:
        """Extract import information from JavaScript/TypeScript code."""
        imports = []
        lines = source.splitlines()
        
        # ES6 imports
        es6_patterns = [
            re.compile(r'^import\s+(\w+)\s+from\s+[\'"]([^\'"]+)[\'"]'),
            re.compile(r'^import\s+\{\s*([^}]+)\s*\}\s+from\s+[\'"]([^\'"]+)[\'"]'),
            re.compile(r'^import\s+\*\s+as\s+(\w+)\s+from\s+[\'"]([^\'"]+)[\'"]'),
            re.compile(r'^import\s+[\'"]([^\'"]+)[\'"]'),
        ]
        
        # CommonJS require
        require_pattern = re.compile(r'^(?:const|let|var)\s+(?:\{([^}]+)\}|(\w+))\s*=\s*require\s*\([\'"]([^\'"]+)[\'"]\)')
        
        for line_num, line in enumerate(lines, 1):
            for pattern in es6_patterns:
                match = pattern.match(line.strip())
                if match:
                    groups = match.groups()
                    if len(groups) == 2:
                        names_str, module = groups
                        names = [n.strip() for n in names_str.split(',') if n.strip()]
                    else:
                        module = groups[0]
                        names = []
                    
                    imports.append(ImportInfo(
                        module=module,
                        names=names,
                        line=line_num,
                    ))
                    break
            
            match = require_pattern.match(line.strip())
            if match:
                destructured, name, module = match.groups()
                if destructured:
                    names = [n.strip() for n in destructured.split(',')]
                else:
                    names = [name] if name else []
                
                imports.append(ImportInfo(
                    module=module,
                    names=names,
                    line=line_num,
                ))
        
        return imports
    
    def extract_variables(self, ast: ASTNode, source: str) -> List[VariableInfo]:
        """Extract variable information from JavaScript/TypeScript code."""
        variables = []
        lines = source.splitlines()
        
        var_pattern = re.compile(r'^(\s*)(const|let|var)\s+(\w+)\s*=\s*(.+)')
        
        for line_num, line in enumerate(lines, 1):
            match = var_pattern.match(line)
            if match:
                kind = match.group(2)
                name = match.group(3)
                value = match.group(4).rstrip(';').strip()
                
                variables.append(VariableInfo(
                    name=name,
                    line=line_num,
                    scope="global",  # Simplified
                    is_constant=(kind == 'const'),
                    assigned_value=value[:50] if len(value) > 50 else value,
                ))
        
        return variables
    
    def find_security_issues(self, source: str) -> List[Dict[str, Any]]:
        """Find common security issues in JavaScript/TypeScript code."""
        issues = []
        lines = source.splitlines()
        
        dangerous_patterns = [
            (r'\beval\s*\(', "Use of eval() - potential code injection"),
            (r'new\s+Function\s*\(', "Use of Function constructor - potential code injection"),
            (r'\.innerHTML\s*=', "Use of innerHTML - potential XSS"),
            (r'document\.write\s*\(', "Use of document.write - potential XSS"),
            (r'\.outerHTML\s*=', "Use of outerHTML - potential XSS"),
            (r'child_process\.exec\s*\(', "Use of child_process.exec - potential command injection"),
            (r'child_process\.execSync\s*\(', "Use of child_process.execSync - potential command injection"),
            (r'dangerouslySetInnerHTML', "Use of dangerouslySetInnerHTML in React - potential XSS"),
            (r'location\s*=\s*[^;]*\+', "Potential open redirect"),
            (r'window\.location\s*=', "Direct location assignment - check for open redirect"),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, message in dangerous_patterns:
                if re.search(pattern, line):
                    issues.append({
                        "line": line_num,
                        "pattern": pattern,
                        "message": message,
                        "code": line.strip()[:100],
                    })
        
        return issues
