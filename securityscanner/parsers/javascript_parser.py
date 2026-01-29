"""
JavaScript/TypeScript parser.

Uses a simple regex-based approach for basic parsing when
tree-sitter or esprima is not available.
"""

import re
from typing import Optional, List, Dict, Any

from securityscanner.parsers.base import BaseParser, ASTNode
from securityscanner.parsers import register_parser


@register_parser("javascript")
@register_parser("typescript")
class JavaScriptParser(BaseParser):
    """
    Parser for JavaScript/TypeScript source code.
    
    Uses regex-based parsing for basic AST construction.
    For production use, consider integrating with tree-sitter or esprima.
    """
    
    def __init__(self):
        self._language = "javascript"
    
    @property
    def language(self) -> str:
        return self._language
    
    def parse(self, source: str, file_path: str = "<unknown>") -> Optional[ASTNode]:
        """Parse JavaScript source code into a normalized AST."""
        # Set language based on file extension
        if file_path.endswith(('.ts', '.tsx')):
            self._language = "typescript"
        else:
            self._language = "javascript"
        
        try:
            return self._build_ast(source, file_path)
        except Exception:
            return None
    
    def _build_ast(self, source: str, file_path: str) -> ASTNode:
        """Build AST from source using regex patterns."""
        root = ASTNode(
            type="module",
            start_line=1,
            end_line=len(source.splitlines()),
        )
        
        lines = source.splitlines()
        
        # Parse functions
        self._parse_functions(source, lines, root)
        
        # Parse classes
        self._parse_classes(source, lines, root)
        
        # Parse function calls
        self._parse_calls(source, lines, root)
        
        # Parse imports
        self._parse_imports(source, lines, root)
        
        # Parse string literals
        self._parse_strings(source, lines, root)
        
        # Parse variable declarations
        self._parse_variables(source, lines, root)
        
        return root
    
    def _parse_functions(self, source: str, lines: List[str], root: ASTNode):
        """Parse function definitions."""
        # Regular functions: function name(args) {
        func_pattern = re.compile(
            r'^(\s*)(async\s+)?function\s+(\w+)\s*\(([^)]*)\)',
            re.MULTILINE
        )
        
        for match in func_pattern.finditer(source):
            line_num = source[:match.start()].count('\n') + 1
            indent = len(match.group(1))
            is_async = bool(match.group(2))
            name = match.group(3)
            args = match.group(4)
            
            node = ASTNode(
                type="function_definition",
                value=name,
                start_line=line_num,
                end_line=line_num,
                start_column=indent,
                parent=root,
                attributes={
                    "name": name,
                    "args": [a.strip() for a in args.split(',') if a.strip()],
                    "is_async": is_async,
                }
            )
            root.children.append(node)
        
        # Arrow functions: const name = (args) => {
        arrow_pattern = re.compile(
            r'^(\s*)(const|let|var)\s+(\w+)\s*=\s*(async\s+)?(?:\([^)]*\)|[\w]+)\s*=>',
            re.MULTILINE
        )
        
        for match in arrow_pattern.finditer(source):
            line_num = source[:match.start()].count('\n') + 1
            indent = len(match.group(1))
            name = match.group(3)
            is_async = bool(match.group(4))
            
            node = ASTNode(
                type="function_definition",
                value=name,
                start_line=line_num,
                end_line=line_num,
                start_column=indent,
                parent=root,
                attributes={
                    "name": name,
                    "is_arrow": True,
                    "is_async": is_async,
                }
            )
            root.children.append(node)
    
    def _parse_classes(self, source: str, lines: List[str], root: ASTNode):
        """Parse class definitions."""
        class_pattern = re.compile(
            r'^(\s*)class\s+(\w+)(?:\s+extends\s+(\w+))?\s*{',
            re.MULTILINE
        )
        
        for match in class_pattern.finditer(source):
            line_num = source[:match.start()].count('\n') + 1
            indent = len(match.group(1))
            name = match.group(2)
            base_class = match.group(3)
            
            node = ASTNode(
                type="class_definition",
                value=name,
                start_line=line_num,
                end_line=line_num,
                start_column=indent,
                parent=root,
                attributes={
                    "name": name,
                    "extends": base_class,
                }
            )
            root.children.append(node)
    
    def _parse_calls(self, source: str, lines: List[str], root: ASTNode):
        """Parse function calls."""
        # Match function calls: name(args) or obj.method(args)
        call_pattern = re.compile(
            r'([\w.]+)\s*\(([^)]*)\)',
        )
        
        for line_num, line in enumerate(lines, 1):
            # Skip function definitions
            if re.match(r'^\s*(async\s+)?function\s+', line):
                continue
            
            for match in call_pattern.finditer(line):
                func_name = match.group(1)
                
                # Skip common non-call patterns
                if func_name in ('if', 'while', 'for', 'switch', 'catch'):
                    continue
                
                node = ASTNode(
                    type="call",
                    value=func_name,
                    start_line=line_num,
                    end_line=line_num,
                    start_column=match.start(),
                    end_column=match.end(),
                    parent=root,
                    attributes={
                        "func_name": func_name,
                    }
                )
                root.children.append(node)
    
    def _parse_imports(self, source: str, lines: List[str], root: ASTNode):
        """Parse import statements."""
        # ES6 imports: import { x } from 'module'
        import_pattern = re.compile(
            r'^(\s*)import\s+(?:(\w+)|{([^}]+)}|(\*\s+as\s+\w+))\s+from\s+[\'"]([^\'"]+)[\'"]',
            re.MULTILINE
        )
        
        for match in import_pattern.finditer(source):
            line_num = source[:match.start()].count('\n') + 1
            module = match.group(5)
            
            node = ASTNode(
                type="import",
                value=module,
                start_line=line_num,
                end_line=line_num,
                parent=root,
                attributes={
                    "module": module,
                }
            )
            root.children.append(node)
        
        # CommonJS require: const x = require('module')
        require_pattern = re.compile(
            r'^(\s*)(?:const|let|var)\s+(\w+)\s*=\s*require\s*\([\'"]([^\'"]+)[\'"]\)',
            re.MULTILINE
        )
        
        for match in require_pattern.finditer(source):
            line_num = source[:match.start()].count('\n') + 1
            name = match.group(2)
            module = match.group(3)
            
            node = ASTNode(
                type="import",
                value=module,
                start_line=line_num,
                end_line=line_num,
                parent=root,
                attributes={
                    "module": module,
                    "name": name,
                    "is_require": True,
                }
            )
            root.children.append(node)
    
    def _parse_strings(self, source: str, lines: List[str], root: ASTNode):
        """Parse string literals."""
        # Match single, double quoted, and template strings
        string_patterns = [
            re.compile(r'"([^"\\]|\\.)*"'),
            re.compile(r"'([^'\\]|\\.)*'"),
            re.compile(r'`([^`\\]|\\.)*`'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern in string_patterns:
                for match in pattern.finditer(line):
                    value = match.group()
                    
                    node = ASTNode(
                        type="string",
                        value=value[1:-1],  # Remove quotes
                        start_line=line_num,
                        end_line=line_num,
                        start_column=match.start(),
                        end_column=match.end(),
                        parent=root,
                        attributes={
                            "is_template": value.startswith('`'),
                        }
                    )
                    root.children.append(node)
    
    def _parse_variables(self, source: str, lines: List[str], root: ASTNode):
        """Parse variable declarations."""
        var_pattern = re.compile(
            r'^(\s*)(const|let|var)\s+(\w+)\s*=',
            re.MULTILINE
        )
        
        for match in var_pattern.finditer(source):
            line_num = source[:match.start()].count('\n') + 1
            kind = match.group(2)
            name = match.group(3)
            
            node = ASTNode(
                type="assignment",
                value=name,
                start_line=line_num,
                end_line=line_num,
                start_column=len(match.group(1)),
                parent=root,
                attributes={
                    "name": name,
                    "kind": kind,
                }
            )
            root.children.append(node)
