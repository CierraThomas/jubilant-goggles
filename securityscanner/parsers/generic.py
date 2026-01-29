"""
Generic parser for languages without dedicated parsers.

Uses regex-based pattern matching to extract basic code structure.
This provides baseline functionality for any language.
"""

import re
from typing import Optional, List, Dict, Any

from securityscanner.parsers.base import BaseParser, ASTNode


# Language-specific patterns
LANGUAGE_PATTERNS: Dict[str, Dict[str, Any]] = {
    "java": {
        "function": re.compile(
            r'^(\s*)(public|private|protected)?\s*(static)?\s*(\w+)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\s*{',
            re.MULTILINE
        ),
        "class": re.compile(
            r'^(\s*)(public|private|protected)?\s*(abstract|final)?\s*class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([\w,\s]+))?\s*{',
            re.MULTILINE
        ),
        "import": re.compile(r'^import\s+([\w.]+);', re.MULTILINE),
        "string": re.compile(r'"([^"\\]|\\.)*"'),
        "call": re.compile(r'([\w.]+)\s*\('),
    },
    "kotlin": {
        "function": re.compile(
            r'^(\s*)(fun)\s+(\w+)\s*\(([^)]*)\)(?:\s*:\s*(\w+))?\s*{',
            re.MULTILINE
        ),
        "class": re.compile(
            r'^(\s*)(class|data\s+class|object)\s+(\w+)(?:\s*:\s*([\w,\s]+))?\s*{?',
            re.MULTILINE
        ),
        "import": re.compile(r'^import\s+([\w.]+)', re.MULTILINE),
        "string": re.compile(r'"([^"\\]|\\.)*"'),
        "call": re.compile(r'([\w.]+)\s*\('),
    },
    "go": {
        "function": re.compile(
            r'^(\s*)func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(([^)]*)\)(?:\s*\([^)]*\)|\s*[\w*]+)?\s*{',
            re.MULTILINE
        ),
        "struct": re.compile(
            r'^(\s*)type\s+(\w+)\s+struct\s*{',
            re.MULTILINE
        ),
        "import": re.compile(r'import\s+(?:"([\w/.-]+)"|(?:\(\s*([\s\S]*?)\s*\)))', re.MULTILINE),
        "string": re.compile(r'"([^"\\]|\\.)*"|`[^`]*`'),
        "call": re.compile(r'([\w.]+)\s*\('),
    },
    "ruby": {
        "function": re.compile(
            r'^(\s*)def\s+(\w+)(?:\(([^)]*)\))?',
            re.MULTILINE
        ),
        "class": re.compile(
            r'^(\s*)class\s+(\w+)(?:\s*<\s*(\w+))?',
            re.MULTILINE
        ),
        "module": re.compile(
            r'^(\s*)module\s+(\w+)',
            re.MULTILINE
        ),
        "string": re.compile(r'"([^"\\]|\\.)*"|\'([^\'\\]|\\.)*\''),
        "call": re.compile(r'([\w.]+)\s*(?:\(|$)'),
    },
    "rust": {
        "function": re.compile(
            r'^(\s*)(pub\s+)?(async\s+)?fn\s+(\w+)(?:<[^>]+>)?\s*\(([^)]*)\)(?:\s*->\s*[\w<>]+)?\s*{',
            re.MULTILINE
        ),
        "struct": re.compile(
            r'^(\s*)(pub\s+)?struct\s+(\w+)(?:<[^>]+>)?\s*{',
            re.MULTILINE
        ),
        "impl": re.compile(
            r'^(\s*)impl(?:<[^>]+>)?\s+(\w+)(?:<[^>]+>)?(?:\s+for\s+(\w+))?\s*{',
            re.MULTILINE
        ),
        "use": re.compile(r'^use\s+([\w:]+)', re.MULTILINE),
        "string": re.compile(r'"([^"\\]|\\.)*"'),
        "call": re.compile(r'([\w:]+)\s*(?:!?\()'),
    },
    "swift": {
        "function": re.compile(
            r'^(\s*)(public|private|internal|fileprivate|open)?\s*(func)\s+(\w+)\s*\(([^)]*)\)(?:\s*->\s*[\w<>?]+)?\s*{',
            re.MULTILINE
        ),
        "class": re.compile(
            r'^(\s*)(public|private|internal|fileprivate|open)?\s*(class|struct|enum)\s+(\w+)(?:\s*:\s*([\w,\s]+))?\s*{',
            re.MULTILINE
        ),
        "import": re.compile(r'^import\s+(\w+)', re.MULTILINE),
        "string": re.compile(r'"([^"\\]|\\.)*"'),
        "call": re.compile(r'([\w.]+)\s*\('),
    },
    "c": {
        "function": re.compile(
            r'^(\s*)(\w+(?:\s*\*)?)\s+(\w+)\s*\(([^)]*)\)\s*{',
            re.MULTILINE
        ),
        "struct": re.compile(
            r'^(\s*)(?:typedef\s+)?struct\s+(\w+)?\s*{',
            re.MULTILINE
        ),
        "include": re.compile(r'^#include\s*[<"]([^>"]+)[>"]', re.MULTILINE),
        "string": re.compile(r'"([^"\\]|\\.)*"'),
        "call": re.compile(r'([\w]+)\s*\('),
    },
    "cpp": {
        "function": re.compile(
            r'^(\s*)(?:virtual\s+)?(\w+(?:\s*[*&])?)\s+(\w+)\s*\(([^)]*)\)(?:\s*const)?\s*(?:override)?\s*{',
            re.MULTILINE
        ),
        "class": re.compile(
            r'^(\s*)class\s+(\w+)(?:\s*:\s*(?:public|private|protected)\s+(\w+))?\s*{',
            re.MULTILINE
        ),
        "include": re.compile(r'^#include\s*[<"]([^>"]+)[>"]', re.MULTILINE),
        "string": re.compile(r'"([^"\\]|\\.)*"'),
        "call": re.compile(r'([\w:]+)\s*\('),
    },
    "csharp": {
        "function": re.compile(
            r'^(\s*)(public|private|protected|internal)?\s*(static|async|virtual|override)?\s*([\w<>]+)\s+(\w+)\s*\(([^)]*)\)\s*{',
            re.MULTILINE
        ),
        "class": re.compile(
            r'^(\s*)(public|private|protected|internal)?\s*(partial|abstract|sealed)?\s*(class|struct|interface)\s+(\w+)(?:\s*:\s*([\w,\s]+))?\s*{',
            re.MULTILINE
        ),
        "using": re.compile(r'^using\s+([\w.]+);', re.MULTILINE),
        "string": re.compile(r'@?"([^"\\]|\\.)*"'),
        "call": re.compile(r'([\w.]+)\s*\('),
    },
}


class GenericParser(BaseParser):
    """
    Generic parser that works for any language using regex patterns.
    
    Provides basic AST extraction for function calls, strings, and imports.
    """
    
    def __init__(self, language: str = "unknown"):
        self._language = language.lower()
    
    @property
    def language(self) -> str:
        return self._language
    
    def parse(self, source: str, file_path: str = "<unknown>") -> Optional[ASTNode]:
        """Parse source code into a basic AST."""
        lines = source.splitlines()
        
        root = ASTNode(
            type="module",
            start_line=1,
            end_line=len(lines),
        )
        
        patterns = LANGUAGE_PATTERNS.get(self._language, {})
        
        # Parse functions
        if "function" in patterns:
            self._parse_with_pattern(source, patterns["function"], "function_definition", root)
        
        # Parse classes/structs
        for key in ("class", "struct", "impl", "module"):
            if key in patterns:
                self._parse_with_pattern(source, patterns[key], "class_definition", root)
        
        # Parse imports
        for key in ("import", "include", "use", "using"):
            if key in patterns:
                self._parse_with_pattern(source, patterns[key], "import", root)
        
        # Parse function calls
        if "call" in patterns:
            self._parse_calls(source, lines, patterns["call"], root)
        
        # Parse strings
        if "string" in patterns:
            self._parse_strings(source, lines, patterns["string"], root)
        
        return root
    
    def _parse_with_pattern(
        self, 
        source: str, 
        pattern: re.Pattern, 
        node_type: str, 
        root: ASTNode
    ):
        """Parse using a regex pattern."""
        for match in pattern.finditer(source):
            line_num = source[:match.start()].count('\n') + 1
            
            # Try to extract a name from the match groups
            groups = match.groups()
            name = None
            for group in groups:
                if group and re.match(r'^[a-zA-Z_]\w*$', str(group)):
                    if name is None or len(group) > 1:
                        name = group
            
            node = ASTNode(
                type=node_type,
                value=name,
                start_line=line_num,
                end_line=line_num,
                start_column=match.start() - source.rfind('\n', 0, match.start()) - 1,
                parent=root,
                attributes={"match_groups": list(groups)},
            )
            root.children.append(node)
    
    def _parse_calls(
        self, 
        source: str, 
        lines: List[str], 
        pattern: re.Pattern, 
        root: ASTNode
    ):
        """Parse function calls."""
        keywords = {'if', 'while', 'for', 'switch', 'catch', 'return', 'throw', 'new', 'delete'}
        
        for line_num, line in enumerate(lines, 1):
            for match in pattern.finditer(line):
                func_name = match.group(1)
                
                if func_name.lower() in keywords:
                    continue
                
                node = ASTNode(
                    type="call",
                    value=func_name,
                    start_line=line_num,
                    end_line=line_num,
                    start_column=match.start(),
                    end_column=match.end(),
                    parent=root,
                    attributes={"func_name": func_name},
                )
                root.children.append(node)
    
    def _parse_strings(
        self, 
        source: str, 
        lines: List[str], 
        pattern: re.Pattern, 
        root: ASTNode
    ):
        """Parse string literals."""
        for line_num, line in enumerate(lines, 1):
            for match in pattern.finditer(line):
                value = match.group()
                
                # Remove quotes
                if value.startswith(('@"', 'r"', "r'", "b'")):
                    content = value[2:-1]
                elif value.startswith(('"', "'", '`')):
                    content = value[1:-1]
                else:
                    content = value
                
                node = ASTNode(
                    type="string",
                    value=content,
                    start_line=line_num,
                    end_line=line_num,
                    start_column=match.start(),
                    end_column=match.end(),
                    parent=root,
                )
                root.children.append(node)
