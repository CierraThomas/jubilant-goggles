"""
Base parser class for language-specific parsers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional, List, Dict, Iterator


@dataclass
class ASTNode:
    """
    Generic AST node representation.
    
    This provides a common interface for AST nodes across different
    parsing libraries, making rules more portable.
    """
    type: str
    value: Optional[str] = None
    start_line: int = 0
    end_line: int = 0
    start_column: int = 0
    end_column: int = 0
    children: List["ASTNode"] = field(default_factory=list)
    parent: Optional["ASTNode"] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    def __repr__(self) -> str:
        return f"ASTNode(type={self.type!r}, value={self.value!r}, line={self.start_line})"
    
    def find_all(self, node_type: str) -> Iterator["ASTNode"]:
        """Find all descendant nodes of a given type."""
        if self.type == node_type:
            yield self
        for child in self.children:
            yield from child.find_all(node_type)
    
    def find_first(self, node_type: str) -> Optional["ASTNode"]:
        """Find the first descendant node of a given type."""
        for node in self.find_all(node_type):
            return node
        return None
    
    def get_children_of_type(self, node_type: str) -> List["ASTNode"]:
        """Get direct children of a given type."""
        return [c for c in self.children if c.type == node_type]
    
    def get_source_text(self, source: str) -> str:
        """Extract the source text for this node."""
        lines = source.splitlines()
        if self.start_line == self.end_line:
            if self.start_line <= len(lines):
                line = lines[self.start_line - 1]
                return line[self.start_column:self.end_column]
        else:
            result = []
            for i in range(self.start_line, self.end_line + 1):
                if i <= len(lines):
                    line = lines[i - 1]
                    if i == self.start_line:
                        result.append(line[self.start_column:])
                    elif i == self.end_line:
                        result.append(line[:self.end_column])
                    else:
                        result.append(line)
            return "\n".join(result)
        return ""
    
    @property
    def text(self) -> str:
        """Get the value or empty string."""
        return self.value or ""


class BaseParser(ABC):
    """
    Base class for language-specific parsers.
    
    Each parser is responsible for parsing source code into
    a normalized AST that can be analyzed by rules.
    """
    
    @property
    @abstractmethod
    def language(self) -> str:
        """Return the language this parser handles."""
        pass
    
    @abstractmethod
    def parse(self, source: str, file_path: str = "<unknown>") -> Optional[ASTNode]:
        """
        Parse source code into an AST.
        
        Args:
            source: The source code to parse.
            file_path: The file path (for error messages).
            
        Returns:
            The root ASTNode or None if parsing fails.
        """
        pass
    
    def get_function_calls(self, ast: ASTNode) -> List[ASTNode]:
        """Get all function call nodes from the AST."""
        return list(ast.find_all("call"))
    
    def get_function_definitions(self, ast: ASTNode) -> List[ASTNode]:
        """Get all function definition nodes from the AST."""
        return list(ast.find_all("function_definition"))
    
    def get_class_definitions(self, ast: ASTNode) -> List[ASTNode]:
        """Get all class definition nodes from the AST."""
        return list(ast.find_all("class_definition"))
    
    def get_imports(self, ast: ASTNode) -> List[ASTNode]:
        """Get all import nodes from the AST."""
        return list(ast.find_all("import"))
    
    def get_string_literals(self, ast: ASTNode) -> List[ASTNode]:
        """Get all string literal nodes from the AST."""
        return list(ast.find_all("string"))
    
    def get_variables(self, ast: ASTNode) -> List[ASTNode]:
        """Get all variable assignment nodes from the AST."""
        return list(ast.find_all("assignment"))
