"""
Python-specific AST parser using Python's built-in ast module.
"""

import ast as python_ast
from typing import Optional, List, Any

from securityscanner.parsers.base import BaseParser, ASTNode
from securityscanner.parsers import register_parser


@register_parser("python")
class PythonParser(BaseParser):
    """
    Parser for Python source code using the built-in ast module.
    """
    
    @property
    def language(self) -> str:
        return "python"
    
    def parse(self, source: str, file_path: str = "<unknown>") -> Optional[ASTNode]:
        """Parse Python source code into a normalized AST."""
        try:
            tree = python_ast.parse(source, filename=file_path)
            return self._convert_node(tree, source)
        except SyntaxError:
            return None
    
    def _convert_node(self, node: python_ast.AST, source: str, parent: Optional[ASTNode] = None) -> ASTNode:
        """Convert a Python AST node to our normalized ASTNode."""
        # Determine node type
        node_type = self._get_node_type(node)
        
        # Get position information
        start_line = getattr(node, "lineno", 0)
        end_line = getattr(node, "end_lineno", start_line)
        start_col = getattr(node, "col_offset", 0)
        end_col = getattr(node, "end_col_offset", 0)
        
        # Get value for certain node types
        value = self._get_node_value(node)
        
        # Create the normalized node
        ast_node = ASTNode(
            type=node_type,
            value=value,
            start_line=start_line,
            end_line=end_line,
            start_column=start_col,
            end_column=end_col,
            parent=parent,
            attributes=self._get_attributes(node),
        )
        
        # Convert children
        for child in python_ast.iter_child_nodes(node):
            child_node = self._convert_node(child, source, ast_node)
            ast_node.children.append(child_node)
        
        return ast_node
    
    def _get_node_type(self, node: python_ast.AST) -> str:
        """Map Python AST node types to normalized types."""
        type_map = {
            "Module": "module",
            "FunctionDef": "function_definition",
            "AsyncFunctionDef": "function_definition",
            "ClassDef": "class_definition",
            "Return": "return",
            "Delete": "delete",
            "Assign": "assignment",
            "AugAssign": "augmented_assignment",
            "AnnAssign": "annotated_assignment",
            "For": "for_loop",
            "AsyncFor": "for_loop",
            "While": "while_loop",
            "If": "if_statement",
            "With": "with_statement",
            "AsyncWith": "with_statement",
            "Raise": "raise",
            "Try": "try_statement",
            "Assert": "assert",
            "Import": "import",
            "ImportFrom": "import_from",
            "Global": "global",
            "Nonlocal": "nonlocal",
            "Expr": "expression_statement",
            "Pass": "pass",
            "Break": "break",
            "Continue": "continue",
            "Call": "call",
            "BinOp": "binary_operation",
            "UnaryOp": "unary_operation",
            "Lambda": "lambda",
            "IfExp": "ternary",
            "Dict": "dict",
            "Set": "set",
            "List": "list",
            "Tuple": "tuple",
            "Subscript": "subscript",
            "Attribute": "attribute",
            "Name": "identifier",
            "Constant": "literal",
            "Str": "string",
            "Num": "number",
            "Bytes": "bytes",
            "JoinedStr": "f_string",
            "FormattedValue": "formatted_value",
            "Compare": "comparison",
            "BoolOp": "boolean_operation",
            "NamedExpr": "walrus_operator",
            "Starred": "starred",
            "Slice": "slice",
            "ListComp": "list_comprehension",
            "SetComp": "set_comprehension",
            "DictComp": "dict_comprehension",
            "GeneratorExp": "generator_expression",
            "Await": "await",
            "Yield": "yield",
            "YieldFrom": "yield_from",
        }
        
        class_name = node.__class__.__name__
        return type_map.get(class_name, class_name.lower())
    
    def _get_node_value(self, node: python_ast.AST) -> Optional[str]:
        """Extract the value from certain node types."""
        if isinstance(node, python_ast.Name):
            return node.id
        elif isinstance(node, python_ast.Constant):
            return str(node.value) if node.value is not None else None
        elif isinstance(node, python_ast.FunctionDef) or isinstance(node, python_ast.AsyncFunctionDef):
            return node.name
        elif isinstance(node, python_ast.ClassDef):
            return node.name
        elif isinstance(node, python_ast.Attribute):
            return node.attr
        elif isinstance(node, python_ast.arg):
            return node.arg
        elif isinstance(node, python_ast.alias):
            return node.name
        return None
    
    def _get_attributes(self, node: python_ast.AST) -> dict:
        """Extract additional attributes from the node."""
        attrs = {}
        
        if isinstance(node, python_ast.FunctionDef) or isinstance(node, python_ast.AsyncFunctionDef):
            attrs["name"] = node.name
            attrs["decorators"] = [self._get_decorator_name(d) for d in node.decorator_list]
            attrs["args"] = [arg.arg for arg in node.args.args]
            attrs["is_async"] = isinstance(node, python_ast.AsyncFunctionDef)
        
        elif isinstance(node, python_ast.ClassDef):
            attrs["name"] = node.name
            attrs["bases"] = [self._get_name(b) for b in node.bases]
            attrs["decorators"] = [self._get_decorator_name(d) for d in node.decorator_list]
        
        elif isinstance(node, python_ast.Call):
            attrs["func_name"] = self._get_call_name(node)
            attrs["arg_count"] = len(node.args)
            attrs["has_kwargs"] = bool(node.keywords)
        
        elif isinstance(node, python_ast.Import):
            attrs["names"] = [alias.name for alias in node.names]
        
        elif isinstance(node, python_ast.ImportFrom):
            attrs["module"] = node.module
            attrs["names"] = [alias.name for alias in node.names]
        
        elif isinstance(node, python_ast.Assign):
            attrs["targets"] = [self._get_name(t) for t in node.targets]
        
        elif isinstance(node, python_ast.Constant):
            attrs["value_type"] = type(node.value).__name__
        
        return attrs
    
    def _get_name(self, node: python_ast.AST) -> str:
        """Get a string name from various node types."""
        if isinstance(node, python_ast.Name):
            return node.id
        elif isinstance(node, python_ast.Attribute):
            base = self._get_name(node.value)
            return f"{base}.{node.attr}"
        elif isinstance(node, python_ast.Subscript):
            return self._get_name(node.value)
        elif isinstance(node, python_ast.Call):
            return self._get_call_name(node)
        return ""
    
    def _get_call_name(self, node: python_ast.Call) -> str:
        """Get the full name of a function call."""
        if isinstance(node.func, python_ast.Name):
            return node.func.id
        elif isinstance(node.func, python_ast.Attribute):
            return self._get_name(node.func)
        return ""
    
    def _get_decorator_name(self, node: python_ast.AST) -> str:
        """Get the name of a decorator."""
        if isinstance(node, python_ast.Name):
            return node.id
        elif isinstance(node, python_ast.Attribute):
            return self._get_name(node)
        elif isinstance(node, python_ast.Call):
            return self._get_call_name(node)
        return ""
    
    def get_function_calls(self, ast: ASTNode) -> List[ASTNode]:
        """Get all function call nodes from the AST."""
        return list(ast.find_all("call"))
    
    def get_function_definitions(self, ast: ASTNode) -> List[ASTNode]:
        """Get all function definition nodes from the AST."""
        return list(ast.find_all("function_definition"))
    
    def get_string_literals(self, ast: ASTNode) -> List[ASTNode]:
        """Get all string literal nodes."""
        strings = []
        for node in ast.find_all("literal"):
            if node.attributes.get("value_type") == "str":
                strings.append(node)
        for node in ast.find_all("string"):
            strings.append(node)
        return strings
