 from __future__ import annotations
 
 from dataclasses import dataclass
 from pathlib import Path
 from typing import Iterable, Optional
 
 try:
     from tree_sitter_languages import get_language, get_parser
 except Exception:  # pragma: no cover - optional dependency handling
     get_language = None
     get_parser = None
 
 
 @dataclass(frozen=True)
 class LanguageSpec:
     name: str
     extensions: set[str]
     identifier_types: set[str]
     string_types: set[str]
     comment_types: set[str]
     call_node_types: set[str]
     assignment_node_types: set[str]
     function_node_types: set[str]
     block_node_types: set[str]
     member_node_types: set[str]
     branch_node_types: set[str]
 
 
TREE_SITTER_ALIASES = {
    "csharp": "c_sharp",
}

LANGUAGE_SPECS = {
     "python": LanguageSpec(
         name="python",
         extensions={".py"},
         identifier_types={"identifier"},
         string_types={"string"},
         comment_types={"comment"},
         call_node_types={"call"},
         assignment_node_types={"assignment"},
         function_node_types={"function_definition"},
         block_node_types={"block"},
         member_node_types={"attribute"},
         branch_node_types={
             "if_statement",
             "elif_clause",
             "for_statement",
             "while_statement",
             "try_statement",
             "with_statement",
             "boolean_operator",
             "conditional_expression",
         },
     ),
     "javascript": LanguageSpec(
         name="javascript",
         extensions={".js", ".jsx", ".mjs", ".cjs"},
         identifier_types={"identifier", "property_identifier"},
         string_types={"string", "template_string"},
         comment_types={"comment"},
         call_node_types={"call_expression", "new_expression"},
         assignment_node_types={"assignment_expression", "variable_declarator"},
         function_node_types={"function_declaration", "function", "arrow_function"},
         block_node_types={"statement_block"},
         member_node_types={"member_expression"},
         branch_node_types={
             "if_statement",
             "for_statement",
             "while_statement",
             "do_statement",
             "switch_statement",
             "case_clause",
             "ternary_expression",
             "logical_expression",
         },
     ),
     "typescript": LanguageSpec(
         name="typescript",
         extensions={".ts", ".tsx"},
         identifier_types={"identifier", "property_identifier"},
         string_types={"string", "template_string"},
         comment_types={"comment"},
         call_node_types={"call_expression", "new_expression"},
         assignment_node_types={"assignment_expression", "variable_declarator"},
         function_node_types={"function_declaration", "function", "arrow_function"},
         block_node_types={"statement_block"},
         member_node_types={"member_expression"},
         branch_node_types={
             "if_statement",
             "for_statement",
             "while_statement",
             "do_statement",
             "switch_statement",
             "case_clause",
             "ternary_expression",
             "logical_expression",
         },
     ),
     "java": LanguageSpec(
         name="java",
         extensions={".java"},
         identifier_types={"identifier"},
         string_types={"string_literal"},
         comment_types={"comment"},
         call_node_types={"method_invocation", "object_creation_expression"},
         assignment_node_types={"assignment_expression", "variable_declarator"},
         function_node_types={"method_declaration", "constructor_declaration"},
         block_node_types={"block"},
         member_node_types={"field_access"},
         branch_node_types={
             "if_statement",
             "for_statement",
             "while_statement",
             "do_statement",
             "switch_statement",
             "switch_rule",
             "ternary_expression",
             "catch_clause",
             "binary_expression",
         },
     ),
     "kotlin": LanguageSpec(
         name="kotlin",
         extensions={".kt", ".kts"},
         identifier_types={"simple_identifier"},
         string_types={"string_literal"},
         comment_types={"comment"},
         call_node_types={"call_expression"},
         assignment_node_types={"assignment"},
         function_node_types={"function_declaration"},
         block_node_types={"block"},
         member_node_types={"navigation_expression"},
         branch_node_types={
             "if_expression",
             "when_expression",
             "for_statement",
             "while_statement",
             "do_while_statement",
             "binary_expression",
         },
     ),
     "go": LanguageSpec(
         name="go",
         extensions={".go"},
         identifier_types={"identifier"},
         string_types={"interpreted_string_literal", "raw_string_literal"},
         comment_types={"comment"},
         call_node_types={"call_expression"},
         assignment_node_types={"assignment_statement", "short_var_declaration"},
         function_node_types={"function_declaration", "method_declaration", "func_literal"},
         block_node_types={"block"},
         member_node_types={"selector_expression"},
         branch_node_types={
             "if_statement",
             "for_statement",
             "switch_statement",
             "type_switch_statement",
             "select_statement",
             "expression_case",
             "communication_case",
             "binary_expression",
         },
     ),
     "ruby": LanguageSpec(
         name="ruby",
         extensions={".rb"},
         identifier_types={"identifier", "constant"},
         string_types={"string", "string_literal"},
         comment_types={"comment"},
         call_node_types={"call", "method_call"},
         assignment_node_types={"assignment"},
         function_node_types={"method", "singleton_method"},
         block_node_types={"do_block", "block"},
         member_node_types={"call"},
         branch_node_types={
             "if",
             "elsif",
             "unless",
             "case",
             "when",
             "while",
             "until",
             "ternary",
             "binary",
         },
     ),
     "rust": LanguageSpec(
         name="rust",
         extensions={".rs"},
         identifier_types={"identifier"},
         string_types={"string_literal"},
         comment_types={"line_comment", "block_comment"},
         call_node_types={"call_expression"},
         assignment_node_types={"assignment_expression", "let_declaration"},
         function_node_types={"function_item"},
         block_node_types={"block"},
         member_node_types={"field_expression"},
         branch_node_types={
             "if_expression",
             "match_expression",
             "while_expression",
             "for_expression",
             "loop_expression",
             "binary_expression",
         },
     ),
     "c": LanguageSpec(
         name="c",
         extensions={".c", ".h"},
         identifier_types={"identifier"},
         string_types={"string_literal"},
         comment_types={"comment"},
         call_node_types={"call_expression"},
         assignment_node_types={"assignment_expression"},
         function_node_types={"function_definition"},
         block_node_types={"compound_statement"},
         member_node_types={"field_expression"},
         branch_node_types={
             "if_statement",
             "for_statement",
             "while_statement",
             "do_statement",
             "switch_statement",
             "case_statement",
             "conditional_expression",
             "binary_expression",
         },
     ),
     "cpp": LanguageSpec(
         name="cpp",
         extensions={".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"},
         identifier_types={"identifier"},
         string_types={"string_literal"},
         comment_types={"comment"},
         call_node_types={"call_expression"},
         assignment_node_types={"assignment_expression"},
         function_node_types={"function_definition"},
         block_node_types={"compound_statement"},
         member_node_types={"field_expression"},
         branch_node_types={
             "if_statement",
             "for_statement",
             "while_statement",
             "do_statement",
             "switch_statement",
             "case_statement",
             "conditional_expression",
             "binary_expression",
         },
     ),
     "csharp": LanguageSpec(
         name="csharp",
         extensions={".cs"},
         identifier_types={"identifier"},
         string_types={"string_literal", "verbatim_string_literal"},
         comment_types={"comment"},
         call_node_types={"invocation_expression", "object_creation_expression"},
         assignment_node_types={"assignment_expression"},
         function_node_types={
             "method_declaration",
             "constructor_declaration",
             "local_function_statement",
         },
         block_node_types={"block"},
         member_node_types={"member_access_expression"},
         branch_node_types={
             "if_statement",
             "for_statement",
             "foreach_statement",
             "while_statement",
             "do_statement",
             "switch_statement",
             "switch_section",
             "conditional_expression",
             "catch_clause",
             "binary_expression",
         },
     ),
     "swift": LanguageSpec(
         name="swift",
         extensions={".swift"},
         identifier_types={"identifier"},
         string_types={"string_literal"},
         comment_types={"comment"},
         call_node_types={"call_expression"},
         assignment_node_types={"assignment_expression"},
         function_node_types={"function_declaration", "initializer_declaration"},
         block_node_types={"code_block"},
         member_node_types={"member_expression"},
         branch_node_types={
             "if_statement",
             "for_statement",
             "while_statement",
             "repeat_while_statement",
             "switch_statement",
             "case_label",
             "ternary_expression",
             "binary_expression",
         },
     ),
 }
 
 
 @dataclass(frozen=True)
 class ParsedFile:
     path: str
     language: str
     source: bytes
     tree: object
     spec: LanguageSpec
 
     @property
     def text(self) -> str:
         return self.source.decode("utf-8", errors="replace")
 
     @property
     def lines(self) -> list[str]:
         return self.text.splitlines()
 
 
 def language_for_path(path: str) -> Optional[str]:
     ext = Path(path).suffix.lower()
     for name, spec in LANGUAGE_SPECS.items():
         if ext in spec.extensions:
             return name
     return None
 
 
 def parse_file(path: str, language: str) -> Optional[ParsedFile]:
     if get_parser is None:
         return None
     spec = LANGUAGE_SPECS[language]
    parser = get_parser(TREE_SITTER_ALIASES.get(language, language))
     source = Path(path).read_bytes()
     tree = parser.parse(source)
     return ParsedFile(path=path, language=language, source=source, tree=tree, spec=spec)
 
 
 def iter_nodes(node) -> Iterable[object]:
     stack = [node]
     while stack:
         current = stack.pop()
         yield current
         stack.extend(reversed(current.children))
 
 
 def node_text(parsed: ParsedFile, node) -> str:
     return parsed.source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
