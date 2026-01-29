 from __future__ import annotations
 
 from dataclasses import dataclass
 from typing import Iterable, List
 
 from mlsecscan.parsing.treesitter import ParsedFile, iter_nodes, node_text
 
 
 @dataclass(frozen=True)
 class FunctionMetrics:
     name: str
     start_line: int
     end_line: int
     cyclomatic: int
     max_nesting: int
     line_count: int
 
 
 def analyze_complexity(parsed: ParsedFile) -> List[FunctionMetrics]:
     metrics: List[FunctionMetrics] = []
     for node in iter_nodes(parsed.tree.root_node):
         if node.type in parsed.spec.function_node_types:
             name = _function_name(parsed, node)
             cyclomatic = _cyclomatic(parsed, node)
             max_nesting = _max_nesting(parsed, node)
             start_line = node.start_point[0] + 1
             end_line = node.end_point[0] + 1
             metrics.append(
                 FunctionMetrics(
                     name=name or "<anonymous>",
                     start_line=start_line,
                     end_line=end_line,
                     cyclomatic=cyclomatic,
                     max_nesting=max_nesting,
                     line_count=end_line - start_line + 1,
                 )
             )
     return metrics
 
 
 def _function_name(parsed: ParsedFile, node) -> str:
     name_node = node.child_by_field_name("name")
     if name_node is None and node.named_children:
         for child in node.named_children:
             if child.type in parsed.spec.identifier_types:
                 name_node = child
                 break
     if name_node is None:
         return ""
     return node_text(parsed, name_node)
 
 
 def _cyclomatic(parsed: ParsedFile, node) -> int:
     complexity = 1
     for child in iter_nodes(node):
         if child.type in parsed.spec.branch_node_types:
             if child.type == "binary_expression":
                 text = node_text(parsed, child)
                 if "&&" not in text and "||" not in text and " and " not in text and " or " not in text:
                     continue
             complexity += 1
     return complexity
 
 
 def _max_nesting(parsed: ParsedFile, node) -> int:
     max_depth = 0
 
     def visit(current, depth: int) -> None:
         nonlocal max_depth
         if current.type in parsed.spec.block_node_types:
             depth += 1
             max_depth = max(max_depth, depth)
         for child in current.children:
             visit(child, depth)
 
     visit(node, 0)
     return max_depth
