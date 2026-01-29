 from __future__ import annotations
 
 from typing import Iterable, List
 
 from mlsecscan.parsing.treesitter import ParsedFile, node_text
 
 
 def extract_call_arguments(parsed: ParsedFile, node) -> List[object]:
     args = (
         node.child_by_field_name("arguments")
         or node.child_by_field_name("argument_list")
         or node.child_by_field_name("parameters")
     )
     if args is None:
         # Fallback: use named children that are not the callee.
         return [
             child
             for child in node.named_children
             if child.type not in parsed.spec.identifier_types
         ]
     return [child for child in args.named_children if child.is_named]
 
 
 def node_snippet(parsed: ParsedFile, node) -> str:
     return node_text(parsed, node).strip()
 
 
 def find_nodes(parsed: ParsedFile, types: set[str]) -> Iterable[object]:
     stack = [parsed.tree.root_node]
     while stack:
         current = stack.pop()
         if current.type in types:
             yield current
         stack.extend(reversed(current.children))


def assignment_parts(node) -> tuple[object | None, object | None]:
    left = (
        node.child_by_field_name("left")
        or node.child_by_field_name("target")
        or node.child_by_field_name("name")
        or node.child_by_field_name("pattern")
    )
    value = (
        node.child_by_field_name("right")
        or node.child_by_field_name("value")
        or node.child_by_field_name("expression")
    )
    return left, value
