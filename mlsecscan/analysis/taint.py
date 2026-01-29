 from __future__ import annotations
 
 from dataclasses import dataclass
 from typing import Iterable, List, Optional, Set
 
 from mlsecscan.parsing.treesitter import ParsedFile, iter_nodes, node_text
 
 
 SOURCE_FUNCTIONS = {
     "input",
     "gets",
     "readline",
     "read_line",
     "console.readLine",
     "console.readline",
     "scanf",
     "fgets",
 }
 
 SOURCE_IDENTIFIERS = {
     "request",
     "req",
     "params",
     "query",
     "body",
     "form",
     "headers",
     "cookies",
 }
 
 SOURCE_PROPERTIES = {
     "params",
     "query",
     "body",
     "form",
     "headers",
     "cookies",
     "args",
     "argv",
 }
 
 DEFAULT_SANITIZERS = {
     "escape",
     "encodeURI",
     "encodeURIComponent",
     "sanitize",
     "sanitizeHTML",
     "sanitizeHtml",
     "htmlspecialchars",
     "html.escape",
     "cgi.escape",
     "urllib.parse.quote",
 }
 
 
 @dataclass(frozen=True)
 class TaintConfig:
     sanitizers: Set[str]
 
 
 class TaintAnalyzer:
     def __init__(self, config: Optional[TaintConfig] = None) -> None:
         self.config = config or TaintConfig(sanitizers=set(DEFAULT_SANITIZERS))
 
    def call_chain(self, parsed: ParsedFile, node) -> List[str]:
        return self._call_chain(parsed, node)

    def member_chain(self, parsed: ParsedFile, node) -> List[str]:
        return self._member_chain(parsed, node)

     def collect_tainted_identifiers(self, parsed: ParsedFile) -> Set[str]:
         tainted: Set[str] = set()
         for node in iter_nodes(parsed.tree.root_node):
             if self._is_source_expression(parsed, node):
                 for name in self._extract_identifiers(parsed, node):
                     tainted.add(name)
             if node.type in parsed.spec.assignment_node_types:
                 targets, value = self._assignment_targets_and_value(parsed, node)
                 if value is None:
                     continue
                 if self.expression_tainted(parsed, value, tainted):
                     tainted.update(targets)
         return tainted
 
     def expression_tainted(
         self,
         parsed: ParsedFile,
         node,
         tainted: Set[str],
     ) -> bool:
         if node is None:
             return False
         if node.type in parsed.spec.string_types:
             return False
         if node.type in parsed.spec.identifier_types:
             name = node_text(parsed, node)
             return name in tainted or name in SOURCE_IDENTIFIERS
         if node.type in parsed.spec.call_node_types:
             call_chain = self._call_chain(parsed, node)
             if call_chain:
                 call_name = ".".join(call_chain)
                 if call_name in self.config.sanitizers:
                     return False
                 if call_name in SOURCE_FUNCTIONS:
                     return True
             if self._is_source_expression(parsed, node):
                 return True
         if self._is_source_expression(parsed, node):
             return True
         for child in node.children:
             if self.expression_tainted(parsed, child, tainted):
                 return True
         return False
 
     def _assignment_targets_and_value(self, parsed: ParsedFile, node) -> tuple[Set[str], Optional[object]]:
         value = (
             node.child_by_field_name("right")
             or node.child_by_field_name("value")
             or node.child_by_field_name("expression")
         )
         left = (
             node.child_by_field_name("left")
             or node.child_by_field_name("target")
             or node.child_by_field_name("name")
             or node.child_by_field_name("pattern")
         )
         targets = set()
         if left is not None:
             targets.update(self._extract_identifiers(parsed, left))
         return targets, value
 
     def _call_chain(self, parsed: ParsedFile, node) -> List[str]:
         target = (
             node.child_by_field_name("function")
             or node.child_by_field_name("callee")
             or node.child_by_field_name("name")
         )
         if target is None:
             return []
         return self._member_chain(parsed, target)
 
     def _member_chain(self, parsed: ParsedFile, node) -> List[str]:
         if node.type in parsed.spec.identifier_types:
             return [node_text(parsed, node)]
         if node.type in parsed.spec.member_node_types:
             left = self._first_child_by_field(
                 node,
                 ["object", "receiver", "value", "expression", "operand", "base"],
             )
             right = self._first_child_by_field(
                 node,
                 ["property", "attribute", "field", "name", "member", "identifier"],
             )
             chain: List[str] = []
             if left is not None:
                 chain.extend(self._member_chain(parsed, left))
             if right is not None:
                 chain.extend(self._member_chain(parsed, right))
             return chain
         return []
 
     def _first_child_by_field(self, node, fields: List[str]):
         for field in fields:
             child = node.child_by_field_name(field)
             if child is not None:
                 return child
         if node.named_children:
             return node.named_children[0]
         return None
 
     def _extract_identifiers(self, parsed: ParsedFile, node) -> Set[str]:
         names: Set[str] = set()
         for child in iter_nodes(node):
             if child.type in parsed.spec.identifier_types:
                 names.add(node_text(parsed, child))
         return names
 
     def _is_source_expression(self, parsed: ParsedFile, node) -> bool:
         if node.type in parsed.spec.identifier_types:
             return node_text(parsed, node) in SOURCE_IDENTIFIERS
         if node.type in parsed.spec.member_node_types:
             chain = self._member_chain(parsed, node)
             if not chain:
                 return False
             if chain[0] in SOURCE_IDENTIFIERS:
                 return True
             if any(part in SOURCE_PROPERTIES for part in chain[1:]):
                 return True
         if node.type in parsed.spec.call_node_types:
             chain = self._call_chain(parsed, node)
             if not chain:
                 return False
             call_name = ".".join(chain)
             if call_name in SOURCE_FUNCTIONS:
                 return True
             if any(part in SOURCE_PROPERTIES for part in chain):
                 return True
         return False
