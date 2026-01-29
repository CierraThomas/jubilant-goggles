 from __future__ import annotations
 
 from typing import Iterable, Set
 
 from mlsecscan.analysis.ast import assignment_parts, extract_call_arguments
 from mlsecscan.analysis.taint import TaintAnalyzer
 from mlsecscan.core.finding import Finding
 from mlsecscan.core.rule import Rule, RuleContext
 from mlsecscan.parsing.treesitter import ParsedFile, iter_nodes
 from mlsecscan.utils.location import location_from_node
 
 
 XSS_SINK_PROPERTIES: Set[str] = {
     "innerHTML",
     "outerHTML",
     "html",
     "dangerouslySetInnerHTML",
 }
 
 XSS_SINK_CALLS: Set[str] = {
     "document.write",
     "document.writeln",
     "response.write",
     "res.send",
     "res.write",
     "render",
     "send",
     "write",
     "setInnerHTML",
     "setHtml",
 }
 
 
 class XSSRule(Rule):
     rule_id = "XSS"
     name = "Cross-Site Scripting"
     description = "Detects tainted data flowing into HTML-rendering sinks."
     languages = {"javascript", "typescript", "python", "ruby", "java", "kotlin"}
 
     def check(self, parsed: ParsedFile, context: RuleContext) -> Iterable[Finding]:
         analyzer = TaintAnalyzer()
         tainted = analyzer.collect_tainted_identifiers(parsed)
         for node in iter_nodes(parsed.tree.root_node):
             if node.type in parsed.spec.call_node_types:
                 chain = analyzer.call_chain(parsed, node)
                 if not chain:
                     continue
                 full_name = ".".join(chain)
                 if chain[-1] not in XSS_SINK_CALLS and full_name not in XSS_SINK_CALLS:
                     continue
                 args = extract_call_arguments(parsed, node)
                 if args and any(analyzer.expression_tainted(parsed, arg, tainted) for arg in args):
                     yield self._finding(parsed, node)
             if node.type in parsed.spec.assignment_node_types:
                 left, value = assignment_parts(node)
                 if left is None or value is None:
                     continue
                 chain = analyzer.member_chain(parsed, left)
                 if not chain:
                     continue
                 if chain[-1] not in XSS_SINK_PROPERTIES:
                     continue
                 if analyzer.expression_tainted(parsed, value, tainted):
                     yield self._finding(parsed, node)
 
     def _finding(self, parsed: ParsedFile, node) -> Finding:
         location = location_from_node(parsed, node)
         return Finding(
             rule_id=self.rule_id,
             title="Possible XSS via tainted HTML sink",
             severity=self.severity(),
             confidence=self.confidence(),
             message=(
                 "User-controlled data appears to reach an HTML rendering sink. "
                 "Escape or sanitize output before rendering to prevent XSS."
             ),
             location=location,
             remediation=(
                 "Apply context-appropriate output encoding (HTML, attribute, URL) "
                 "or sanitize input using a vetted library before rendering."
             ),
             references=[
                 "https://owasp.org/www-community/attacks/xss/",
             ],
         )
