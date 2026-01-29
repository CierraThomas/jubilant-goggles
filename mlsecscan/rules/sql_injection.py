 from __future__ import annotations
 
 from typing import Iterable, Set
 
 from mlsecscan.analysis.ast import extract_call_arguments
 from mlsecscan.analysis.taint import TaintAnalyzer
 from mlsecscan.core.finding import Finding
 from mlsecscan.core.rule import Rule, RuleContext
 from mlsecscan.parsing.treesitter import ParsedFile, iter_nodes
 from mlsecscan.utils.location import location_from_node
 
 
 SQL_SINKS: Set[str] = {
     "execute",
     "executemany",
     "query",
     "raw",
     "exec",
     "executeQuery",
     "prepareStatement",
 }
 
 
 class SQLInjectionRule(Rule):
     rule_id = "SQLI"
     name = "SQL Injection"
     description = "Detects user-controlled input reaching SQL execution APIs."
     languages = {
         "c",
         "cpp",
         "csharp",
         "go",
         "java",
         "kotlin",
         "javascript",
         "typescript",
         "python",
         "ruby",
         "rust",
         "swift",
     }
 
     def check(self, parsed: ParsedFile, context: RuleContext) -> Iterable[Finding]:
         analyzer = TaintAnalyzer()
         tainted = analyzer.collect_tainted_identifiers(parsed)
         for node in iter_nodes(parsed.tree.root_node):
             if node.type not in parsed.spec.call_node_types:
                 continue
             call_chain = analyzer.call_chain(parsed, node)
             if not call_chain:
                 continue
             if call_chain[-1] not in SQL_SINKS and ".".join(call_chain) not in SQL_SINKS:
                 continue
             args = extract_call_arguments(parsed, node)
             if not args:
                 continue
             if any(analyzer.expression_tainted(parsed, arg, tainted) for arg in args):
                 location = location_from_node(parsed, node)
                 yield Finding(
                     rule_id=self.rule_id,
                     title="Possible SQL injection via tainted input",
                     severity=self.severity(),
                     confidence=self.confidence(),
                     message=(
                         "User-controlled data appears to reach a SQL execution call. "
                         "Parameterize the query instead of concatenating or interpolating input."
                     ),
                     location=location,
                     remediation=(
                         "Use parameterized queries or prepared statements. "
                         "Bind user input as parameters rather than concatenating into SQL strings."
                     ),
                     references=[
                         "https://owasp.org/www-community/attacks/SQL_Injection",
                     ],
                 )
