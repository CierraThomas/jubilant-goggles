 from __future__ import annotations
 
 from typing import Iterable
 
 from mlsecscan.analysis.complexity import analyze_complexity
 from mlsecscan.core.finding import Finding
 from mlsecscan.core.rule import Rule, RuleContext
 from mlsecscan.parsing.treesitter import ParsedFile
 from mlsecscan.utils.location import location_from_node
 
 
 class ComplexityRule(Rule):
     rule_id = "COMPLEXITY"
     name = "Code Complexity"
     description = "Flags functions that exceed complexity thresholds."
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
         thresholds = context.config.thresholds().get("complexity", {})
         max_cyclomatic = thresholds.get("max_cyclomatic", 15)
         max_nesting = thresholds.get("max_nesting", 4)
         max_lines = thresholds.get("max_function_lines", 80)
         for metric in analyze_complexity(parsed):
             violations = []
             if metric.cyclomatic > max_cyclomatic:
                 violations.append(f"cyclomatic {metric.cyclomatic} > {max_cyclomatic}")
             if metric.max_nesting > max_nesting:
                 violations.append(f"nesting {metric.max_nesting} > {max_nesting}")
             if metric.line_count > max_lines:
                 violations.append(f"lines {metric.line_count} > {max_lines}")
             if not violations:
                 continue
             node = self._find_function_node(parsed, metric.start_line)
             location = location_from_node(parsed, node) if node else location_from_node(parsed, parsed.tree.root_node)
             yield Finding(
                 rule_id=self.rule_id,
                 title="Function exceeds complexity thresholds",
                 severity=self.severity(),
                 confidence=self.confidence(),
                 message=(
                     f"Function '{metric.name}' exceeds configured thresholds: "
                     + ", ".join(violations)
                 ),
                 location=location,
                 remediation=(
                     "Refactor the function by extracting helpers, reducing nesting, "
                     "and simplifying control flow."
                 ),
                 references=[
                     "https://owasp.org/www-community/controls/Code_Review",
                 ],
             )
 
     def _find_function_node(self, parsed: ParsedFile, start_line: int):
         for node in parsed.tree.root_node.children:
             if node.type in parsed.spec.function_node_types and node.start_point[0] + 1 == start_line:
                 return node
         return None
