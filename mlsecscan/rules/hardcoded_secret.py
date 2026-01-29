 from __future__ import annotations
 
 import re
 from typing import Iterable, Optional
 
 from mlsecscan.analysis.ast import assignment_parts
 from mlsecscan.core.finding import Finding, Fix
 from mlsecscan.core.rule import Rule, RuleContext
 from mlsecscan.parsing.treesitter import ParsedFile, iter_nodes, node_text
 from mlsecscan.utils.diff import unified_diff
 from mlsecscan.utils.location import location_from_node
 
 
 SECRET_NAME_HINTS = {
     "password",
     "passwd",
     "secret",
     "token",
     "api_key",
     "apikey",
     "access_key",
     "private_key",
 }
 
 SECRET_VALUE_PATTERNS = [
     re.compile(r"AKIA[0-9A-Z]{16}"),
     re.compile(r"ASIA[0-9A-Z]{16}"),
     re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
     re.compile(r"sk_(live|test)_[0-9a-zA-Z]{16,}"),
     re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,}"),
     re.compile(r"-----BEGIN (RSA |EC |)PRIVATE KEY-----"),
 ]
 
 
 class HardcodedSecretRule(Rule):
     rule_id = "HARDCODED_SECRET"
     name = "Hard-coded secret"
     description = "Detects secrets embedded directly in source code."
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
         for node in iter_nodes(parsed.tree.root_node):
             if node.type not in parsed.spec.assignment_node_types:
                 continue
             left, value = assignment_parts(node)
             if left is None or value is None:
                 continue
             if value.type not in parsed.spec.string_types:
                 continue
             var_name = self._identifier_from_node(parsed, left)
             literal = self._string_literal(parsed, value)
             if not literal:
                 continue
             if not self._looks_like_secret(var_name, literal):
                 continue
             location = location_from_node(parsed, node)
             fix = self._build_fix(parsed, node, value, var_name, literal)
             yield Finding(
                 rule_id=self.rule_id,
                 title="Hard-coded secret detected",
                 severity=self.severity(),
                 confidence=self.confidence(),
                 message=(
                     "A credential-like value is embedded directly in code. "
                     "Hard-coded secrets are easily exposed and difficult to rotate."
                 ),
                 location=location,
                 remediation=(
                     "Move secrets to environment variables or a secrets manager, "
                     "and rotate the exposed credential."
                 ),
                 references=[
                     "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                 ],
                 fix=fix,
             )
 
     def _identifier_from_node(self, parsed: ParsedFile, node) -> str:
         for child in iter_nodes(node):
             if child.type in parsed.spec.identifier_types:
                 return node_text(parsed, child)
         return ""
 
     def _string_literal(self, parsed: ParsedFile, node) -> str:
         raw = node_text(parsed, node).strip()
         if not raw:
             return ""
         if raw[0] in {"'", '"', "`"}:
             raw = raw.strip("`\"'")
         return raw
 
     def _looks_like_secret(self, name: str, literal: str) -> bool:
         name_lower = name.lower()
         if any(hint in name_lower for hint in SECRET_NAME_HINTS):
             return True
         for pattern in SECRET_VALUE_PATTERNS:
             if pattern.search(literal):
                 return True
         return False
 
     def _build_fix(
         self,
         parsed: ParsedFile,
         node,
         value_node,
         name: str,
         literal: str,
     ) -> Optional[Fix]:
         if not name:
             return None
         if parsed.language in {"javascript", "typescript"}:
             env_ref = f"process.env.{name.upper()}"
         elif parsed.language == "python":
             env_ref = f'os.environ.get("{name.upper()}")'
         else:
             env_ref = ""
         if not env_ref:
             return None
         before = node_text(parsed, node)
         literal_token = node_text(parsed, value_node)
         after = before.replace(literal_token, env_ref, 1)
         if before == after:
             return None
         diff = unified_diff(before, after, filename=parsed.path)
         return Fix(
             description="Replace hard-coded secret with environment variable.",
             before=before,
             after=after,
             diff=diff,
             auto_applicable=parsed.language in {"javascript", "typescript"},
         )
