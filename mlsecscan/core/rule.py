 from __future__ import annotations
 
 from dataclasses import dataclass
 from typing import Iterable, Optional
 
 from mlsecscan.core.config import Config
 from mlsecscan.core.finding import Finding
 from mlsecscan.parsing.treesitter import ParsedFile
 
 
 @dataclass(frozen=True)
 class RuleContext:
     config: Config
 
 
 class Rule:
     rule_id = "GENERIC"
     name = "Generic Rule"
     description = ""
     languages: set[str] = set()
 
     def __init__(self, config: Config) -> None:
         self.config = config
 
     def enabled(self) -> bool:
         return self.config.rule_enabled(self.rule_id)
 
     def applies_to(self, parsed: ParsedFile) -> bool:
         return parsed.language in self.languages
 
     def check(self, parsed: ParsedFile, context: RuleContext) -> Iterable[Finding]:
         return []
 
     def severity(self) -> str:
         return self.config.rule_severity(self.rule_id)
 
     def confidence(self) -> str:
         return self.config.rule_confidence(self.rule_id)
 
     def suppression_marker(self) -> str:
         return self.config.suppression_marker()
