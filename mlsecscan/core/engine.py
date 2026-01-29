 from __future__ import annotations
 
 from dataclasses import dataclass
 from pathlib import Path
 from typing import Iterable, List
 
 from mlsecscan.core.config import Config
 from mlsecscan.core.finding import Finding
 from mlsecscan.core.registry import load_rules
 from mlsecscan.core.rule import RuleContext
 from mlsecscan.parsing.treesitter import parse_file
 from mlsecscan.utils.files import iter_source_files
 
 
 @dataclass(frozen=True)
 class ScanReport:
     findings: List[Finding]
     suppressed: int
     applied_fixes: int
     skipped_fixes: int
 
 
 class ScanEngine:
     def __init__(self, config: Config) -> None:
         self.config = config
         self.rules = list(load_rules(config))
         self.context = RuleContext(config=config)
 
     def scan(
         self,
         path: str,
         apply_fixes: bool = False,
         dry_run: bool = True,
     ) -> ScanReport:
         findings: List[Finding] = []
         suppressed = 0
         applied_fixes = 0
         skipped_fixes = 0
         for file_path in iter_source_files(path, self.config.languages()):
             parsed = parse_file(file_path, self._language_for_file(file_path))
             if parsed is None:
                 continue
             file_findings = []
             for rule in self.rules:
                 if not rule.applies_to(parsed):
                     continue
                 for finding in rule.check(parsed, self.context):
                     if self._is_suppressed(parsed, finding):
                         suppressed += 1
                         continue
                     file_findings.append(finding)
             if apply_fixes and file_findings:
                 applied, skipped = self._apply_fixes(parsed, file_findings, dry_run=dry_run)
                 applied_fixes += applied
                 skipped_fixes += skipped
             findings.extend(file_findings)
         findings.sort(key=lambda f: (f.location.path, f.location.line, f.rule_id))
         return ScanReport(
             findings=findings,
             suppressed=suppressed,
             applied_fixes=applied_fixes,
             skipped_fixes=skipped_fixes,
         )
 
     def _language_for_file(self, path: str) -> str:
         # parse_file expects a language name; iter_source_files already filtered.
         from mlsecscan.parsing.treesitter import language_for_path
 
         language = language_for_path(path)
         if language is None:
             raise ValueError(f"Unsupported language for path: {path}")
         return language
 
     def _is_suppressed(self, parsed, finding: Finding) -> bool:
         marker = self.config.suppression_marker()
         lines = parsed.lines
         idx = finding.location.line - 1
         if idx < 0 or idx >= len(lines):
             return False
         if marker in lines[idx]:
             return True
         if idx > 0 and marker in lines[idx - 1]:
             return True
         return False
 
     def _apply_fixes(self, parsed, findings: Iterable[Finding], dry_run: bool) -> tuple[int, int]:
         text = parsed.text
         applied = 0
         skipped = 0
         for finding in findings:
             if finding.fix is None or not finding.fix.auto_applicable:
                 skipped += 1
                 continue
             if finding.fix.before not in text:
                 skipped += 1
                 continue
             if dry_run:
                 skipped += 1
                 continue
             text = text.replace(finding.fix.before, finding.fix.after, 1)
             applied += 1
         if applied > 0 and not dry_run:
             Path(parsed.path).write_text(text, encoding="utf-8")
         return applied, skipped
