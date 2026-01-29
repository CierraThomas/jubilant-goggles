 import json
 from dataclasses import dataclass
 from pathlib import Path
 from typing import Any, Dict
 
 import yaml
 
 
 DEFAULT_CONFIG: Dict[str, Any] = {
     "version": 1,
     "rules": {
         "enabled": [
             "SQLI",
             "XSS",
             "HARDCODED_SECRET",
             "COMPLEXITY",
         ],
         "severities": {
             "SQLI": "High",
             "XSS": "High",
             "HARDCODED_SECRET": "High",
             "COMPLEXITY": "Medium",
         },
         "confidence": {
             "SQLI": "Medium",
             "XSS": "Medium",
             "HARDCODED_SECRET": "High",
             "COMPLEXITY": "Low",
         },
     },
     "thresholds": {
         "complexity": {
             "max_cyclomatic": 15,
             "max_nesting": 4,
             "max_function_lines": 80,
         }
     },
     "languages": {
         "enabled": [
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
         ]
     },
     "suppression": {
         "inline_comment": "mlsecscan:ignore",
     },
     "reporting": {
         "format": "text",
         "fail_on_severity": "High",
     },
 }
 
 
 def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
     merged = dict(base)
     for key, value in override.items():
         if isinstance(value, dict) and isinstance(merged.get(key), dict):
             merged[key] = _deep_merge(merged[key], value)
         else:
             merged[key] = value
     return merged
 
 
 @dataclass(frozen=True)
 class Config:
     data: Dict[str, Any]
 
     @classmethod
     def load(cls, path: str | None) -> "Config":
         if not path:
             return cls(DEFAULT_CONFIG)
         config_path = Path(path)
         if not config_path.exists():
             raise FileNotFoundError(f"Config file not found: {path}")
         raw = config_path.read_text(encoding="utf-8")
         if config_path.suffix.lower() in {".json"}:
             overrides = json.loads(raw)
         else:
             overrides = yaml.safe_load(raw) or {}
         merged = _deep_merge(DEFAULT_CONFIG, overrides)
         return cls(merged)
 
     def rule_enabled(self, rule_id: str) -> bool:
         enabled = set(self.data.get("rules", {}).get("enabled", []))
         return rule_id in enabled
 
     def rule_severity(self, rule_id: str) -> str:
         return self.data.get("rules", {}).get("severities", {}).get(rule_id, "Medium")
 
     def rule_confidence(self, rule_id: str) -> str:
         return self.data.get("rules", {}).get("confidence", {}).get(rule_id, "Medium")
 
     def languages(self) -> set[str]:
         return set(self.data.get("languages", {}).get("enabled", []))
 
     def suppression_marker(self) -> str:
         return self.data.get("suppression", {}).get("inline_comment", "mlsecscan:ignore")
 
     def thresholds(self) -> Dict[str, Any]:
         return self.data.get("thresholds", {})
 
     def reporting(self) -> Dict[str, Any]:
         return self.data.get("reporting", {})
