 from __future__ import annotations
 
 from typing import Iterable, Type
 
 from mlsecscan.core.config import Config
 from mlsecscan.core.rule import Rule
 from mlsecscan.rules.complexity import ComplexityRule
 from mlsecscan.rules.hardcoded_secret import HardcodedSecretRule
 from mlsecscan.rules.sql_injection import SQLInjectionRule
 from mlsecscan.rules.xss import XSSRule
 
 
 RULES: list[Type[Rule]] = [
     SQLInjectionRule,
     XSSRule,
     HardcodedSecretRule,
     ComplexityRule,
 ]
 
 
 def load_rules(config: Config) -> Iterable[Rule]:
     for rule_cls in RULES:
         rule = rule_cls(config)
         if rule.enabled():
             yield rule
