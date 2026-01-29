"""
Insecure deserialization detection rules.

Detects potentially dangerous deserialization of untrusted data.
"""

import re
from typing import Generator

from securityscanner.core.rules import (
    Rule, RuleMetadata, RuleType, AnalysisContext, rule
)
from securityscanner.core.findings import (
    Finding, Severity, Confidence, FindingCategory, CodeLocation, Remediation
)


@rule
class InsecureDeserializationRule(Rule):
    """
    Detects insecure deserialization vulnerabilities.
    
    Deserializing untrusted data can lead to remote code execution,
    denial of service, or other attacks.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-DESER-001",
            name="Insecure Deserialization",
            description="Detects use of potentially dangerous deserialization functions that may lead to remote code execution.",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=FindingCategory.DESERIALIZATION,
            rule_type=RuleType.SECURITY,
            languages=["python", "javascript", "java", "ruby", "csharp", "php"],
            tags=["deserialization", "rce", "injection", "owasp-a08"],
            cwe_id="CWE-502",
            owasp_id="A08:2021",
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for insecure deserialization."""
        patterns = self._get_patterns(context.language)
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern, desc, severity in patterns:
                if pattern.search(line):
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        severity=severity,
                        description=f"Insecure deserialization: {desc}. Deserializing untrusted data can lead to remote code execution.",
                        remediation=self._get_remediation(context.language),
                    )
                    
                    yield finding
    
    def _get_patterns(self, language: str) -> list:
        """Get deserialization patterns for the given language."""
        patterns = {
            "python": [
                (re.compile(r'pickle\.loads?\s*\('), "pickle deserialization", Severity.CRITICAL),
                (re.compile(r'cPickle\.loads?\s*\('), "cPickle deserialization", Severity.CRITICAL),
                (re.compile(r'_pickle\.loads?\s*\('), "_pickle deserialization", Severity.CRITICAL),
                (re.compile(r'shelve\.open\s*\('), "shelve module usage", Severity.HIGH),
                (re.compile(r'marshal\.loads?\s*\('), "marshal deserialization", Severity.HIGH),
                (re.compile(r'yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader)'), "yaml.load without safe Loader", Severity.CRITICAL),
                (re.compile(r'yaml\.unsafe_load\s*\('), "yaml.unsafe_load", Severity.CRITICAL),
                (re.compile(r'jsonpickle\.decode\s*\('), "jsonpickle deserialization", Severity.HIGH),
            ],
            "javascript": [
                (re.compile(r'node-serialize.*unserialize'), "node-serialize deserialization", Severity.CRITICAL),
                (re.compile(r'serialize-javascript.*deserialize'), "serialize-javascript usage", Severity.HIGH),
                (re.compile(r'\.deserialize\s*\([^)]*(?:request|req|body|input|data)'), "Generic deserialization of user input", Severity.HIGH),
            ],
            "java": [
                (re.compile(r'ObjectInputStream'), "ObjectInputStream usage", Severity.HIGH),
                (re.compile(r'\.readObject\s*\('), "readObject() call", Severity.HIGH),
                (re.compile(r'XMLDecoder'), "XMLDecoder usage", Severity.CRITICAL),
                (re.compile(r'XStream\.fromXML'), "XStream deserialization", Severity.HIGH),
                (re.compile(r'ObjectMapper.*readValue.*Object\.class'), "Jackson polymorphic deserialization", Severity.HIGH),
            ],
            "ruby": [
                (re.compile(r'Marshal\.load\s*\('), "Marshal.load", Severity.CRITICAL),
                (re.compile(r'YAML\.load\s*\([^)]*\)(?!\s*,\s*(?:safe|permitted))'), "YAML.load without safe mode", Severity.CRITICAL),
                (re.compile(r'Psych\.load\s*\([^)]*\)(?!\s*,\s*(?:safe|permitted))'), "Psych.load without safe mode", Severity.HIGH),
            ],
            "csharp": [
                (re.compile(r'BinaryFormatter'), "BinaryFormatter usage", Severity.CRITICAL),
                (re.compile(r'NetDataContractSerializer'), "NetDataContractSerializer usage", Severity.CRITICAL),
                (re.compile(r'SoapFormatter'), "SoapFormatter usage", Severity.CRITICAL),
                (re.compile(r'LosFormatter'), "LosFormatter usage", Severity.HIGH),
                (re.compile(r'ObjectStateFormatter'), "ObjectStateFormatter usage", Severity.HIGH),
                (re.compile(r'JavaScriptSerializer.*Deserialize<Object>'), "JavaScriptSerializer with Object type", Severity.HIGH),
            ],
            "php": [
                (re.compile(r'unserialize\s*\('), "unserialize() call", Severity.CRITICAL),
                (re.compile(r'maybe_unserialize\s*\('), "WordPress maybe_unserialize()", Severity.HIGH),
            ],
        }
        
        return patterns.get(language, [])
    
    def _get_remediation(self, language: str) -> Remediation:
        """Get language-specific remediation."""
        remediations = {
            "python": Remediation(
                description="Avoid using pickle for untrusted data. Use JSON or other safe formats. If YAML is needed, use yaml.safe_load().",
                before_code='data = pickle.loads(untrusted_input)',
                after_code='import json\ndata = json.loads(untrusted_input)  # For JSON\n# Or: data = yaml.safe_load(untrusted_input)  # For YAML',
                cwe_id="CWE-502",
                references=[
                    "https://docs.python.org/3/library/pickle.html#restricting-globals",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
                ],
            ),
            "java": Remediation(
                description="Avoid deserializing untrusted data with ObjectInputStream. Use JSON with type validation, or implement ValidatingObjectInputStream with a whitelist.",
                cwe_id="CWE-502",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html#java",
                ],
            ),
            "ruby": Remediation(
                description="Use YAML.safe_load() instead of YAML.load(). Avoid Marshal.load() on untrusted data.",
                before_code='data = YAML.load(untrusted_input)',
                after_code='data = YAML.safe_load(untrusted_input)',
                cwe_id="CWE-502",
            ),
            "csharp": Remediation(
                description="Avoid BinaryFormatter and related formatters. Use JSON.NET with TypeNameHandling.None (default).",
                cwe_id="CWE-502",
                references=[
                    "https://docs.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide",
                ],
            ),
        }
        
        return remediations.get(language, Remediation(
            description="Avoid deserializing untrusted data with native serialization formats. Use safe alternatives like JSON with strict type checking.",
            cwe_id="CWE-502",
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
            ],
        ))


@rule
class UnsafeYAMLRule(Rule):
    """
    Detects unsafe YAML loading.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-DESER-002",
            name="Unsafe YAML Loading",
            description="Detects unsafe YAML loading that may lead to code execution.",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=FindingCategory.DESERIALIZATION,
            rule_type=RuleType.SECURITY,
            languages=["python", "ruby"],
            tags=["yaml", "deserialization", "rce", "owasp-a08"],
            cwe_id="CWE-502",
            owasp_id="A08:2021",
            auto_fixable=True,
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for unsafe YAML loading."""
        patterns = {
            "python": [
                # yaml.load without Loader argument
                (re.compile(r'yaml\.load\s*\(\s*[^,)]+\s*\)'), "yaml.load() without Loader argument"),
                (re.compile(r'yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.(?:Unsafe)?Loader'), "yaml.load() with unsafe Loader"),
                (re.compile(r'yaml\.full_load\s*\('), "yaml.full_load() - allows arbitrary Python objects"),
                (re.compile(r'yaml\.unsafe_load\s*\('), "yaml.unsafe_load()"),
            ],
            "ruby": [
                (re.compile(r'YAML\.load\s*\([^)]*\)(?!\s*,\s*(?:permitted_classes|safe))'), "YAML.load() without restrictions"),
                (re.compile(r'Psych\.load\s*\([^)]*\)(?!\s*,\s*(?:permitted_classes|safe))'), "Psych.load() without restrictions"),
            ],
        }
        
        lang_patterns = patterns.get(context.language, [])
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern, desc in lang_patterns:
                if pattern.search(line):
                    # Skip if safe_load is on the same line
                    if 'safe_load' in line or 'SafeLoader' in line:
                        continue
                    
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        description=f"Unsafe YAML loading: {desc}. This can execute arbitrary Python/Ruby code.",
                        remediation=Remediation(
                            description="Use yaml.safe_load() or yaml.load() with Loader=yaml.SafeLoader.",
                            before_code='data = yaml.load(file_content)',
                            after_code='data = yaml.safe_load(file_content)',
                            cwe_id="CWE-502",
                            auto_fixable=True,
                        ),
                    )
                    
                    yield finding
