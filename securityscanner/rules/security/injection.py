"""
Injection vulnerability detection rules.

Detects SQL Injection, Command Injection, LDAP Injection, and other
injection vulnerabilities using pattern matching and taint analysis.
"""

import re
from typing import Generator, List, Optional, Dict, Any

from securityscanner.core.rules import (
    Rule, PatternRule, TaintRule, RuleMetadata, RuleType, AnalysisContext, rule
)
from securityscanner.core.findings import (
    Finding, Severity, Confidence, FindingCategory, CodeLocation, Remediation
)


@rule
class SQLInjectionRule(Rule):
    """
    Detects potential SQL injection vulnerabilities.
    
    SQL injection occurs when user-controlled input is concatenated
    directly into SQL queries without proper parameterization.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-INJ-001",
            name="SQL Injection",
            description="Detects potential SQL injection vulnerabilities where user input may be directly concatenated into SQL queries.",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=FindingCategory.INJECTION,
            rule_type=RuleType.SECURITY,
            languages=["python", "javascript", "java", "go", "ruby", "csharp", "php"],
            tags=["injection", "sql", "database", "owasp-a03"],
            cwe_id="CWE-89",
            owasp_id="A03:2021",
            auto_fixable=True,
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for SQL injection vulnerabilities."""
        patterns = self._get_patterns(context.language)
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern, pattern_desc in patterns:
                if pattern.search(line):
                    # Check for string formatting/concatenation
                    if self._is_vulnerable(line, context.language):
                        location = CodeLocation(
                            file_path=context.file_path,
                            start_line=line_num,
                            end_line=line_num,
                        )
                        
                        snippet = context.get_snippet(line_num)
                        
                        finding = self.create_finding(
                            location=location,
                            snippet=snippet,
                            description=f"Potential SQL injection: {pattern_desc}. User input appears to be directly concatenated into a SQL query.",
                            remediation=self._get_remediation(context.language),
                        )
                        
                        yield finding
    
    def _get_patterns(self, language: str) -> List[tuple]:
        """Get SQL patterns for the given language."""
        common_patterns = [
            (re.compile(r'execute\s*\([^)]*["\'].*%'), "String formatting in SQL execute"),
            (re.compile(r'execute\s*\([^)]*\.format\s*\('), "String format() in SQL execute"),
            (re.compile(r'execute\s*\([^)]*\+'), "String concatenation in SQL execute"),
            (re.compile(r'execute\s*\(.*f["\']'), "f-string in SQL execute"),
        ]
        
        language_patterns = {
            "python": [
                (re.compile(r'cursor\.execute\s*\([^)]*%'), "String formatting in cursor.execute"),
                (re.compile(r'cursor\.execute\s*\([^)]*\.format'), "format() in cursor.execute"),
                (re.compile(r'cursor\.execute\s*\(.*f["\']'), "f-string in cursor.execute"),
                (re.compile(r'\.execute\s*\(["\'][^"\']*\s*\+'), "Concatenation in execute()"),
                (re.compile(r'\.raw\s*\([^)]*%'), "String formatting in raw SQL"),
            ],
            "javascript": [
                (re.compile(r'\.query\s*\([^)]*\+'), "Concatenation in query()"),
                (re.compile(r'\.query\s*\(`[^`]*\$\{'), "Template literal in query()"),
                (re.compile(r'execute\s*\([^)]*\+'), "Concatenation in execute()"),
            ],
            "java": [
                (re.compile(r'Statement.*execute.*\+'), "Concatenation with Statement"),
                (re.compile(r'createStatement.*execute'), "createStatement without PreparedStatement"),
                (re.compile(r'executeQuery\s*\([^)]*\+'), "Concatenation in executeQuery()"),
            ],
            "go": [
                (re.compile(r'db\.(?:Query|Exec)\s*\([^)]*\+'), "Concatenation in Query/Exec"),
                (re.compile(r'fmt\.Sprintf.*(?:Query|Exec)'), "Sprintf with Query/Exec"),
            ],
            "ruby": [
                (re.compile(r'\.execute\s*\([^)]*#\{'), "Interpolation in execute"),
                (re.compile(r'\.find_by_sql\s*\([^)]*#\{'), "Interpolation in find_by_sql"),
                (re.compile(r'\.where\s*\(["\'][^"\']*#\{'), "Interpolation in where clause"),
            ],
            "csharp": [
                (re.compile(r'SqlCommand.*\+'), "Concatenation with SqlCommand"),
                (re.compile(r'ExecuteReader\s*\([^)]*\+'), "Concatenation in ExecuteReader"),
                (re.compile(r'\$".*(?:SELECT|INSERT|UPDATE|DELETE)'), "Interpolated SQL string"),
            ],
        }
        
        return common_patterns + language_patterns.get(language, [])
    
    def _is_vulnerable(self, line: str, language: str) -> bool:
        """Check if the line contains vulnerable SQL construction."""
        # Check for parameterized queries (safe patterns)
        safe_patterns = [
            r'\?\s*,',  # Placeholder with tuple
            r'%s\s*[,)].*,\s*\(',  # Python DB-API with tuple
            r':\w+',  # Named parameters
            r'@\w+',  # SQL Server parameters
            r'\$\d+',  # PostgreSQL parameters
        ]
        
        for pattern in safe_patterns:
            if re.search(pattern, line):
                return False
        
        return True
    
    def _get_remediation(self, language: str) -> Remediation:
        """Get language-specific remediation."""
        remediations = {
            "python": Remediation(
                description="Use parameterized queries instead of string formatting. Pass user input as a tuple parameter to execute().",
                before_code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                after_code='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                owasp_reference="https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
                cwe_id="CWE-89",
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://docs.python.org/3/library/sqlite3.html#sqlite3.Cursor.execute",
                ],
                auto_fixable=True,
            ),
            "javascript": Remediation(
                description="Use parameterized queries with placeholders. Never concatenate user input into SQL strings.",
                before_code='db.query("SELECT * FROM users WHERE id = " + userId)',
                after_code='db.query("SELECT * FROM users WHERE id = ?", [userId])',
                owasp_reference="https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
                cwe_id="CWE-89",
                auto_fixable=True,
            ),
            "java": Remediation(
                description="Use PreparedStatement instead of Statement. Never concatenate user input into SQL strings.",
                before_code='stmt.executeQuery("SELECT * FROM users WHERE id = " + userId)',
                after_code='PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nps.setString(1, userId);\nps.executeQuery()',
                owasp_reference="https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
                cwe_id="CWE-89",
                auto_fixable=True,
            ),
        }
        
        return remediations.get(language, Remediation(
            description="Use parameterized queries instead of string concatenation. Never directly include user input in SQL strings.",
            owasp_reference="https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html",
            cwe_id="CWE-89",
        ))


@rule
class CommandInjectionRule(Rule):
    """
    Detects potential command injection vulnerabilities.
    
    Command injection occurs when user-controlled input is passed
    to system command execution functions without proper sanitization.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-INJ-002",
            name="Command Injection",
            description="Detects potential command injection vulnerabilities where user input may be passed to system commands.",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=FindingCategory.INJECTION,
            rule_type=RuleType.SECURITY,
            languages=["python", "javascript", "java", "go", "ruby", "csharp", "php"],
            tags=["injection", "command", "os", "rce", "owasp-a03"],
            cwe_id="CWE-78",
            owasp_id="A03:2021",
            auto_fixable=False,
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for command injection vulnerabilities."""
        patterns = self._get_patterns(context.language)
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern, pattern_desc, check_func in patterns:
                match = pattern.search(line)
                if match:
                    if check_func is None or check_func(line):
                        location = CodeLocation(
                            file_path=context.file_path,
                            start_line=line_num,
                            end_line=line_num,
                        )
                        
                        snippet = context.get_snippet(line_num)
                        
                        finding = self.create_finding(
                            location=location,
                            snippet=snippet,
                            description=f"Potential command injection: {pattern_desc}.",
                            remediation=self._get_remediation(context.language),
                        )
                        
                        yield finding
    
    def _get_patterns(self, language: str) -> List[tuple]:
        """Get command execution patterns for the given language."""
        def has_variable(line: str) -> bool:
            """Check if line contains variable interpolation."""
            return any(p in line for p in ['+', 'f"', "f'", '.format', '%s', '${', '#{'])
        
        patterns = {
            "python": [
                (re.compile(r'os\.system\s*\('), "os.system() call", has_variable),
                (re.compile(r'os\.popen\s*\('), "os.popen() call", has_variable),
                (re.compile(r'subprocess\.call\s*\([^)]*shell\s*=\s*True'), "subprocess with shell=True", None),
                (re.compile(r'subprocess\.run\s*\([^)]*shell\s*=\s*True'), "subprocess.run with shell=True", None),
                (re.compile(r'subprocess\.Popen\s*\([^)]*shell\s*=\s*True'), "subprocess.Popen with shell=True", None),
                (re.compile(r'commands\.getoutput\s*\('), "commands.getoutput() call", has_variable),
            ],
            "javascript": [
                (re.compile(r'child_process\.exec\s*\('), "child_process.exec() call", has_variable),
                (re.compile(r'child_process\.execSync\s*\('), "child_process.execSync() call", has_variable),
                (re.compile(r'require\s*\([\'"]child_process[\'"]\)\.exec'), "child_process.exec() call", has_variable),
                (re.compile(r'\.exec\s*\([^)]*\+'), "exec with string concatenation", None),
            ],
            "java": [
                (re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\('), "Runtime.exec() call", has_variable),
                (re.compile(r'ProcessBuilder\s*\('), "ProcessBuilder usage", has_variable),
            ],
            "go": [
                (re.compile(r'exec\.Command\s*\([^)]*\+'), "exec.Command with concatenation", None),
                (re.compile(r'exec\.CommandContext\s*\([^)]*\+'), "exec.CommandContext with concatenation", None),
            ],
            "ruby": [
                (re.compile(r'`[^`]*#\{'), "Backtick command with interpolation", None),
                (re.compile(r'system\s*\([^)]*#\{'), "system() with interpolation", None),
                (re.compile(r'exec\s*\([^)]*#\{'), "exec() with interpolation", None),
                (re.compile(r'%x\[[^\]]*#\{'), "%x with interpolation", None),
            ],
            "csharp": [
                (re.compile(r'Process\.Start\s*\([^)]*\+'), "Process.Start with concatenation", None),
                (re.compile(r'ProcessStartInfo.*\$"'), "ProcessStartInfo with interpolation", None),
            ],
        }
        
        return patterns.get(language, [])
    
    def _get_remediation(self, language: str) -> Remediation:
        """Get language-specific remediation."""
        return Remediation(
            description="Avoid passing user input directly to command execution functions. Use parameterized commands, input validation, and allowlists where possible.",
            references=[
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            ],
            owasp_reference="https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            cwe_id="CWE-78",
            auto_fixable=False,
        )


@rule
class LDAPInjectionRule(Rule):
    """
    Detects potential LDAP injection vulnerabilities.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-INJ-003",
            name="LDAP Injection",
            description="Detects potential LDAP injection vulnerabilities where user input may be included in LDAP queries.",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category=FindingCategory.INJECTION,
            rule_type=RuleType.SECURITY,
            languages=["python", "javascript", "java", "csharp"],
            tags=["injection", "ldap", "directory", "owasp-a03"],
            cwe_id="CWE-90",
            owasp_id="A03:2021",
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for LDAP injection vulnerabilities."""
        patterns = [
            (re.compile(r'ldap.*search.*\(.*\+'), "LDAP search with string concatenation"),
            (re.compile(r'ldap.*filter.*=.*\+'), "LDAP filter with concatenation"),
            (re.compile(r'\(.*=.*%s'), "LDAP filter with string formatting"),
            (re.compile(r'DirectorySearcher.*Filter.*\+'), "DirectorySearcher with concatenation"),
        ]
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern, pattern_desc in patterns:
                if pattern.search(line.lower()):
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        description=f"Potential LDAP injection: {pattern_desc}.",
                        remediation=Remediation(
                            description="Escape special LDAP characters in user input before including in LDAP queries. Use parameterized LDAP queries where available.",
                            cwe_id="CWE-90",
                            references=["https://owasp.org/www-community/attacks/LDAP_Injection"],
                        ),
                    )
                    
                    yield finding


@rule
class CodeInjectionRule(Rule):
    """
    Detects potential code injection vulnerabilities.
    
    Code injection occurs when user input is passed to code
    evaluation functions like eval(), exec(), or Function().
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-INJ-004",
            name="Code Injection",
            description="Detects use of code evaluation functions that may lead to code injection.",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=FindingCategory.INJECTION,
            rule_type=RuleType.SECURITY,
            languages=["python", "javascript", "ruby", "php"],
            tags=["injection", "eval", "rce", "owasp-a03"],
            cwe_id="CWE-94",
            owasp_id="A03:2021",
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for code injection vulnerabilities."""
        patterns = {
            "python": [
                (re.compile(r'\beval\s*\('), "Use of eval()"),
                (re.compile(r'\bexec\s*\('), "Use of exec()"),
                (re.compile(r'\bcompile\s*\([^)]*,\s*[^)]*,\s*[\'"]exec[\'"]'), "Use of compile() with exec mode"),
                (re.compile(r'__import__\s*\('), "Use of __import__()"),
            ],
            "javascript": [
                (re.compile(r'\beval\s*\('), "Use of eval()"),
                (re.compile(r'new\s+Function\s*\('), "Use of Function constructor"),
                (re.compile(r'setTimeout\s*\([\'"`]'), "setTimeout with string argument"),
                (re.compile(r'setInterval\s*\([\'"`]'), "setInterval with string argument"),
            ],
            "ruby": [
                (re.compile(r'\beval\s*\('), "Use of eval()"),
                (re.compile(r'\binstance_eval\b'), "Use of instance_eval"),
                (re.compile(r'\bclass_eval\b'), "Use of class_eval"),
                (re.compile(r'\bmodule_eval\b'), "Use of module_eval"),
            ],
        }
        
        lang_patterns = patterns.get(context.language, [])
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern, pattern_desc in lang_patterns:
                if pattern.search(line):
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        description=f"Potential code injection: {pattern_desc}. If user input reaches this function, it could lead to arbitrary code execution.",
                        remediation=Remediation(
                            description="Avoid using code evaluation functions with user input. Use safer alternatives like JSON parsing for data, or implement a restricted DSL.",
                            cwe_id="CWE-94",
                            references=["https://owasp.org/www-community/attacks/Code_Injection"],
                        ),
                    )
                    
                    yield finding
