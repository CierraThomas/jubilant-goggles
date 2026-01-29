"""
Hard-coded secrets detection rules.

Detects API keys, passwords, tokens, private keys, and other
sensitive data that should not be committed to source code.
"""

import re
from typing import Generator, List, Tuple

from securityscanner.core.rules import (
    Rule, PatternRule, RuleMetadata, RuleType, AnalysisContext, rule
)
from securityscanner.core.findings import (
    Finding, Severity, Confidence, FindingCategory, CodeLocation, Remediation
)


@rule
class HardcodedPasswordRule(Rule):
    """
    Detects hard-coded passwords in source code.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-SEC-001",
            name="Hard-coded Password",
            description="Detects hard-coded passwords that may expose credentials.",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category=FindingCategory.SECRETS,
            rule_type=RuleType.SECURITY,
            languages=["*"],
            tags=["secrets", "password", "credentials", "owasp-a07"],
            cwe_id="CWE-798",
            owasp_id="A07:2021",
            auto_fixable=False,
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for hard-coded passwords."""
        # Password variable patterns
        password_patterns = [
            re.compile(r'(?:password|passwd|pwd|pass)\s*[=:]\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
            re.compile(r'(?:password|passwd|pwd|pass)\s*=\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
            re.compile(r'["\'](?:password|passwd|pwd)["\']:\s*["\'][^"\']{4,}["\']', re.IGNORECASE),
        ]
        
        # Exclude patterns (test files, examples, placeholders)
        exclude_patterns = [
            re.compile(r'(?:example|sample|test|dummy|fake|placeholder|xxx+|your_password)', re.IGNORECASE),
            re.compile(r'password\s*[=:]\s*["\'](?:\*+|\.+|_+)["\']', re.IGNORECASE),
            re.compile(r'getenv|environ|os\.environ|process\.env', re.IGNORECASE),
        ]
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern in password_patterns:
                match = pattern.search(line)
                if match:
                    # Check exclusions
                    is_excluded = any(ex.search(line) for ex in exclude_patterns)
                    if is_excluded:
                        continue
                    
                    # Check if it's a comment
                    stripped = line.strip()
                    if stripped.startswith(('#', '//', '/*', '*', '--')):
                        continue
                    
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        description="Hard-coded password detected. Credentials should be stored securely using environment variables or a secrets manager.",
                        remediation=Remediation(
                            description="Store passwords in environment variables or a secure secrets manager. Never commit credentials to source control.",
                            before_code='password = "my_secret_password"',
                            after_code='password = os.environ.get("DB_PASSWORD")',
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                            ],
                            cwe_id="CWE-798",
                        ),
                    )
                    
                    yield finding


@rule
class HardcodedAPIKeyRule(Rule):
    """
    Detects hard-coded API keys and tokens.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-SEC-002",
            name="Hard-coded API Key",
            description="Detects hard-coded API keys that may expose service credentials.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.SECRETS,
            rule_type=RuleType.SECURITY,
            languages=["*"],
            tags=["secrets", "api-key", "credentials", "owasp-a07"],
            cwe_id="CWE-798",
            owasp_id="A07:2021",
        )
    
    # Specific patterns for known API key formats
    API_KEY_PATTERNS = [
        # AWS
        (re.compile(r'(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'), "AWS Access Key ID", Confidence.HIGH),
        (re.compile(r'(?:aws_secret_access_key|aws_secret_key)\s*[=:]\s*["\'][A-Za-z0-9/+=]{40}["\']', re.IGNORECASE), "AWS Secret Access Key", Confidence.HIGH),
        
        # Google
        (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "Google API Key", Confidence.HIGH),
        (re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'), "Google OAuth Client ID", Confidence.MEDIUM),
        
        # GitHub
        (re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'), "GitHub Token", Confidence.HIGH),
        (re.compile(r'github_pat_[A-Za-z0-9_]{22,}'), "GitHub Personal Access Token", Confidence.HIGH),
        
        # Slack
        (re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'), "Slack Token", Confidence.HIGH),
        
        # Stripe
        (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'), "Stripe Secret Key", Confidence.HIGH),
        (re.compile(r'pk_live_[0-9a-zA-Z]{24,}'), "Stripe Publishable Key", Confidence.MEDIUM),
        
        # Generic patterns
        (re.compile(r'(?:api_key|apikey|api-key)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{20,}["\']', re.IGNORECASE), "Generic API Key", Confidence.MEDIUM),
        (re.compile(r'(?:secret_key|secretkey|secret-key)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{20,}["\']', re.IGNORECASE), "Secret Key", Confidence.MEDIUM),
        (re.compile(r'(?:access_token|accesstoken|access-token)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{20,}["\']', re.IGNORECASE), "Access Token", Confidence.MEDIUM),
        (re.compile(r'(?:auth_token|authtoken|auth-token)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{20,}["\']', re.IGNORECASE), "Auth Token", Confidence.MEDIUM),
        
        # Bearer tokens in headers
        (re.compile(r'["\']Authorization["\']\s*:\s*["\']Bearer\s+[a-zA-Z0-9_\-.]+["\']'), "Bearer Token in Header", Confidence.HIGH),
    ]
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for hard-coded API keys."""
        exclude_patterns = [
            re.compile(r'(?:example|sample|test|dummy|placeholder|xxx+|your[_-])', re.IGNORECASE),
            re.compile(r'getenv|environ|os\.environ|process\.env', re.IGNORECASE),
        ]
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern, key_type, confidence in self.API_KEY_PATTERNS:
                match = pattern.search(line)
                if match:
                    # Check exclusions
                    is_excluded = any(ex.search(line) for ex in exclude_patterns)
                    if is_excluded:
                        continue
                    
                    # Check if it's a comment
                    stripped = line.strip()
                    if stripped.startswith(('#', '//', '/*', '*', '--')):
                        continue
                    
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    # Mask the actual secret in the finding
                    matched_text = match.group()
                    masked = matched_text[:8] + '*' * (len(matched_text) - 12) + matched_text[-4:] if len(matched_text) > 16 else '*' * len(matched_text)
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        confidence=confidence,
                        description=f"{key_type} detected. API keys should be stored securely, not in source code.",
                        metadata={"key_type": key_type, "masked_value": masked},
                        remediation=Remediation(
                            description="Store API keys in environment variables or a secure secrets manager. Rotate this key immediately if it was committed to version control.",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
                            ],
                            cwe_id="CWE-798",
                        ),
                    )
                    
                    yield finding


@rule
class HardcodedPrivateKeyRule(Rule):
    """
    Detects hard-coded private keys.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-SEC-003",
            name="Hard-coded Private Key",
            description="Detects hard-coded private keys in source code.",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=FindingCategory.SECRETS,
            rule_type=RuleType.SECURITY,
            languages=["*"],
            tags=["secrets", "private-key", "crypto", "owasp-a07"],
            cwe_id="CWE-321",
            owasp_id="A07:2021",
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for hard-coded private keys."""
        # Private key patterns
        key_patterns = [
            (re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'), "Private Key Header"),
            (re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'), "PGP Private Key"),
            (re.compile(r'-----BEGIN ENCRYPTED PRIVATE KEY-----'), "Encrypted Private Key"),
        ]
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern, key_type in key_patterns:
                if pattern.search(line):
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        description=f"{key_type} detected in source code. Private keys should never be stored in source files.",
                        severity=Severity.CRITICAL,
                        remediation=Remediation(
                            description="Remove the private key from source code immediately. Store it in a secure location (e.g., secrets manager, HSM) and reference it via environment variables or configuration. Rotate the key if it was committed to version control.",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html",
                            ],
                            cwe_id="CWE-321",
                        ),
                    )
                    
                    yield finding


@rule
class HardcodedConnectionStringRule(Rule):
    """
    Detects hard-coded database connection strings.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-SEC-004",
            name="Hard-coded Connection String",
            description="Detects hard-coded database connection strings that may contain credentials.",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category=FindingCategory.SECRETS,
            rule_type=RuleType.SECURITY,
            languages=["*"],
            tags=["secrets", "database", "connection-string", "owasp-a07"],
            cwe_id="CWE-798",
            owasp_id="A07:2021",
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for hard-coded connection strings."""
        patterns = [
            # Database URLs with credentials
            re.compile(r'(?:mysql|postgresql|postgres|mongodb|redis|mssql|oracle)://[^:]+:[^@]+@[^\s"\']+', re.IGNORECASE),
            # JDBC connection strings
            re.compile(r'jdbc:[a-z]+://[^\s"\']+;(?:user|password)=[^\s"\']+', re.IGNORECASE),
            # Connection string with password
            re.compile(r'(?:connection_string|connectionstring|conn_string)\s*[=:]\s*["\'][^"\']*(?:password|pwd)=[^\s"\']+', re.IGNORECASE),
            # MongoDB connection strings
            re.compile(r'mongodb(?:\+srv)?://[^:]+:[^@]+@', re.IGNORECASE),
        ]
        
        exclude_patterns = [
            re.compile(r'(?:localhost|127\.0\.0\.1|example|sample|test)', re.IGNORECASE),
            re.compile(r'getenv|environ|os\.environ|process\.env', re.IGNORECASE),
        ]
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern in patterns:
                match = pattern.search(line)
                if match:
                    # Check exclusions
                    is_excluded = any(ex.search(line) for ex in exclude_patterns)
                    if is_excluded:
                        continue
                    
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        description="Hard-coded database connection string with credentials detected. Store connection strings with credentials in environment variables or a secrets manager.",
                        remediation=Remediation(
                            description="Store database credentials in environment variables or a secrets manager. Use connection string builders that read from secure configuration.",
                            before_code='conn = "postgresql://admin:s3cr3t@prod-db.example.com/mydb"',
                            after_code='conn = os.environ.get("DATABASE_URL")',
                            cwe_id="CWE-798",
                        ),
                    )
                    
                    yield finding


@rule
class GenericSecretRule(Rule):
    """
    Detects generic patterns that might indicate secrets.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-SEC-005",
            name="Generic Secret Pattern",
            description="Detects generic patterns that may indicate hard-coded secrets.",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            category=FindingCategory.SECRETS,
            rule_type=RuleType.SECURITY,
            languages=["*"],
            tags=["secrets", "credentials", "owasp-a07"],
            cwe_id="CWE-798",
            owasp_id="A07:2021",
            enabled_by_default=True,
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for generic secret patterns."""
        patterns = [
            (re.compile(r'(?:secret|token|credential|private)[_-]?(?:key)?\s*[=:]\s*["\'][a-zA-Z0-9_\-/+=]{16,}["\']', re.IGNORECASE), "Generic secret assignment"),
            (re.compile(r'(?:encryption|signing)[_-]?key\s*[=:]\s*["\'][a-zA-Z0-9_\-/+=]{16,}["\']', re.IGNORECASE), "Encryption/signing key"),
            (re.compile(r'(?:ssh|sftp)[_-]?(?:password|key)\s*[=:]\s*["\'][^\'"]{8,}["\']', re.IGNORECASE), "SSH/SFTP credentials"),
        ]
        
        exclude_patterns = [
            re.compile(r'(?:example|sample|test|dummy|placeholder|mock)', re.IGNORECASE),
            re.compile(r'getenv|environ|os\.environ|process\.env|config\[', re.IGNORECASE),
        ]
        
        for line_num, line in enumerate(context.lines, start=1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith(('#', '//', '/*', '*', '--')):
                continue
            
            for pattern, desc in patterns:
                match = pattern.search(line)
                if match:
                    is_excluded = any(ex.search(line) for ex in exclude_patterns)
                    if is_excluded:
                        continue
                    
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        description=f"Potential secret detected: {desc}. Review this line to ensure no sensitive data is hard-coded.",
                        confidence=Confidence.LOW,
                        remediation=Remediation(
                            description="If this is a secret, move it to environment variables or a secrets manager.",
                            cwe_id="CWE-798",
                        ),
                    )
                    
                    yield finding
