"""
Cryptographic security rules.

Detects weak algorithms, insecure key management, and other
cryptographic vulnerabilities.
"""

import re
from typing import Generator, List

from securityscanner.core.rules import (
    Rule, RuleMetadata, RuleType, AnalysisContext, rule
)
from securityscanner.core.findings import (
    Finding, Severity, Confidence, FindingCategory, CodeLocation, Remediation
)


@rule
class WeakHashingAlgorithmRule(Rule):
    """
    Detects use of weak or broken hashing algorithms.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-CRYPTO-001",
            name="Weak Hashing Algorithm",
            description="Detects use of weak hashing algorithms like MD5 and SHA1 for security-sensitive operations.",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=FindingCategory.CRYPTOGRAPHY,
            rule_type=RuleType.SECURITY,
            languages=["python", "javascript", "java", "go", "ruby", "csharp"],
            tags=["crypto", "hash", "md5", "sha1", "owasp-a02"],
            cwe_id="CWE-328",
            owasp_id="A02:2021",
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for weak hashing algorithms."""
        patterns = {
            "python": [
                (re.compile(r'hashlib\.md5\s*\('), "MD5", Severity.MEDIUM),
                (re.compile(r'hashlib\.sha1\s*\('), "SHA1", Severity.LOW),
                (re.compile(r'md5\s*\('), "MD5", Severity.MEDIUM),
            ],
            "javascript": [
                (re.compile(r'crypto\.createHash\s*\([\'"]md5[\'"]\)'), "MD5", Severity.MEDIUM),
                (re.compile(r'crypto\.createHash\s*\([\'"]sha1[\'"]\)'), "SHA1", Severity.LOW),
                (re.compile(r'CryptoJS\.MD5\s*\('), "MD5", Severity.MEDIUM),
                (re.compile(r'CryptoJS\.SHA1\s*\('), "SHA1", Severity.LOW),
            ],
            "java": [
                (re.compile(r'MessageDigest\.getInstance\s*\([\'"]MD5[\'"]\)'), "MD5", Severity.MEDIUM),
                (re.compile(r'MessageDigest\.getInstance\s*\([\'"]SHA-?1[\'"]\)'), "SHA1", Severity.LOW),
            ],
            "go": [
                (re.compile(r'md5\.New\s*\('), "MD5", Severity.MEDIUM),
                (re.compile(r'md5\.Sum\s*\('), "MD5", Severity.MEDIUM),
                (re.compile(r'sha1\.New\s*\('), "SHA1", Severity.LOW),
            ],
            "ruby": [
                (re.compile(r'Digest::MD5\.'), "MD5", Severity.MEDIUM),
                (re.compile(r'Digest::SHA1\.'), "SHA1", Severity.LOW),
            ],
            "csharp": [
                (re.compile(r'MD5\.Create\s*\('), "MD5", Severity.MEDIUM),
                (re.compile(r'SHA1\.Create\s*\('), "SHA1", Severity.LOW),
                (re.compile(r'new\s+MD5CryptoServiceProvider'), "MD5", Severity.MEDIUM),
            ],
        }
        
        lang_patterns = patterns.get(context.language, [])
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern, algo, severity in lang_patterns:
                if pattern.search(line):
                    # Skip if used for non-security purposes (file checksums, etc.)
                    if self._is_likely_non_security(line, context.lines, line_num):
                        continue
                    
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        severity=severity,
                        description=f"Weak hashing algorithm {algo} detected. {algo} is cryptographically broken and should not be used for security-sensitive operations like password hashing.",
                        remediation=Remediation(
                            description=f"Replace {algo} with a stronger algorithm. For password hashing, use bcrypt, scrypt, or Argon2. For general hashing, use SHA-256 or SHA-3.",
                            cwe_id="CWE-328",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
                            ],
                        ),
                    )
                    
                    yield finding
    
    def _is_likely_non_security(self, line: str, lines: List[str], line_num: int) -> bool:
        """Check if the hash is likely used for non-security purposes."""
        non_security_keywords = [
            'checksum', 'etag', 'cache', 'fingerprint', 'identifier', 'unique_id'
        ]
        
        # Check current line and surrounding context
        context_start = max(0, line_num - 3)
        context_end = min(len(lines), line_num + 3)
        context = '\n'.join(lines[context_start:context_end]).lower()
        
        return any(kw in context for kw in non_security_keywords)


@rule
class WeakEncryptionAlgorithmRule(Rule):
    """
    Detects use of weak or deprecated encryption algorithms.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-CRYPTO-002",
            name="Weak Encryption Algorithm",
            description="Detects use of weak or deprecated encryption algorithms like DES, 3DES, RC4, and ECB mode.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.CRYPTOGRAPHY,
            rule_type=RuleType.SECURITY,
            languages=["python", "javascript", "java", "go", "csharp"],
            tags=["crypto", "encryption", "des", "rc4", "owasp-a02"],
            cwe_id="CWE-327",
            owasp_id="A02:2021",
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for weak encryption algorithms."""
        patterns = [
            # DES
            (re.compile(r'\bDES\b(?!3)'), "DES", "DES is a weak algorithm with a 56-bit key that can be brute-forced"),
            (re.compile(r'DESede|3DES|Triple.?DES', re.IGNORECASE), "3DES", "3DES is deprecated and should be replaced with AES"),
            
            # RC4
            (re.compile(r'\bRC4\b|ARC4|ARCFOUR', re.IGNORECASE), "RC4", "RC4 has known weaknesses and should not be used"),
            
            # ECB mode
            (re.compile(r'\.MODE_ECB|ECB_MODE|/ECB/', re.IGNORECASE), "ECB mode", "ECB mode does not provide semantic security"),
            (re.compile(r'AES/ECB|cipher.*ecb', re.IGNORECASE), "ECB mode", "ECB mode does not provide semantic security"),
            
            # Blowfish (for security-sensitive use)
            (re.compile(r'\bBlowfish\b', re.IGNORECASE), "Blowfish", "Blowfish has a small block size (64-bit) that makes it vulnerable"),
            
            # RC2
            (re.compile(r'\bRC2\b', re.IGNORECASE), "RC2", "RC2 is an outdated algorithm with known weaknesses"),
        ]
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern, algo, reason in patterns:
                if pattern.search(line):
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        description=f"Weak encryption algorithm {algo} detected. {reason}.",
                        remediation=Remediation(
                            description="Use AES-256-GCM or ChaCha20-Poly1305 for encryption. Ensure you use authenticated encryption modes (GCM, CCM) rather than CBC or CTR alone.",
                            cwe_id="CWE-327",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
                            ],
                        ),
                    )
                    
                    yield finding


@rule
class InsecureRandomnessRule(Rule):
    """
    Detects use of insecure random number generators.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-CRYPTO-003",
            name="Insecure Randomness",
            description="Detects use of non-cryptographic random number generators for security-sensitive operations.",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            category=FindingCategory.CRYPTOGRAPHY,
            rule_type=RuleType.SECURITY,
            languages=["python", "javascript", "java", "go", "ruby", "csharp"],
            tags=["crypto", "random", "prng", "owasp-a02"],
            cwe_id="CWE-330",
            owasp_id="A02:2021",
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for insecure randomness."""
        patterns = {
            "python": [
                (re.compile(r'\brandom\.random\s*\('), "random.random()"),
                (re.compile(r'\brandom\.randint\s*\('), "random.randint()"),
                (re.compile(r'\brandom\.choice\s*\('), "random.choice()"),
                (re.compile(r'\brandom\.shuffle\s*\('), "random.shuffle()"),
            ],
            "javascript": [
                (re.compile(r'Math\.random\s*\('), "Math.random()"),
            ],
            "java": [
                (re.compile(r'new\s+Random\s*\('), "java.util.Random"),
                (re.compile(r'Math\.random\s*\('), "Math.random()"),
            ],
            "go": [
                (re.compile(r'math/rand'), "math/rand package"),
                (re.compile(r'rand\.Int\s*\('), "rand.Int()"),
                (re.compile(r'rand\.Intn\s*\('), "rand.Intn()"),
            ],
            "ruby": [
                (re.compile(r'\brand\s*\('), "rand()"),
                (re.compile(r'Random\.rand'), "Random.rand"),
            ],
            "csharp": [
                (re.compile(r'new\s+Random\s*\('), "System.Random"),
            ],
        }
        
        # Keywords that suggest security-sensitive context
        security_keywords = [
            'token', 'secret', 'key', 'password', 'salt', 'nonce', 'iv',
            'session', 'auth', 'crypto', 'encrypt', 'hash', 'secure'
        ]
        
        lang_patterns = patterns.get(context.language, [])
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern, func_name in lang_patterns:
                if pattern.search(line):
                    # Check for security-sensitive context
                    line_lower = line.lower()
                    context_lines = context.lines[max(0, line_num-3):min(len(context.lines), line_num+2)]
                    context_str = '\n'.join(context_lines).lower()
                    
                    is_security_context = any(kw in context_str for kw in security_keywords)
                    
                    if is_security_context:
                        location = CodeLocation(
                            file_path=context.file_path,
                            start_line=line_num,
                            end_line=line_num,
                        )
                        
                        finding = self.create_finding(
                            location=location,
                            snippet=context.get_snippet(line_num),
                            description=f"Insecure random number generator {func_name} used in security-sensitive context. Use a cryptographically secure random generator instead.",
                            remediation=self._get_remediation(context.language),
                        )
                        
                        yield finding
    
    def _get_remediation(self, language: str) -> Remediation:
        """Get language-specific remediation."""
        remediations = {
            "python": Remediation(
                description="Use the secrets module for security-sensitive random values.",
                before_code='token = random.randint(0, 999999)',
                after_code='import secrets\ntoken = secrets.randbelow(1000000)',
                cwe_id="CWE-330",
            ),
            "javascript": Remediation(
                description="Use crypto.randomBytes() or crypto.getRandomValues() for security-sensitive random values.",
                before_code='const token = Math.random().toString(36);',
                after_code='const crypto = require("crypto");\nconst token = crypto.randomBytes(32).toString("hex");',
                cwe_id="CWE-330",
            ),
            "java": Remediation(
                description="Use java.security.SecureRandom for security-sensitive random values.",
                before_code='Random random = new Random();\nint token = random.nextInt();',
                after_code='SecureRandom secureRandom = new SecureRandom();\nint token = secureRandom.nextInt();',
                cwe_id="CWE-330",
            ),
            "go": Remediation(
                description="Use crypto/rand instead of math/rand for security-sensitive random values.",
                before_code='import "math/rand"\nn := rand.Int()',
                after_code='import "crypto/rand"\nn, _ := rand.Int(rand.Reader, big.NewInt(100))',
                cwe_id="CWE-330",
            ),
        }
        
        return remediations.get(language, Remediation(
            description="Use a cryptographically secure random number generator for security-sensitive operations.",
            cwe_id="CWE-330",
        ))


@rule
class HardcodedCryptoKeyRule(Rule):
    """
    Detects hard-coded cryptographic keys.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-CRYPTO-004",
            name="Hard-coded Cryptographic Key",
            description="Detects hard-coded cryptographic keys that should be stored securely.",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category=FindingCategory.CRYPTOGRAPHY,
            rule_type=RuleType.SECURITY,
            languages=["*"],
            tags=["crypto", "key", "hardcoded", "owasp-a02"],
            cwe_id="CWE-321",
            owasp_id="A02:2021",
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for hard-coded cryptographic keys."""
        patterns = [
            (re.compile(r'(?:aes|encryption|cipher)[_-]?key\s*[=:]\s*["\'][a-zA-Z0-9+/=]{16,}["\']', re.IGNORECASE), "AES key"),
            (re.compile(r'(?:secret|signing)[_-]?key\s*[=:]\s*["\'][a-zA-Z0-9+/=]{16,}["\']', re.IGNORECASE), "Secret key"),
            (re.compile(r'(?:iv|initialization[_-]?vector)\s*[=:]\s*["\'][a-zA-Z0-9+/=]{16,}["\']', re.IGNORECASE), "Initialization vector"),
            (re.compile(r'HMAC.*key\s*[=:]\s*["\'][a-zA-Z0-9+/=]{16,}["\']', re.IGNORECASE), "HMAC key"),
        ]
        
        exclude_patterns = [
            re.compile(r'getenv|environ|os\.environ|process\.env|config\[', re.IGNORECASE),
            re.compile(r'(?:example|test|dummy|placeholder)', re.IGNORECASE),
        ]
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern, key_type in patterns:
                if pattern.search(line):
                    if any(ex.search(line) for ex in exclude_patterns):
                        continue
                    
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        description=f"Hard-coded {key_type} detected. Cryptographic keys should be stored securely and rotated regularly.",
                        remediation=Remediation(
                            description="Store cryptographic keys in environment variables, a secure key management system, or hardware security module (HSM).",
                            cwe_id="CWE-321",
                            references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html",
                            ],
                        ),
                    )
                    
                    yield finding
