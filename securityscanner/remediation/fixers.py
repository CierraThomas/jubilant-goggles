"""
Fixers for automatically remediating security issues.

Each fixer is specialized for a specific type of vulnerability
and generates secure code replacements.
"""

import re
from abc import ABC, abstractmethod
from typing import Dict, Optional, Type

from securityscanner.core.findings import Finding


class BaseFixer(ABC):
    """Base class for code fixers."""
    
    @property
    @abstractmethod
    def supported_rules(self) -> list:
        """Return the rule IDs this fixer can handle."""
        pass
    
    @abstractmethod
    def fix(self, code: str, finding: Finding) -> str:
        """
        Apply a fix to the code.
        
        Args:
            code: The original code to fix.
            finding: The finding that triggered this fix.
            
        Returns:
            The fixed code.
        """
        pass
    
    def can_fix(self, finding: Finding) -> bool:
        """Check if this fixer can handle a finding."""
        return finding.rule_id in self.supported_rules


# Registry of fixers
_fixers: Dict[str, BaseFixer] = {}


def register_fixer(fixer: BaseFixer):
    """Register a fixer instance."""
    for rule_id in fixer.supported_rules:
        _fixers[rule_id] = fixer


def get_fixer(rule_id: str) -> Optional[BaseFixer]:
    """Get a fixer for a rule ID."""
    return _fixers.get(rule_id)


class SQLInjectionFixer(BaseFixer):
    """Fixer for SQL injection vulnerabilities."""
    
    @property
    def supported_rules(self) -> list:
        return ["SEC-INJ-001"]
    
    def fix(self, code: str, finding: Finding) -> str:
        """Convert string-formatted SQL to parameterized queries."""
        language = finding.language
        
        if language == "python":
            return self._fix_python_sql(code)
        elif language == "javascript":
            return self._fix_javascript_sql(code)
        elif language == "java":
            return self._fix_java_sql(code)
        
        return code
    
    def _fix_python_sql(self, code: str) -> str:
        """Fix Python SQL injection."""
        # Pattern: cursor.execute(f"SELECT ... WHERE x = {var}")
        # or: cursor.execute("SELECT ... WHERE x = %s" % var)
        
        # Handle f-strings
        fstring_pattern = re.compile(
            r'(\.execute\s*\()f["\']([^"\']*)\{(\w+)\}([^"\']*)["\'](\))'
        )
        match = fstring_pattern.search(code)
        if match:
            prefix = match.group(1)
            sql_before = match.group(2)
            var_name = match.group(3)
            sql_after = match.group(4)
            suffix = match.group(5)
            
            # Convert to parameterized query
            new_sql = f'{prefix}"{sql_before}%s{sql_after}", ({var_name},){suffix}'
            return fstring_pattern.sub(new_sql, code)
        
        # Handle % formatting
        percent_pattern = re.compile(
            r'(\.execute\s*\()["\']([^"\']*)["\']\s*%\s*(\w+)(\))'
        )
        match = percent_pattern.search(code)
        if match:
            prefix = match.group(1)
            sql = match.group(2)
            var_name = match.group(3)
            suffix = match.group(4)
            
            # Already has %s, just need to use tuple
            if '%s' in sql:
                return f'{prefix}"{sql}", ({var_name},){suffix}'
            else:
                # Replace %s or %d with %s parameter
                sql = re.sub(r'%[sd]', '%s', sql)
                return f'{prefix}"{sql}", ({var_name},){suffix}'
        
        # Handle .format()
        format_pattern = re.compile(
            r'(\.execute\s*\()["\']([^"\']*)["\']\.format\s*\(([^)]+)\)(\))'
        )
        match = format_pattern.search(code)
        if match:
            prefix = match.group(1)
            sql = match.group(2)
            args = match.group(3)
            suffix = match.group(4)
            
            # Replace {} with %s
            sql = re.sub(r'\{\w*\}', '%s', sql)
            return f'{prefix}"{sql}", ({args},){suffix}'
        
        return code
    
    def _fix_javascript_sql(self, code: str) -> str:
        """Fix JavaScript SQL injection."""
        # Pattern: db.query("SELECT ... " + variable)
        concat_pattern = re.compile(
            r'(\.query\s*\()["\']([^"\']+)["\'](\s*\+\s*)(\w+)(\))'
        )
        match = concat_pattern.search(code)
        if match:
            prefix = match.group(1)
            sql = match.group(2)
            var_name = match.group(4)
            suffix = match.group(5)
            
            return f'{prefix}"{sql}?", [{var_name}]{suffix}'
        
        return code
    
    def _fix_java_sql(self, code: str) -> str:
        """Fix Java SQL injection."""
        # This is more complex - would need to convert Statement to PreparedStatement
        # For now, add a comment suggesting the fix
        if 'Statement' in code and 'execute' in code:
            return f"// TODO: Convert to PreparedStatement\n{code}"
        return code


class XSSFixer(BaseFixer):
    """Fixer for XSS vulnerabilities."""
    
    @property
    def supported_rules(self) -> list:
        return ["SEC-XSS-001", "SEC-XSS-002"]
    
    def fix(self, code: str, finding: Finding) -> str:
        """Fix XSS vulnerabilities."""
        language = finding.language
        
        if language in ("javascript", "typescript"):
            return self._fix_javascript_xss(code)
        elif language == "python":
            return self._fix_python_xss(code)
        
        return code
    
    def _fix_javascript_xss(self, code: str) -> str:
        """Fix JavaScript XSS."""
        # Replace innerHTML with textContent where possible
        if '.innerHTML' in code and '=' in code:
            # Simple case: element.innerHTML = value
            code = re.sub(
                r'(\w+)\.innerHTML\s*=\s*(\w+)',
                r'\1.textContent = \2',
                code
            )
        
        # Add DOMPurify for HTML content
        if 'innerHTML' in code:
            code = f"// Consider using: element.innerHTML = DOMPurify.sanitize(content);\n{code}"
        
        return code
    
    def _fix_python_xss(self, code: str) -> str:
        """Fix Python XSS."""
        # Replace Markup with escaped content
        if 'Markup(' in code:
            code = re.sub(
                r'Markup\(([^)]+)\)',
                r'Markup.escape(\1)',
                code
            )
        
        return code


class YAMLFixer(BaseFixer):
    """Fixer for unsafe YAML loading."""
    
    @property
    def supported_rules(self) -> list:
        return ["SEC-DESER-002"]
    
    def fix(self, code: str, finding: Finding) -> str:
        """Fix unsafe YAML loading."""
        # Replace yaml.load with yaml.safe_load
        code = re.sub(r'yaml\.load\s*\(', 'yaml.safe_load(', code)
        code = re.sub(r'yaml\.unsafe_load\s*\(', 'yaml.safe_load(', code)
        code = re.sub(r'yaml\.full_load\s*\(', 'yaml.safe_load(', code)
        
        # Remove unsafe Loader arguments
        code = re.sub(
            r'yaml\.safe_load\(([^,)]+),\s*Loader\s*=\s*yaml\.(?:Unsafe)?Loader\)',
            r'yaml.safe_load(\1)',
            code
        )
        
        return code


class HardcodedSecretFixer(BaseFixer):
    """Fixer for hardcoded secrets."""
    
    @property
    def supported_rules(self) -> list:
        return ["SEC-SEC-001", "SEC-SEC-002", "SEC-SEC-004"]
    
    def fix(self, code: str, finding: Finding) -> str:
        """Suggest environment variable usage for hardcoded secrets."""
        language = finding.language
        
        # Extract the variable name
        var_match = re.search(r'(\w+)\s*[=:]\s*["\']', code)
        if not var_match:
            return code
        
        var_name = var_match.group(1)
        env_var_name = var_name.upper()
        
        if language == "python":
            return f'{var_name} = os.environ.get("{env_var_name}")'
        elif language in ("javascript", "typescript"):
            return f'const {var_name} = process.env.{env_var_name};'
        elif language == "java":
            return f'String {var_name} = System.getenv("{env_var_name}");'
        elif language == "go":
            return f'{var_name} := os.Getenv("{env_var_name}")'
        elif language == "ruby":
            return f'{var_name} = ENV["{env_var_name}"]'
        elif language == "csharp":
            return f'var {var_name} = Environment.GetEnvironmentVariable("{env_var_name}");'
        
        return f"// Move secret to environment variable: {env_var_name}\n{code}"


class InsecureRandomFixer(BaseFixer):
    """Fixer for insecure randomness."""
    
    @property
    def supported_rules(self) -> list:
        return ["SEC-CRYPTO-003"]
    
    def fix(self, code: str, finding: Finding) -> str:
        """Fix insecure random number generation."""
        language = finding.language
        
        if language == "python":
            # Replace random.X with secrets.X
            code = re.sub(r'random\.randint\(([^)]+)\)', r'secrets.randbelow(\1)', code)
            code = re.sub(r'random\.random\(\)', 'secrets.SystemRandom().random()', code)
            code = re.sub(r'random\.choice\(([^)]+)\)', r'secrets.choice(\1)', code)
            
            if 'secrets.' in code and 'import secrets' not in code:
                code = f'import secrets\n{code}'
        
        elif language in ("javascript", "typescript"):
            code = re.sub(
                r'Math\.random\(\)',
                'crypto.randomBytes(8).readBigUInt64BE() / BigInt(2**64)',
                code
            )
        
        return code


class EmptyExceptFixer(BaseFixer):
    """Fixer for empty exception handlers."""
    
    @property
    def supported_rules(self) -> list:
        return ["QUAL-ERR-001"]
    
    def fix(self, code: str, finding: Finding) -> str:
        """Add logging to empty exception handlers."""
        language = finding.language
        
        if language == "python":
            # Replace 'pass' with logging
            if re.search(r'except.*:\s*\n\s*pass\s*$', code, re.MULTILINE):
                code = re.sub(
                    r'(except\s+\w+)(\s+as\s+\w+)?:\s*\n\s*pass',
                    r'\1 as e:\n        logging.exception("Error occurred: %s", e)',
                    code
                )
            elif re.search(r'except.*:\s*\n\s*\.\.\.\s*$', code, re.MULTILINE):
                code = re.sub(
                    r'(except\s+\w+)(\s+as\s+\w+)?:\s*\n\s*\.\.\.',
                    r'\1 as e:\n        logging.exception("Error occurred: %s", e)',
                    code
                )
        
        return code


# Register all fixers
register_fixer(SQLInjectionFixer())
register_fixer(XSSFixer())
register_fixer(YAMLFixer())
register_fixer(HardcodedSecretFixer())
register_fixer(InsecureRandomFixer())
register_fixer(EmptyExceptFixer())
