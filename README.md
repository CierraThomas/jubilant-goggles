# Security Scanner

A comprehensive multi-language static analysis tool for security vulnerability detection, code quality enforcement, and AI-powered remediation.

## Features

### Security Vulnerability Detection

- **Injection Vulnerabilities**: SQL Injection, Command Injection, LDAP Injection, Code Injection
- **Cross-Site Scripting (XSS)**: Reflected, Stored, and DOM-based XSS
- **Insecure Deserialization**: Pickle, YAML, ObjectInputStream, and more
- **Hard-coded Secrets**: API keys, passwords, private keys, connection strings
- **Weak Cryptography**: MD5, SHA1, DES, RC4, ECB mode, insecure randomness
- **Authentication & Authorization Flaws**: Various patterns

### Code Quality & Standards

- **Complexity Analysis**: Cyclomatic complexity, cognitive complexity
- **Code Smells**: Long functions, deep nesting, too many parameters
- **Naming Conventions**: Language-specific naming standards
- **Error Handling**: Empty catch blocks, swallowed exceptions
- **Best Practices**: Language-specific recommendations

### AI-Powered Remediation

- Detailed fix recommendations with security rationale
- Before/after code examples
- Automatic fix application with dry-run support
- References to OWASP, CWE, and security best practices

## Supported Languages

| Language | Security Rules | Quality Rules | AST Parsing |
|----------|---------------|---------------|-------------|
| Python | ✅ | ✅ | ✅ (built-in ast) |
| JavaScript/TypeScript | ✅ | ✅ | ✅ (regex-based) |
| Java | ✅ | ✅ | ✅ (regex-based) |
| Go | ✅ | ✅ | ✅ (regex-based) |
| Ruby | ✅ | ✅ | ✅ (regex-based) |
| C# | ✅ | ✅ | ✅ (regex-based) |
| Rust | ✅ | ⚠️ | ✅ (regex-based) |
| Swift | ✅ | ⚠️ | ✅ (regex-based) |
| C/C++ | ✅ | ⚠️ | ✅ (regex-based) |
| Kotlin | ✅ | ⚠️ | ✅ (regex-based) |

## Installation

```bash
# Install from source
pip install -e .

# Install with optional dependencies
pip install -e ".[full]"
```

## Quick Start

### Basic Scan

```bash
# Scan current directory
securityscanner scan .

# Scan specific file or directory
securityscanner scan ./src/app.py
securityscanner scan ./backend

# Scan with specific severity threshold
securityscanner scan . --severity high
```

### Output Formats

```bash
# Human-readable output (default)
securityscanner scan .

# JSON output
securityscanner scan . --format json

# SARIF output (for IDE integration)
securityscanner scan . --format sarif -o results.sarif
```

### Automatic Fixes

```bash
# Show available fixes without applying
securityscanner fix . --dry-run

# Apply fixes (creates backups)
securityscanner fix .
```

### Configuration

```bash
# Create a configuration file
securityscanner init

# Use custom config
securityscanner scan . -c myconfig.yaml
```

## Configuration

Create a `.securityscanner.yaml` file in your project root:

```yaml
scan:
  target: .
  exclude:
    - "node_modules/**"
    - "vendor/**"
    - "dist/**"
    - "*.min.js"
  max_file_size: 10485760  # 10MB
  max_workers: 4

rules:
  preset: standard  # strict, standard, relaxed
  enabled: []       # Additional rules to enable
  disabled:         # Rules to disable
    - QUAL-NAME-001
    - QUAL-NAME-002
  severity_overrides:
    SEC-INJ-001: critical

taint_analysis:
  enabled: true

output:
  format: text
  verbose: false
  color: true
  show_context: true
  context_lines: 3

remediation:
  enabled: true
  auto_fix: false
  dry_run: true
```

## Rule Categories

### Security Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| SEC-INJ-001 | SQL Injection | Critical | Detects SQL injection vulnerabilities |
| SEC-INJ-002 | Command Injection | Critical | Detects command injection |
| SEC-INJ-003 | LDAP Injection | High | Detects LDAP injection |
| SEC-INJ-004 | Code Injection | Critical | Detects eval/exec usage |
| SEC-XSS-001 | DOM-based XSS | High | Detects DOM XSS |
| SEC-XSS-002 | Reflected XSS | High | Detects reflected XSS |
| SEC-SEC-001 | Hard-coded Password | High | Detects hard-coded passwords |
| SEC-SEC-002 | Hard-coded API Key | High | Detects API keys in code |
| SEC-SEC-003 | Hard-coded Private Key | Critical | Detects private keys |
| SEC-CRYPTO-001 | Weak Hashing | Medium | Detects MD5, SHA1 usage |
| SEC-CRYPTO-002 | Weak Encryption | High | Detects DES, RC4, ECB |
| SEC-CRYPTO-003 | Insecure Randomness | Medium | Detects non-CSPRNG usage |
| SEC-DESER-001 | Insecure Deserialization | Critical | Detects unsafe deserialization |

### Code Quality Rules

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| QUAL-CMPLX-001 | High Complexity | Medium | Cyclomatic complexity > 10 |
| QUAL-CMPLX-002 | Long Function | Low | Functions > 50 lines |
| QUAL-CMPLX-003 | Deep Nesting | Medium | Nesting depth > 4 |
| QUAL-CMPLX-004 | Too Many Parameters | Low | Functions with > 5 params |
| QUAL-ERR-001 | Empty Except Block | Medium | Silent exception handling |
| QUAL-ERR-002 | Bare Except | Medium | Catches all exceptions |
| QUAL-NAME-001 | Function Naming | Info | Naming convention check |
| QUAL-NAME-002 | Class Naming | Info | PascalCase check |

## Inline Suppression

Suppress findings using inline comments:

```python
# Python
password = "secret"  # noqa: SEC-SEC-001
password = "secret"  # nosec
password = "secret"  # security-scanner-ignore
```

```javascript
// JavaScript
const password = "secret"; // noqa
const password = "secret"; // nosec
```

## Programmatic Usage

```python
from securityscanner import ScanEngine, ScanConfig
from securityscanner.formatters import CLIFormatter

# Create engine with custom config
config = {
    "severity_threshold": "medium",
    "max_workers": 8,
}
engine = ScanEngine(config)

# Run scan
result = engine.scan("./src")

# Process results
for finding in result.findings:
    print(f"{finding.severity}: {finding.title}")
    print(f"  Location: {finding.location}")
    if finding.remediation:
        print(f"  Fix: {finding.remediation.description}")

# Format output
formatter = CLIFormatter()
print(formatter.format_result(result))
```

## Architecture

```
securityscanner/
├── core/
│   ├── engine.py       # Main scanning engine
│   ├── findings.py     # Finding data structures
│   ├── rules.py        # Rule engine and registry
│   └── taint.py        # Taint analysis engine
├── parsers/
│   ├── base.py         # Base parser class
│   ├── python_parser.py
│   ├── javascript_parser.py
│   └── generic.py      # Regex-based parser
├── analyzers/
│   ├── base.py         # Base analyzer class
│   ├── python_analyzer.py
│   └── javascript_analyzer.py
├── rules/
│   ├── security/       # Security rules
│   │   ├── injection.py
│   │   ├── xss.py
│   │   ├── secrets.py
│   │   ├── crypto.py
│   │   └── deserialization.py
│   └── quality/        # Code quality rules
│       ├── complexity.py
│       ├── naming.py
│       └── error_handling.py
├── remediation/
│   ├── engine.py       # Remediation engine
│   └── fixers.py       # Automatic fixers
├── formatters/
│   ├── cli.py          # CLI output
│   ├── json_formatter.py
│   └── sarif.py        # SARIF output
├── config.py           # Configuration handling
└── cli.py              # Command-line interface
```

## Extending the Scanner

### Adding a New Rule

```python
from securityscanner.core.rules import Rule, RuleMetadata, RuleType, rule
from securityscanner.core.findings import Severity, Confidence, FindingCategory

@rule
class MyCustomRule(Rule):
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="CUSTOM-001",
            name="My Custom Rule",
            description="Detects something dangerous",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.INJECTION,
            rule_type=RuleType.SECURITY,
            languages=["python", "javascript"],
            tags=["custom", "security"],
            cwe_id="CWE-XXX",
        )
    
    def analyze(self, context):
        for line_num, line in enumerate(context.lines, start=1):
            if "dangerous_pattern" in line:
                yield self.create_finding(
                    location=CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    ),
                    snippet=context.get_snippet(line_num),
                )
```

### Adding a New Language Parser

```python
from securityscanner.parsers.base import BaseParser, ASTNode
from securityscanner.parsers import register_parser

@register_parser("mylang")
class MyLanguageParser(BaseParser):
    @property
    def language(self) -> str:
        return "mylang"
    
    def parse(self, source: str, file_path: str) -> Optional[ASTNode]:
        # Parse source code into AST
        root = ASTNode(type="module", start_line=1, end_line=len(source.splitlines()))
        # ... build AST ...
        return root
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      
      - name: Install Security Scanner
        run: pip install -e .
      
      - name: Run Security Scan
        run: securityscanner scan . --format sarif -o results.sarif --severity high
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  stage: test
  script:
    - pip install -e .
    - securityscanner scan . --format json -o security-report.json
  artifacts:
    reports:
      sast: security-report.json
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please see CONTRIBUTING.md for guidelines.

## Security

To report security vulnerabilities, please see SECURITY.md.
