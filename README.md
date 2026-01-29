# mlsecscan: Multi-language Security Scanner

mlsecscan is an offline, AST-based static analysis tool for multi-language
security vulnerability detection, code quality enforcement, and remediation
guidance. It is designed for CI/CD pipelines and local developer workflows.

## High-level Architecture

```
                 +------------------------+
                 |   CLI / Config Loader  |
                 +-----------+------------+
                             |
                             v
                   +---------+---------+
                   |   Scan Engine     |
                   +---------+---------+
                             |
     +-----------------------+-----------------------+
     |                       |                       |
     v                       v                       v
  Parsing                Analysis                 Reporting
 (Tree-sitter)     (Taint, Complexity)      (Text/JSON/SARIF)
     |                       |
     v                       v
  Language              Rule Evaluation
  Specs & AST           (Rules -> Findings)
     |                       |
     +-----------+-----------+
                 v
            Remediation
         (Fix hints + diff)
```

### Key Design Goals
- **AST-based parsing** (Tree-sitter) for modern languages.
- **Modular rule engine** with language-specific analyzers and shared abstractions.
- **Deterministic results** and configurable severity/confidence levels.
- **Offline-first** (no external API calls at runtime).

## Supported Languages
- C / C++
- C#
- Go
- Java / Kotlin
- JavaScript / TypeScript
- Python
- Ruby
- Rust
- Swift

## Installation

```
pip install -e .
```

## Usage

Scan a repository:

```
mlsecscan scan .
```

Use a custom config:

```
mlsecscan scan . --config configs/default.yml
```

Output JSON or SARIF:

```
mlsecscan scan . --format json
mlsecscan scan . --format sarif --output results.sarif
```

Dry-run fixes (default) or apply safe fixes:

```
mlsecscan scan . --apply-fixes --dry-run
mlsecscan scan . --apply-fixes
```

## Configuration

mlsecscan reads a single YAML or JSON config file:

```
version: 1
rules:
  enabled: [SQLI, XSS, HARDCODED_SECRET, COMPLEXITY]
  severities:
    SQLI: High
    XSS: High
    HARDCODED_SECRET: High
    COMPLEXITY: Medium
thresholds:
  complexity:
    max_cyclomatic: 15
    max_nesting: 4
    max_function_lines: 80
suppression:
  inline_comment: "mlsecscan:ignore"
```

### Suppression

Suppress a finding by adding the marker to the same line or the line above:

```
user_input = request.args["id"]  # mlsecscan:ignore
cursor.execute("SELECT * FROM users WHERE id=" + user_input)
```

## Example Remediation Output

```
[High/Medium] SQLI: Possible SQL injection via tainted input
  Location: app/routes.py:42:5
  Snippet: cursor.execute("SELECT * FROM users WHERE id=" + user_id)
  Message: User-controlled data appears to reach a SQL execution call.
  Remediation: Use parameterized queries or prepared statements.
  References:
    - https://owasp.org/www-community/attacks/SQL_Injection
```

## Extension Points

Add a new language:
1. Update `mlsecscan/parsing/treesitter.py` with a `LanguageSpec`.
2. Ensure Tree-sitter grammar is available in `tree_sitter_languages`.

Add a new rule:
1. Create a new rule in `mlsecscan/rules/`.
2. Register it in `mlsecscan/core/registry.py`.

## Project Layout

```
mlsecscan/
  analysis/        # Taint + complexity analysis
  core/            # Engine, config, rule base
  parsing/         # Tree-sitter parsing layer
  reporting/       # Text/JSON/SARIF output
  remediation/     # Fix generation helpers
  rules/           # Security + quality rules
  utils/           # Helpers (diffs, file scan, location)
configs/
  default.yml
```
