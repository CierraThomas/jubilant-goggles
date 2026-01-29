"""
Tests for the security scanner.
"""

import pytest
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from securityscanner.core.engine import ScanEngine
from securityscanner.core.findings import Finding, Severity, Confidence, FindingCategory
from securityscanner.core.rules import RuleRegistry, AnalysisContext


class TestScanEngine:
    """Tests for the main scan engine."""
    
    def test_engine_creation(self):
        """Test that engine can be created."""
        engine = ScanEngine()
        assert engine is not None
    
    def test_engine_with_config(self):
        """Test engine creation with configuration."""
        config = {
            "severity_threshold": "high",
            "max_workers": 2,
        }
        engine = ScanEngine(config)
        assert engine.severity_threshold == Severity.HIGH
        assert engine.max_workers == 2
    
    def test_language_detection(self):
        """Test language detection from file extensions."""
        engine = ScanEngine()
        
        assert engine.detect_language("app.py") == "python"
        assert engine.detect_language("index.js") == "javascript"
        assert engine.detect_language("App.java") == "java"
        assert engine.detect_language("main.go") == "go"
        assert engine.detect_language("app.rb") == "ruby"
        assert engine.detect_language("Program.cs") == "csharp"
        assert engine.detect_language("main.rs") == "rust"
        assert engine.detect_language("App.swift") == "swift"
        assert engine.detect_language("README.md") is None
    
    def test_scan_content_python(self):
        """Test scanning Python content."""
        engine = ScanEngine()
        
        code = '''
import os

password = "secret123"

def run_command(cmd):
    os.system(cmd)
'''
        
        findings = engine.scan_content(code, "python", "test.py")
        
        # Should find hard-coded password and command injection
        assert len(findings) >= 1
        
        # Check that we found the password
        password_findings = [f for f in findings if "password" in f.description.lower() or "secret" in f.rule_id.lower()]
        assert len(password_findings) >= 1
    
    def test_scan_content_javascript(self):
        """Test scanning JavaScript content."""
        engine = ScanEngine()
        
        code = '''
const API_KEY = "sk_live_1234567890abcdef";

function showMessage(msg) {
    document.innerHTML = msg;
}
'''
        
        findings = engine.scan_content(code, "javascript", "test.js")
        
        # Should find hard-coded API key and potential XSS
        assert len(findings) >= 1


class TestFindings:
    """Tests for finding data structures."""
    
    def test_finding_creation(self):
        """Test creating a finding."""
        from securityscanner.core.findings import CodeLocation
        
        location = CodeLocation(
            file_path="test.py",
            start_line=10,
            end_line=10,
        )
        
        finding = Finding(
            rule_id="TEST-001",
            title="Test Finding",
            description="This is a test finding",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.INJECTION,
            location=location,
        )
        
        assert finding.rule_id == "TEST-001"
        assert finding.severity == Severity.HIGH
        assert finding.location.start_line == 10
    
    def test_finding_to_dict(self):
        """Test converting finding to dictionary."""
        from securityscanner.core.findings import CodeLocation
        
        location = CodeLocation(
            file_path="test.py",
            start_line=10,
            end_line=10,
        )
        
        finding = Finding(
            rule_id="TEST-001",
            title="Test Finding",
            description="This is a test finding",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.INJECTION,
            location=location,
        )
        
        data = finding.to_dict()
        
        assert data["rule_id"] == "TEST-001"
        assert data["severity"] == "high"
        assert data["location"]["start_line"] == 10
    
    def test_severity_comparison(self):
        """Test severity level comparison."""
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO


class TestRules:
    """Tests for rule engine."""
    
    def test_rule_registry(self):
        """Test rule registry."""
        # Import rules to register them
        import securityscanner.rules
        
        registry = RuleRegistry.get_instance()
        
        # Should have some rules registered
        assert registry.rule_count > 0
    
    def test_get_rules_for_language(self):
        """Test getting rules for a specific language."""
        import securityscanner.rules
        
        registry = RuleRegistry.get_instance()
        
        python_rules = registry.get_rules_for_language("python")
        assert len(python_rules) > 0
        
        js_rules = registry.get_rules_for_language("javascript")
        assert len(js_rules) > 0
    
    def test_analysis_context(self):
        """Test analysis context creation."""
        context = AnalysisContext(
            file_path="test.py",
            content="def hello():\n    print('world')\n",
            language="python",
        )
        
        assert context.file_path == "test.py"
        assert len(context.lines) == 2
        assert context.language == "python"
    
    def test_context_snippet(self):
        """Test getting code snippets from context."""
        code = """line 1
line 2
line 3
line 4
line 5
line 6
line 7"""
        
        context = AnalysisContext(
            file_path="test.py",
            content=code,
            language="python",
        )
        
        snippet = context.get_snippet(4, context_lines=2)
        
        assert snippet.highlighted_line == 4
        assert snippet.code == "line 4"
        assert len(snippet.context_before) == 2
        assert len(snippet.context_after) == 2


class TestSecurityRules:
    """Tests for security vulnerability detection rules."""
    
    def test_sql_injection_detection(self):
        """Test SQL injection detection."""
        engine = ScanEngine()
        
        code = '''
import sqlite3

def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        
        findings = engine.scan_content(code, "python", "test.py")
        sql_findings = [f for f in findings if "sql" in f.rule_id.lower() or "inj" in f.rule_id.lower()]
        
        assert len(sql_findings) >= 1
    
    def test_command_injection_detection(self):
        """Test command injection detection."""
        engine = ScanEngine()
        
        code = '''
import subprocess

def run_cmd(cmd):
    subprocess.call(cmd, shell=True)
'''
        
        findings = engine.scan_content(code, "python", "test.py")
        cmd_findings = [f for f in findings if "command" in f.description.lower() or "inj-002" in f.rule_id.lower()]
        
        assert len(cmd_findings) >= 1
    
    def test_hardcoded_secret_detection(self):
        """Test hard-coded secret detection."""
        engine = ScanEngine()
        
        code = '''
password = "my_secret_password"
api_key = "sk_live_1234567890abcdef"
'''
        
        findings = engine.scan_content(code, "python", "test.py")
        secret_findings = [f for f in findings if "sec-sec" in f.rule_id.lower()]
        
        assert len(secret_findings) >= 1
    
    def test_weak_hash_detection(self):
        """Test weak hashing algorithm detection."""
        engine = ScanEngine()
        
        code = '''
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
'''
        
        findings = engine.scan_content(code, "python", "test.py")
        crypto_findings = [f for f in findings if "crypto" in f.rule_id.lower() or "hash" in f.description.lower()]
        
        assert len(crypto_findings) >= 1
    
    def test_unsafe_yaml_detection(self):
        """Test unsafe YAML loading detection."""
        engine = ScanEngine()
        
        code = '''
import yaml

def load_config(data):
    return yaml.load(data)
'''
        
        findings = engine.scan_content(code, "python", "test.py")
        yaml_findings = [f for f in findings if "yaml" in f.description.lower() or "deser" in f.rule_id.lower()]
        
        assert len(yaml_findings) >= 1


class TestCodeQualityRules:
    """Tests for code quality rules."""
    
    def test_empty_except_detection(self):
        """Test empty except block detection."""
        engine = ScanEngine()
        
        code = '''
def risky():
    try:
        do_something()
    except Exception:
        pass
'''
        
        findings = engine.scan_content(code, "python", "test.py")
        err_findings = [f for f in findings if "err" in f.rule_id.lower() or "except" in f.description.lower()]
        
        assert len(err_findings) >= 1


class TestFormatters:
    """Tests for output formatters."""
    
    def test_cli_formatter(self):
        """Test CLI formatter."""
        from securityscanner.formatters.cli import CLIFormatter
        from securityscanner.core.findings import ScanResult, CodeLocation
        
        location = CodeLocation(
            file_path="test.py",
            start_line=10,
            end_line=10,
        )
        
        finding = Finding(
            rule_id="TEST-001",
            title="Test Finding",
            description="This is a test finding",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.INJECTION,
            location=location,
        )
        
        result = ScanResult(
            findings=[finding],
            files_scanned=1,
            scan_time_seconds=0.5,
            languages_detected=["python"],
            rules_applied=["TEST-001"],
        )
        
        formatter = CLIFormatter(use_color=False)
        output = formatter.format_result(result)
        
        assert "TEST-001" in output
        assert "Test Finding" in output
    
    def test_json_formatter(self):
        """Test JSON formatter."""
        from securityscanner.formatters.json_formatter import JSONFormatter
        from securityscanner.core.findings import ScanResult, CodeLocation
        import json
        
        location = CodeLocation(
            file_path="test.py",
            start_line=10,
            end_line=10,
        )
        
        finding = Finding(
            rule_id="TEST-001",
            title="Test Finding",
            description="This is a test finding",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.INJECTION,
            location=location,
        )
        
        result = ScanResult(
            findings=[finding],
            files_scanned=1,
            scan_time_seconds=0.5,
            languages_detected=["python"],
            rules_applied=["TEST-001"],
        )
        
        formatter = JSONFormatter()
        output = formatter.format_result(result)
        
        # Should be valid JSON
        data = json.loads(output)
        
        assert "findings" in data
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == "TEST-001"
    
    def test_sarif_formatter(self):
        """Test SARIF formatter."""
        from securityscanner.formatters.sarif import SARIFFormatter
        from securityscanner.core.findings import ScanResult, CodeLocation
        import json
        
        location = CodeLocation(
            file_path="test.py",
            start_line=10,
            end_line=10,
        )
        
        finding = Finding(
            rule_id="TEST-001",
            title="Test Finding",
            description="This is a test finding",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.INJECTION,
            location=location,
        )
        
        result = ScanResult(
            findings=[finding],
            files_scanned=1,
            scan_time_seconds=0.5,
            languages_detected=["python"],
            rules_applied=["TEST-001"],
        )
        
        formatter = SARIFFormatter()
        output = formatter.format_result(result)
        
        # Should be valid SARIF JSON
        data = json.loads(output)
        
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1


class TestRemediation:
    """Tests for remediation engine."""
    
    def test_remediation_engine(self):
        """Test remediation engine creation."""
        from securityscanner.remediation import RemediationEngine
        
        engine = RemediationEngine()
        assert engine is not None
    
    def test_generate_fix(self):
        """Test generating a fix."""
        from securityscanner.remediation import RemediationEngine
        from securityscanner.core.findings import CodeLocation, Remediation
        
        location = CodeLocation(
            file_path="test.py",
            start_line=10,
            end_line=10,
        )
        
        finding = Finding(
            rule_id="SEC-DESER-002",
            title="Unsafe YAML",
            description="Unsafe YAML loading",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=FindingCategory.DESERIALIZATION,
            location=location,
            remediation=Remediation(
                description="Use yaml.safe_load",
                auto_fixable=True,
            ),
        )
        
        engine = RemediationEngine()
        # Note: This would need file access to work fully
        # Just test that the method exists and is callable
        assert hasattr(engine, 'generate_fix')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
