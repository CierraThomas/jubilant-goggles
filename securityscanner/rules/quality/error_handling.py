"""
Error handling rules.

Detects improper error handling patterns that may lead to
issues or security vulnerabilities.
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
class EmptyExceptBlockRule(Rule):
    """
    Detects empty exception handlers that silently swallow errors.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="QUAL-ERR-001",
            name="Empty Exception Handler",
            description="Detects empty catch/except blocks that silently swallow errors.",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=FindingCategory.ERROR_HANDLING,
            rule_type=RuleType.CODE_QUALITY,
            languages=["python", "javascript", "java", "csharp", "ruby", "go"],
            tags=["error-handling", "silent-failure", "debugging"],
            enabled_by_default=True,
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Detect empty exception handlers."""
        patterns = {
            "python": self._check_python_except,
            "javascript": self._check_js_catch,
            "java": self._check_java_catch,
            "csharp": self._check_csharp_catch,
        }
        
        checker = patterns.get(context.language)
        if checker:
            yield from checker(context)
    
    def _check_python_except(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Check for empty except blocks in Python."""
        lines = context.lines
        i = 0
        
        while i < len(lines):
            line = lines[i]
            
            if re.match(r'^\s*except\s*(?:\w+)?(?:\s+as\s+\w+)?:', line):
                except_line = i + 1
                except_indent = len(line) - len(line.lstrip())
                
                # Check the block content
                i += 1
                block_content = []
                
                while i < len(lines):
                    next_line = lines[i]
                    if not next_line.strip():
                        i += 1
                        continue
                    
                    next_indent = len(next_line) - len(next_line.lstrip())
                    if next_indent <= except_indent:
                        break
                    
                    block_content.append(next_line.strip())
                    i += 1
                
                # Check if block is empty or just contains pass
                is_empty = (
                    not block_content or 
                    (len(block_content) == 1 and block_content[0] in ('pass', '...'))
                )
                
                if is_empty:
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=except_line,
                        end_line=except_line,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(except_line),
                        description="Empty except block silently swallows errors. At minimum, log the exception.",
                        remediation=Remediation(
                            description="At minimum, log the exception. Consider whether the exception should be re-raised or handled differently.",
                            before_code='except Exception:\n    pass',
                            after_code='except Exception as e:\n    logging.error(f"Error occurred: {e}")\n    # Handle or re-raise as appropriate',
                        ),
                    )
                    
                    yield finding
            else:
                i += 1
    
    def _check_js_catch(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Check for empty catch blocks in JavaScript."""
        lines = context.lines
        
        for i, line in enumerate(lines):
            if re.match(r'^\s*}\s*catch\s*\([^)]*\)\s*{\s*}', line):
                location = CodeLocation(
                    file_path=context.file_path,
                    start_line=i + 1,
                    end_line=i + 1,
                )
                
                finding = self.create_finding(
                    location=location,
                    snippet=context.get_snippet(i + 1),
                    description="Empty catch block silently swallows errors.",
                    remediation=Remediation(
                        description="Log the error or handle it appropriately. Never silently ignore exceptions.",
                        before_code='catch (error) {}',
                        after_code='catch (error) {\n  console.error("Error:", error);\n}',
                    ),
                )
                
                yield finding
            
            # Also check for catch followed by empty block on next line
            elif re.match(r'^\s*}\s*catch\s*\([^)]*\)\s*{', line):
                if i + 1 < len(lines) and re.match(r'^\s*}\s*$', lines[i + 1]):
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=i + 1,
                        end_line=i + 2,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(i + 1),
                        description="Empty catch block silently swallows errors.",
                        remediation=Remediation(
                            description="Log the error or handle it appropriately.",
                        ),
                    )
                    
                    yield finding
    
    def _check_java_catch(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Check for empty catch blocks in Java."""
        lines = context.lines
        
        for i, line in enumerate(lines):
            if re.match(r'^\s*}\s*catch\s*\([^)]+\)\s*{\s*}', line):
                location = CodeLocation(
                    file_path=context.file_path,
                    start_line=i + 1,
                    end_line=i + 1,
                )
                
                finding = self.create_finding(
                    location=location,
                    snippet=context.get_snippet(i + 1),
                    description="Empty catch block silently swallows errors.",
                    remediation=Remediation(
                        description="At minimum, log the exception using a proper logging framework.",
                    ),
                )
                
                yield finding
    
    def _check_csharp_catch(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Check for empty catch blocks in C#."""
        # Similar to Java
        yield from self._check_java_catch(context)


@rule
class BareExceptRule(Rule):
    """
    Detects bare except clauses that catch all exceptions.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="QUAL-ERR-002",
            name="Bare Except Clause",
            description="Detects bare except clauses that catch all exceptions including system-exiting ones.",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=FindingCategory.ERROR_HANDLING,
            rule_type=RuleType.CODE_QUALITY,
            languages=["python"],
            tags=["error-handling", "exception", "best-practice"],
            enabled_by_default=True,
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Detect bare except clauses."""
        if context.language != "python":
            return
        
        for line_num, line in enumerate(context.lines, start=1):
            # Match bare except: or except:
            if re.match(r'^\s*except\s*:', line):
                location = CodeLocation(
                    file_path=context.file_path,
                    start_line=line_num,
                    end_line=line_num,
                )
                
                finding = self.create_finding(
                    location=location,
                    snippet=context.get_snippet(line_num),
                    description="Bare except clause catches all exceptions including KeyboardInterrupt and SystemExit. Use 'except Exception:' instead.",
                    remediation=Remediation(
                        description="Specify the exception types to catch. Use 'except Exception:' for general errors, or catch specific exceptions.",
                        before_code='except:\n    pass',
                        after_code='except Exception as e:\n    logging.error(f"Error: {e}")',
                    ),
                )
                
                yield finding


@rule
class GenericExceptionRule(Rule):
    """
    Detects catching overly broad exception types.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="QUAL-ERR-003",
            name="Generic Exception Catch",
            description="Detects catching overly broad exception types that may mask bugs.",
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            category=FindingCategory.ERROR_HANDLING,
            rule_type=RuleType.CODE_QUALITY,
            languages=["python", "javascript", "java", "csharp"],
            tags=["error-handling", "exception", "best-practice"],
            enabled_by_default=True,
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Detect catching generic exceptions."""
        patterns = {
            "python": re.compile(r'^\s*except\s+(Exception|BaseException)\s*(?:as\s+\w+)?:'),
            "java": re.compile(r'catch\s*\(\s*(Exception|Throwable)\s+\w+\s*\)'),
            "csharp": re.compile(r'catch\s*\(\s*Exception\s*(?:\w+)?\s*\)'),
        }
        
        pattern = patterns.get(context.language)
        if not pattern:
            return
        
        for line_num, line in enumerate(context.lines, start=1):
            match = pattern.search(line)
            if match:
                exception_type = match.group(1) if match.groups() else "Exception"
                
                location = CodeLocation(
                    file_path=context.file_path,
                    start_line=line_num,
                    end_line=line_num,
                )
                
                finding = self.create_finding(
                    location=location,
                    snippet=context.get_snippet(line_num),
                    description=f"Catching generic '{exception_type}' may mask bugs. Consider catching more specific exception types.",
                    remediation=Remediation(
                        description="Catch specific exception types that you can handle. Let unexpected exceptions propagate.",
                    ),
                )
                
                yield finding


@rule
class ExceptionLoggingRule(Rule):
    """
    Detects exception handlers that don't log the exception.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="QUAL-ERR-004",
            name="Exception Without Logging",
            description="Detects exception handlers that don't log the exception information.",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            category=FindingCategory.ERROR_HANDLING,
            rule_type=RuleType.CODE_QUALITY,
            languages=["python", "javascript", "java"],
            tags=["error-handling", "logging", "debugging"],
            enabled_by_default=False,  # Too many false positives
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Detect exception handlers without logging."""
        # This rule has many false positives, so it's disabled by default
        # Implementation would check if exception handlers reference the exception variable
        pass


@rule
class ThrowInFinallyRule(Rule):
    """
    Detects throwing exceptions in finally blocks.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="QUAL-ERR-005",
            name="Throw in Finally Block",
            description="Detects throwing exceptions in finally blocks which can mask original exceptions.",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category=FindingCategory.ERROR_HANDLING,
            rule_type=RuleType.CODE_QUALITY,
            languages=["python", "javascript", "java", "csharp"],
            tags=["error-handling", "finally", "exception"],
            enabled_by_default=True,
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Detect throw/raise in finally blocks."""
        lines = context.lines
        in_finally = False
        finally_indent = 0
        
        throw_keywords = {
            "python": "raise",
            "javascript": "throw",
            "java": "throw",
            "csharp": "throw",
        }
        
        throw_kw = throw_keywords.get(context.language, "throw")
        
        for i, line in enumerate(lines):
            stripped = line.strip()
            
            if context.language == "python":
                if stripped.startswith("finally:"):
                    in_finally = True
                    finally_indent = len(line) - len(line.lstrip())
                elif in_finally:
                    current_indent = len(line) - len(line.lstrip())
                    if stripped and current_indent <= finally_indent:
                        in_finally = False
                    elif stripped.startswith("raise"):
                        location = CodeLocation(
                            file_path=context.file_path,
                            start_line=i + 1,
                            end_line=i + 1,
                        )
                        
                        finding = self.create_finding(
                            location=location,
                            snippet=context.get_snippet(i + 1),
                            description="Raising exception in finally block may mask the original exception.",
                            remediation=Remediation(
                                description="Avoid raising exceptions in finally blocks. If cleanup can fail, handle it separately.",
                            ),
                        )
                        
                        yield finding
            else:
                # Brace-based languages
                if "finally" in stripped and "{" in stripped:
                    in_finally = True
                    finally_indent = 1
                elif in_finally:
                    finally_indent += stripped.count("{")
                    finally_indent -= stripped.count("}")
                    
                    if finally_indent <= 0:
                        in_finally = False
                    elif stripped.startswith(throw_kw):
                        location = CodeLocation(
                            file_path=context.file_path,
                            start_line=i + 1,
                            end_line=i + 1,
                        )
                        
                        finding = self.create_finding(
                            location=location,
                            snippet=context.get_snippet(i + 1),
                            description=f"Throwing exception in finally block may mask the original exception.",
                            remediation=Remediation(
                                description="Avoid throwing exceptions in finally blocks. Handle cleanup errors separately.",
                            ),
                        )
                        
                        yield finding


@rule
class MissingErrorCheckRule(Rule):
    """
    Detects function calls that return errors but don't check them.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="QUAL-ERR-006",
            name="Missing Error Check",
            description="Detects function calls that return errors which are not checked.",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            category=FindingCategory.ERROR_HANDLING,
            rule_type=RuleType.CODE_QUALITY,
            languages=["go"],
            tags=["error-handling", "go", "best-practice"],
            enabled_by_default=True,
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Detect unchecked errors in Go."""
        if context.language != "go":
            return
        
        # Pattern for assignments that ignore error return value
        ignore_pattern = re.compile(r'^\s*(\w+)\s*(?:,\s*_)?\s*:?=\s*(\w+)\s*\(')
        
        for line_num, line in enumerate(context.lines, start=1):
            match = ignore_pattern.match(line)
            if match and ', _' in line:
                location = CodeLocation(
                    file_path=context.file_path,
                    start_line=line_num,
                    end_line=line_num,
                )
                
                finding = self.create_finding(
                    location=location,
                    snippet=context.get_snippet(line_num),
                    description="Error return value is explicitly ignored with '_'. Consider handling the error.",
                    remediation=Remediation(
                        description="Handle the error appropriately. If the error truly can be ignored, add a comment explaining why.",
                    ),
                )
                
                yield finding
