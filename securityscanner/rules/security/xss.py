"""
Cross-Site Scripting (XSS) vulnerability detection rules.

Detects Reflected, Stored, and DOM-based XSS vulnerabilities.
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
class DOMBasedXSSRule(Rule):
    """
    Detects potential DOM-based XSS vulnerabilities.
    
    DOM-based XSS occurs when JavaScript writes user-controlled data
    to the DOM without proper sanitization.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-XSS-001",
            name="DOM-based XSS",
            description="Detects potential DOM-based XSS vulnerabilities where user input may be written to the DOM unsafely.",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.XSS,
            rule_type=RuleType.SECURITY,
            languages=["javascript", "typescript"],
            tags=["xss", "dom", "client-side", "owasp-a03"],
            cwe_id="CWE-79",
            owasp_id="A03:2021",
            auto_fixable=True,
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for DOM-based XSS vulnerabilities."""
        # Dangerous sinks
        sink_patterns = [
            (re.compile(r'\.innerHTML\s*='), "innerHTML assignment"),
            (re.compile(r'\.outerHTML\s*='), "outerHTML assignment"),
            (re.compile(r'document\.write\s*\('), "document.write()"),
            (re.compile(r'document\.writeln\s*\('), "document.writeln()"),
            (re.compile(r'\.insertAdjacentHTML\s*\('), "insertAdjacentHTML()"),
            (re.compile(r'dangerouslySetInnerHTML\s*='), "React dangerouslySetInnerHTML"),
            (re.compile(r'\[innerHTML\]\s*='), "Angular innerHTML binding"),
            (re.compile(r'v-html\s*='), "Vue v-html directive"),
        ]
        
        # Sources of user input
        source_indicators = [
            'location', 'document.URL', 'document.referrer', 'window.name',
            'localStorage', 'sessionStorage', 'cookie', 'params', 'query',
            'search', 'hash', 'req.body', 'req.query', 'req.params',
        ]
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern, pattern_desc in sink_patterns:
                if pattern.search(line):
                    # Check if line might contain user input
                    has_source = any(src in line for src in source_indicators)
                    has_variable = '+' in line or '${' in line or '`' in line
                    
                    if has_source or has_variable:
                        confidence = Confidence.HIGH if has_source else Confidence.MEDIUM
                    else:
                        confidence = Confidence.LOW
                    
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        confidence=confidence,
                        description=f"Potential DOM-based XSS: {pattern_desc}. User input written to the DOM without sanitization can execute malicious scripts.",
                        remediation=self._get_remediation(),
                    )
                    
                    yield finding
    
    def _get_remediation(self) -> Remediation:
        return Remediation(
            description="Use textContent or innerText instead of innerHTML for text content. For HTML content, use a sanitization library like DOMPurify.",
            before_code='element.innerHTML = userInput;',
            after_code='element.textContent = userInput;\n// Or for HTML: element.innerHTML = DOMPurify.sanitize(userInput);',
            references=[
                "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
            ],
            owasp_reference="https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
            cwe_id="CWE-79",
            auto_fixable=True,
        )


@rule
class ReflectedXSSRule(Rule):
    """
    Detects potential reflected XSS vulnerabilities in server-side code.
    
    Reflected XSS occurs when user input from the request is included
    in the response without proper encoding.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-XSS-002",
            name="Reflected XSS",
            description="Detects potential reflected XSS vulnerabilities where request data may be included in responses unsafely.",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            category=FindingCategory.XSS,
            rule_type=RuleType.SECURITY,
            languages=["python", "javascript", "java", "ruby", "go", "csharp", "php"],
            tags=["xss", "reflected", "server-side", "owasp-a03"],
            cwe_id="CWE-79",
            owasp_id="A03:2021",
            auto_fixable=True,
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for reflected XSS vulnerabilities."""
        patterns = self._get_patterns(context.language)
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern, pattern_desc in patterns:
                if pattern.search(line):
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        description=f"Potential reflected XSS: {pattern_desc}.",
                        remediation=self._get_remediation(context.language),
                    )
                    
                    yield finding
    
    def _get_patterns(self, language: str) -> List[tuple]:
        """Get XSS patterns for the given language."""
        patterns = {
            "python": [
                (re.compile(r'return\s+.*request\.(args|form|data|values)'), "Request data in response"),
                (re.compile(r'render_template_string\s*\(.*request'), "render_template_string with request data"),
                (re.compile(r'Markup\s*\(.*request'), "Markup with request data"),
                (re.compile(r'\.write\s*\(.*request\.'), "Writing request data directly"),
            ],
            "javascript": [
                (re.compile(r'res\.send\s*\(.*req\.(body|query|params)'), "Sending request data in response"),
                (re.compile(r'res\.write\s*\(.*req\.'), "Writing request data to response"),
                (re.compile(r'res\.end\s*\(.*req\.'), "Ending response with request data"),
            ],
            "java": [
                (re.compile(r'getWriter\(\)\.(?:print|write)\s*\(.*getParameter'), "Writing request parameter"),
                (re.compile(r'response\..*\(.*request\.getParameter'), "Request parameter in response"),
            ],
            "ruby": [
                (re.compile(r'render\s+.*:?\s*html:.*params\['), "Rendering params as HTML"),
                (re.compile(r'\.html_safe.*params'), "html_safe with params"),
                (re.compile(r'raw\s*\(.*params'), "raw() with params"),
            ],
            "go": [
                (re.compile(r'template\.HTML\s*\(.*r\.(?:FormValue|URL)'), "template.HTML with form value"),
                (re.compile(r'fmt\.Fprint.*r\.(?:FormValue|URL)'), "Fprint with form value"),
            ],
            "csharp": [
                (re.compile(r'Response\.Write\s*\(.*Request\['), "Response.Write with Request data"),
                (re.compile(r'@Html\.Raw\s*\(.*Request'), "Html.Raw with Request data"),
            ],
        }
        
        return patterns.get(language, [])
    
    def _get_remediation(self, language: str) -> Remediation:
        """Get language-specific remediation."""
        remediations = {
            "python": Remediation(
                description="Use template engines with auto-escaping enabled. For Flask, use render_template instead of render_template_string, and avoid Markup() with user input.",
                before_code='return Markup(request.args.get("name"))',
                after_code='return render_template("greeting.html", name=request.args.get("name"))',
                cwe_id="CWE-79",
                auto_fixable=True,
            ),
            "javascript": Remediation(
                description="Encode user input before including it in HTML responses. Use template engines with auto-escaping or libraries like he for HTML encoding.",
                before_code='res.send("<h1>Hello " + req.query.name + "</h1>");',
                after_code='const he = require("he");\nres.send("<h1>Hello " + he.encode(req.query.name) + "</h1>");',
                cwe_id="CWE-79",
                auto_fixable=True,
            ),
        }
        
        return remediations.get(language, Remediation(
            description="HTML-encode all user input before including it in HTML responses. Use context-appropriate encoding for other contexts (JavaScript, CSS, URL).",
            cwe_id="CWE-79",
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
        ))


@rule
class UnsafeJQueryRule(Rule):
    """
    Detects potentially unsafe jQuery method usage.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-XSS-003",
            name="Unsafe jQuery Usage",
            description="Detects potentially unsafe jQuery methods that may lead to XSS.",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            category=FindingCategory.XSS,
            rule_type=RuleType.SECURITY,
            languages=["javascript", "typescript"],
            tags=["xss", "jquery", "dom", "owasp-a03"],
            cwe_id="CWE-79",
            owasp_id="A03:2021",
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for unsafe jQuery usage."""
        patterns = [
            (re.compile(r'\$\s*\([^)]+\)\.html\s*\([^)]+\+'), "jQuery .html() with concatenation"),
            (re.compile(r'\$\s*\([^)]+\)\.append\s*\([^)]+\+'), "jQuery .append() with concatenation"),
            (re.compile(r'\$\s*\([^)]+\)\.prepend\s*\([^)]+\+'), "jQuery .prepend() with concatenation"),
            (re.compile(r'\$\s*\([^)]+\)\.after\s*\([^)]+\+'), "jQuery .after() with concatenation"),
            (re.compile(r'\$\s*\([^)]+\)\.before\s*\([^)]+\+'), "jQuery .before() with concatenation"),
            (re.compile(r'\$\s*\(`[^`]*\$\{'), "jQuery selector with template literal"),
        ]
        
        for line_num, line in enumerate(context.lines, start=1):
            for pattern, pattern_desc in patterns:
                if pattern.search(line):
                    location = CodeLocation(
                        file_path=context.file_path,
                        start_line=line_num,
                        end_line=line_num,
                    )
                    
                    finding = self.create_finding(
                        location=location,
                        snippet=context.get_snippet(line_num),
                        description=f"Potential XSS via {pattern_desc}.",
                        remediation=Remediation(
                            description="Use .text() instead of .html() for text content. Sanitize HTML content before using .html() or other methods that insert HTML.",
                            before_code='$(selector).html(userInput);',
                            after_code='$(selector).text(userInput);\n// Or: $(selector).html(DOMPurify.sanitize(userInput));',
                            cwe_id="CWE-79",
                        ),
                    )
                    
                    yield finding


@rule
class TemplateInjectionRule(Rule):
    """
    Detects potential Server-Side Template Injection (SSTI) vulnerabilities.
    """
    
    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            rule_id="SEC-XSS-004",
            name="Template Injection",
            description="Detects potential server-side template injection vulnerabilities.",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category=FindingCategory.XSS,
            rule_type=RuleType.SECURITY,
            languages=["python", "javascript", "java", "ruby"],
            tags=["ssti", "template", "injection", "owasp-a03"],
            cwe_id="CWE-1336",
            owasp_id="A03:2021",
        )
    
    def analyze(self, context: AnalysisContext) -> Generator[Finding, None, None]:
        """Analyze for template injection vulnerabilities."""
        patterns = {
            "python": [
                (re.compile(r'render_template_string\s*\([^,)]+\+'), "render_template_string with concatenation"),
                (re.compile(r'render_template_string\s*\(.*\.format'), "render_template_string with format()"),
                (re.compile(r'Template\s*\([^,)]+\+'), "Jinja2 Template with concatenation"),
                (re.compile(r'Environment.*from_string'), "Jinja2 from_string usage"),
            ],
            "javascript": [
                (re.compile(r'ejs\.render\s*\([^,)]+\+'), "EJS render with concatenation"),
                (re.compile(r'pug\.render\s*\([^,)]+\+'), "Pug render with concatenation"),
                (re.compile(r'handlebars\.compile\s*\([^,)]+\+'), "Handlebars compile with concatenation"),
            ],
            "java": [
                (re.compile(r'Velocity.*evaluate.*\+'), "Velocity evaluate with concatenation"),
                (re.compile(r'FreeMarker.*process.*\+'), "FreeMarker process with concatenation"),
            ],
            "ruby": [
                (re.compile(r'ERB\.new\s*\([^)]+\+'), "ERB.new with concatenation"),
                (re.compile(r'Erubis.*new.*\+'), "Erubis with concatenation"),
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
                        description=f"Potential template injection: {pattern_desc}. User input in templates can lead to remote code execution.",
                        remediation=Remediation(
                            description="Never include user input directly in template strings. Pass user data as template variables instead.",
                            cwe_id="CWE-1336",
                            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection"],
                        ),
                    )
                    
                    yield finding
