"""
Taint analysis engine for tracking data flow.

This module implements taint tracking to trace user-controlled inputs
(sources) through the code to dangerous functions (sinks), while
accounting for sanitization steps to reduce false positives.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple
from enum import Enum
import re

from securityscanner.core.findings import CodeLocation


class TaintState(Enum):
    """State of a tainted value."""
    TAINTED = "tainted"
    SANITIZED = "sanitized"
    CLEAN = "clean"
    UNKNOWN = "unknown"


@dataclass
class TaintSource:
    """Represents a source of tainted data."""
    name: str
    pattern: str
    language: str
    description: str
    category: str = "user_input"
    
    def matches(self, code: str) -> bool:
        """Check if this source matches the code."""
        return bool(re.search(self.pattern, code))


@dataclass
class TaintSink:
    """Represents a sink where tainted data is dangerous."""
    name: str
    pattern: str
    language: str
    description: str
    vulnerability_type: str
    argument_index: Optional[int] = None  # Which argument must not be tainted
    
    def matches(self, code: str) -> bool:
        """Check if this sink matches the code."""
        return bool(re.search(self.pattern, code))


@dataclass
class Sanitizer:
    """Represents a function that sanitizes tainted data."""
    name: str
    pattern: str
    language: str
    description: str
    sanitizes: List[str] = field(default_factory=list)  # What vulnerabilities it sanitizes
    
    def matches(self, code: str) -> bool:
        """Check if this sanitizer matches the code."""
        return bool(re.search(self.pattern, code))


@dataclass
class TaintedValue:
    """Represents a tainted value in the code."""
    variable_name: str
    source: TaintSource
    location: CodeLocation
    state: TaintState = TaintState.TAINTED
    sanitizers_applied: List[Sanitizer] = field(default_factory=list)
    
    def is_sanitized_for(self, vulnerability_type: str) -> bool:
        """Check if this value is sanitized for a vulnerability type."""
        for sanitizer in self.sanitizers_applied:
            if vulnerability_type in sanitizer.sanitizes or "*" in sanitizer.sanitizes:
                return True
        return False


@dataclass
class DataFlowPath:
    """Represents a path from source to sink."""
    source_location: CodeLocation
    sink_location: CodeLocation
    source: TaintSource
    sink: TaintSink
    path: List[CodeLocation] = field(default_factory=list)
    sanitizers: List[CodeLocation] = field(default_factory=list)
    variable_name: str = ""
    is_sanitized: bool = False


class TaintAnalyzer:
    """
    Performs taint analysis on source code.
    
    This analyzer tracks data flow from sources (user input) to sinks
    (dangerous functions), noting when sanitization is applied.
    """
    
    # Default sources for common languages
    DEFAULT_SOURCES: Dict[str, List[TaintSource]] = {
        "python": [
            TaintSource("request.args", r"request\.(args|form|data|json|values|files)\b", "python", "Flask request data"),
            TaintSource("request.GET", r"request\.(GET|POST|FILES|body|data)\b", "python", "Django request data"),
            TaintSource("input", r"\binput\s*\(", "python", "User input from stdin"),
            TaintSource("sys.argv", r"sys\.argv\b", "python", "Command line arguments"),
            TaintSource("os.environ", r"os\.environ\b", "python", "Environment variables"),
            TaintSource("raw_input", r"\braw_input\s*\(", "python", "User input (Python 2)"),
        ],
        "javascript": [
            TaintSource("req.body", r"req\.(body|query|params|headers|cookies)\b", "javascript", "Express request data"),
            TaintSource("req.query", r"req\.query\b", "javascript", "Express query parameters"),
            TaintSource("document.location", r"(document|window)\.(location|URL|referrer)\b", "javascript", "Browser location data"),
            TaintSource("document.cookie", r"document\.cookie\b", "javascript", "Browser cookies"),
            TaintSource("localStorage", r"(localStorage|sessionStorage)\.(getItem|get)\b", "javascript", "Browser storage"),
            TaintSource("prompt", r"\bprompt\s*\(", "javascript", "User prompt input"),
        ],
        "java": [
            TaintSource("request.getParameter", r"request\.getParameter\s*\(", "java", "Servlet request parameter"),
            TaintSource("request.getHeader", r"request\.getHeader\s*\(", "java", "HTTP header"),
            TaintSource("Scanner.next", r"scanner\.(next|nextLine)\s*\(", "java", "Scanner input"),
            TaintSource("BufferedReader.readLine", r"(reader|br)\.readLine\s*\(", "java", "Buffered reader input"),
            TaintSource("System.getenv", r"System\.getenv\s*\(", "java", "Environment variables"),
        ],
        "go": [
            TaintSource("r.FormValue", r"r\.(FormValue|PostFormValue|URL\.Query)\b", "go", "HTTP form value"),
            TaintSource("r.Header.Get", r"r\.Header\.Get\s*\(", "go", "HTTP header"),
            TaintSource("os.Args", r"os\.Args\b", "go", "Command line arguments"),
            TaintSource("os.Getenv", r"os\.Getenv\s*\(", "go", "Environment variables"),
            TaintSource("bufio.Scanner", r"scanner\.(Text|Bytes)\s*\(", "go", "Scanner input"),
        ],
        "ruby": [
            TaintSource("params", r"\bparams\[", "ruby", "Rails params"),
            TaintSource("request", r"request\.(body|raw_post|query_string)\b", "ruby", "Rails request data"),
            TaintSource("gets", r"\bgets\b", "ruby", "Standard input"),
            TaintSource("ARGV", r"\bARGV\b", "ruby", "Command line arguments"),
            TaintSource("ENV", r"\bENV\[", "ruby", "Environment variables"),
        ],
        "csharp": [
            TaintSource("Request.QueryString", r"Request\.(QueryString|Form|Params)\[", "csharp", "ASP.NET request data"),
            TaintSource("HttpContext.Request", r"(HttpContext\.)?Request\.(Query|Form|Body)\b", "csharp", "HTTP request data"),
            TaintSource("Console.ReadLine", r"Console\.ReadLine\s*\(", "csharp", "Console input"),
            TaintSource("Environment.GetEnvironmentVariable", r"Environment\.GetEnvironmentVariable\s*\(", "csharp", "Environment variables"),
        ],
    }
    
    # Default sinks for common vulnerabilities
    DEFAULT_SINKS: Dict[str, List[TaintSink]] = {
        "python": [
            TaintSink("execute", r"(cursor|conn|db)\.execute\s*\(", "python", "SQL execution", "sql_injection"),
            TaintSink("os.system", r"os\.system\s*\(", "python", "Command execution", "command_injection"),
            TaintSink("subprocess", r"subprocess\.(call|run|Popen|check_output)\s*\(", "python", "Subprocess execution", "command_injection"),
            TaintSink("eval", r"\beval\s*\(", "python", "Code evaluation", "code_injection"),
            TaintSink("exec", r"\bexec\s*\(", "python", "Code execution", "code_injection"),
            TaintSink("open", r"\bopen\s*\(", "python", "File open", "path_traversal"),
            TaintSink("render_template_string", r"render_template_string\s*\(", "python", "Template rendering", "ssti"),
            TaintSink("pickle.loads", r"pickle\.loads\s*\(", "python", "Deserialization", "insecure_deserialization"),
        ],
        "javascript": [
            TaintSink("eval", r"\beval\s*\(", "javascript", "Code evaluation", "code_injection"),
            TaintSink("innerHTML", r"\.innerHTML\s*=", "javascript", "HTML injection", "xss"),
            TaintSink("document.write", r"document\.write\s*\(", "javascript", "Document write", "xss"),
            TaintSink("exec", r"child_process\.(exec|execSync|spawn)\s*\(", "javascript", "Command execution", "command_injection"),
            TaintSink("query", r"\.(query|execute)\s*\(", "javascript", "SQL query", "sql_injection"),
            TaintSink("Function", r"new\s+Function\s*\(", "javascript", "Function constructor", "code_injection"),
        ],
        "java": [
            TaintSink("executeQuery", r"\.(executeQuery|executeUpdate|execute)\s*\(", "java", "SQL execution", "sql_injection"),
            TaintSink("Runtime.exec", r"Runtime\.getRuntime\(\)\.exec\s*\(", "java", "Command execution", "command_injection"),
            TaintSink("ProcessBuilder", r"new\s+ProcessBuilder\s*\(", "java", "Process execution", "command_injection"),
            TaintSink("ObjectInputStream", r"(ObjectInputStream|readObject)\s*\(", "java", "Deserialization", "insecure_deserialization"),
            TaintSink("XPath.evaluate", r"xpath\.(evaluate|compile)\s*\(", "java", "XPath evaluation", "xpath_injection"),
            TaintSink("File", r"new\s+File\s*\(", "java", "File access", "path_traversal"),
        ],
        "go": [
            TaintSink("Query", r"db\.(Query|Exec|QueryRow)\s*\(", "go", "SQL execution", "sql_injection"),
            TaintSink("exec.Command", r"exec\.Command\s*\(", "go", "Command execution", "command_injection"),
            TaintSink("template.HTML", r"template\.HTML\s*\(", "go", "Unsafe HTML", "xss"),
            TaintSink("os.Open", r"os\.(Open|OpenFile|Create)\s*\(", "go", "File access", "path_traversal"),
        ],
        "ruby": [
            TaintSink("execute", r"\.(execute|exec|find_by_sql)\s*\(", "ruby", "SQL execution", "sql_injection"),
            TaintSink("system", r"\b(system|exec|`)\s*", "ruby", "Command execution", "command_injection"),
            TaintSink("eval", r"\beval\s*\(", "ruby", "Code evaluation", "code_injection"),
            TaintSink("html_safe", r"\.html_safe\b", "ruby", "Unsafe HTML", "xss"),
            TaintSink("File.open", r"File\.(open|read|write)\s*\(", "ruby", "File access", "path_traversal"),
            TaintSink("Marshal.load", r"Marshal\.load\s*\(", "ruby", "Deserialization", "insecure_deserialization"),
        ],
        "csharp": [
            TaintSink("SqlCommand", r"(SqlCommand|ExecuteReader|ExecuteNonQuery)\s*\(", "csharp", "SQL execution", "sql_injection"),
            TaintSink("Process.Start", r"Process\.Start\s*\(", "csharp", "Process execution", "command_injection"),
            TaintSink("BinaryFormatter", r"(BinaryFormatter|Deserialize)\s*\(", "csharp", "Deserialization", "insecure_deserialization"),
            TaintSink("File.Open", r"File\.(Open|Read|Write|Create)\s*\(", "csharp", "File access", "path_traversal"),
        ],
    }
    
    # Default sanitizers
    DEFAULT_SANITIZERS: Dict[str, List[Sanitizer]] = {
        "python": [
            Sanitizer("escape", r"(html\.escape|escape|cgi\.escape)\s*\(", "python", "HTML escape", ["xss"]),
            Sanitizer("quote", r"(shlex\.quote|pipes\.quote)\s*\(", "python", "Shell quote", ["command_injection"]),
            Sanitizer("parameterized", r"execute\s*\([^,]+,\s*[\[\(]", "python", "Parameterized query", ["sql_injection"]),
            Sanitizer("bleach", r"bleach\.(clean|sanitize)\s*\(", "python", "Bleach sanitizer", ["xss"]),
            Sanitizer("secure_filename", r"secure_filename\s*\(", "python", "Secure filename", ["path_traversal"]),
        ],
        "javascript": [
            Sanitizer("escapeHtml", r"(escapeHtml|escape|encodeURIComponent)\s*\(", "javascript", "HTML/URL escape", ["xss"]),
            Sanitizer("textContent", r"\.textContent\s*=", "javascript", "Text content", ["xss"]),
            Sanitizer("createTextNode", r"createTextNode\s*\(", "javascript", "Create text node", ["xss"]),
            Sanitizer("parameterized", r"\?\s*,", "javascript", "Parameterized query", ["sql_injection"]),
            Sanitizer("DOMPurify", r"DOMPurify\.(sanitize|clean)\s*\(", "javascript", "DOMPurify sanitizer", ["xss"]),
        ],
        "java": [
            Sanitizer("PreparedStatement", r"PreparedStatement|prepareStatement\s*\(", "java", "Prepared statement", ["sql_injection"]),
            Sanitizer("escapeHtml", r"(StringEscapeUtils|HtmlUtils)\.escape", "java", "HTML escape", ["xss"]),
            Sanitizer("encode", r"URLEncoder\.encode\s*\(", "java", "URL encode", ["xss"]),
            Sanitizer("sanitize", r"(ESAPI|PolicyFactory)\.sanitize\s*\(", "java", "ESAPI/OWASP sanitizer", ["xss", "sql_injection"]),
        ],
        "go": [
            Sanitizer("QueryEscape", r"(url\.QueryEscape|html\.EscapeString)\s*\(", "go", "URL/HTML escape", ["xss"]),
            Sanitizer("template", r"template\.(HTMLEscapeString|JSEscapeString)\s*\(", "go", "Template escape", ["xss"]),
            Sanitizer("placeholder", r"\$\d+|\?", "go", "Query placeholder", ["sql_injection"]),
            Sanitizer("filepath.Clean", r"filepath\.Clean\s*\(", "go", "Path sanitization", ["path_traversal"]),
        ],
        "ruby": [
            Sanitizer("sanitize", r"(sanitize|h|html_escape)\s*\(", "ruby", "HTML sanitize", ["xss"]),
            Sanitizer("shellescape", r"(Shellwords\.escape|shellescape)\b", "ruby", "Shell escape", ["command_injection"]),
            Sanitizer("placeholder", r"\?\s*,|:\w+\s*=>", "ruby", "Parameterized query", ["sql_injection"]),
            Sanitizer("strip_tags", r"strip_tags\s*\(", "ruby", "Strip HTML tags", ["xss"]),
        ],
        "csharp": [
            Sanitizer("HtmlEncode", r"(HttpUtility|WebUtility)\.HtmlEncode\s*\(", "csharp", "HTML encode", ["xss"]),
            Sanitizer("SqlParameter", r"new\s+SqlParameter\b|@\w+", "csharp", "SQL parameter", ["sql_injection"]),
            Sanitizer("Encoder", r"(AntiXss|Encoder)\.(HtmlEncode|JavaScriptEncode)\s*\(", "csharp", "AntiXSS encoder", ["xss"]),
        ],
    }
    
    def __init__(self, language: str, config: Optional[Dict[str, Any]] = None):
        self.language = language.lower()
        self.config = config or {}
        self.sources = list(self.DEFAULT_SOURCES.get(self.language, []))
        self.sinks = list(self.DEFAULT_SINKS.get(self.language, []))
        self.sanitizers = list(self.DEFAULT_SANITIZERS.get(self.language, []))
        self.tainted_values: Dict[str, TaintedValue] = {}
    
    def add_source(self, source: TaintSource):
        """Add a custom taint source."""
        self.sources.append(source)
    
    def add_sink(self, sink: TaintSink):
        """Add a custom taint sink."""
        self.sinks.append(sink)
    
    def add_sanitizer(self, sanitizer: Sanitizer):
        """Add a custom sanitizer."""
        self.sanitizers.append(sanitizer)
    
    def find_flows(
        self,
        content: str,
        file_path: str,
        sources: Optional[List[str]] = None,
        sinks: Optional[List[str]] = None,
        sanitizers: Optional[List[str]] = None,
    ) -> List[DataFlowPath]:
        """
        Find data flows from sources to sinks.
        
        This performs a simplified intra-procedural taint analysis by:
        1. Identifying source locations where user input enters
        2. Tracking variable assignments that propagate taint
        3. Finding sinks that receive tainted data
        4. Noting sanitization that occurs along the path
        """
        flows: List[DataFlowPath] = []
        lines = content.splitlines()
        
        # Find all sources and track tainted variables
        tainted_vars: Dict[str, Tuple[TaintSource, CodeLocation, List[CodeLocation]]] = {}
        sanitized_vars: Dict[str, List[Tuple[Sanitizer, CodeLocation]]] = {}
        
        for line_num, line in enumerate(lines, start=1):
            # Check for sources
            for source in self.sources:
                if sources and source.name not in sources:
                    continue
                    
                if source.matches(line):
                    # Try to find the variable being assigned
                    var_match = re.search(r"(\w+)\s*=.*" + re.escape(source.pattern[:10]), line)
                    if var_match:
                        var_name = var_match.group(1)
                    else:
                        # Use generic name based on source
                        var_name = f"__tainted_{line_num}"
                    
                    location = CodeLocation(
                        file_path=file_path,
                        start_line=line_num,
                        end_line=line_num,
                        start_column=line.find(source.pattern.split("\\")[0]) if "\\" in source.pattern else 0,
                        end_column=len(line),
                    )
                    tainted_vars[var_name] = (source, location, [location])
            
            # Check for sanitization
            for sanitizer in self.sanitizers:
                if sanitizers and sanitizer.name not in sanitizers:
                    continue
                    
                if sanitizer.matches(line):
                    # Find variables being sanitized
                    for var_name in list(tainted_vars.keys()):
                        if var_name in line:
                            location = CodeLocation(
                                file_path=file_path,
                                start_line=line_num,
                                end_line=line_num,
                            )
                            if var_name not in sanitized_vars:
                                sanitized_vars[var_name] = []
                            sanitized_vars[var_name].append((sanitizer, location))
            
            # Track variable propagation
            # Simple assignment detection: new_var = tainted_var
            for var_name in list(tainted_vars.keys()):
                if var_name in line:
                    assign_match = re.search(rf"(\w+)\s*=.*\b{re.escape(var_name)}\b", line)
                    if assign_match:
                        new_var = assign_match.group(1)
                        if new_var != var_name:
                            source, source_loc, path = tainted_vars[var_name]
                            new_location = CodeLocation(
                                file_path=file_path,
                                start_line=line_num,
                                end_line=line_num,
                            )
                            tainted_vars[new_var] = (source, source_loc, path + [new_location])
            
            # Check for sinks
            for sink in self.sinks:
                if sinks and sink.name not in sinks:
                    continue
                    
                if sink.matches(line):
                    # Check if any tainted variable reaches this sink
                    for var_name, (source, source_loc, path) in tainted_vars.items():
                        if var_name in line or any(v in line for v in tainted_vars.keys()):
                            # Check if sanitized for this vulnerability
                            is_sanitized = False
                            sanitizer_locs = []
                            
                            if var_name in sanitized_vars:
                                for sanitizer, san_loc in sanitized_vars[var_name]:
                                    if sink.vulnerability_type in sanitizer.sanitizes or "*" in sanitizer.sanitizes:
                                        is_sanitized = True
                                        sanitizer_locs.append(san_loc)
                            
                            sink_location = CodeLocation(
                                file_path=file_path,
                                start_line=line_num,
                                end_line=line_num,
                            )
                            
                            flow = DataFlowPath(
                                source_location=source_loc,
                                sink_location=sink_location,
                                source=source,
                                sink=sink,
                                path=path + [sink_location],
                                sanitizers=sanitizer_locs,
                                variable_name=var_name,
                                is_sanitized=is_sanitized,
                            )
                            
                            # Only report if not sanitized
                            if not is_sanitized:
                                flows.append(flow)
        
        return flows
    
    def analyze_function(
        self,
        function_ast: Any,
        context: Any,
    ) -> List[DataFlowPath]:
        """
        Perform intra-procedural taint analysis on a function.
        
        This is a more sophisticated analysis that uses the AST.
        """
        # This would require language-specific AST traversal
        # For now, return empty list - implement per language
        return []
    
    def get_vulnerability_type(self, sink: TaintSink) -> str:
        """Get the vulnerability type for a sink."""
        return sink.vulnerability_type
    
    def is_sanitized(self, flow: DataFlowPath) -> bool:
        """Check if a flow is properly sanitized."""
        return flow.is_sanitized
