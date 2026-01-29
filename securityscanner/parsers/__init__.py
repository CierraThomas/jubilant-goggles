"""
Language parsers for AST-based analysis.

This module provides parsers for each supported language that produce
ASTs (Abstract Syntax Trees) for rule analysis.
"""

from typing import Dict, Optional, Any, Type
from securityscanner.parsers.base import BaseParser

# Registry of available parsers
_parsers: Dict[str, Type[BaseParser]] = {}


def register_parser(language: str):
    """Decorator to register a parser for a language."""
    def decorator(cls: Type[BaseParser]) -> Type[BaseParser]:
        _parsers[language.lower()] = cls
        return cls
    return decorator


def get_parser(language: str) -> Optional[BaseParser]:
    """Get a parser instance for a language."""
    language = language.lower()
    
    # Aliases
    aliases = {
        "js": "javascript",
        "ts": "typescript",
        "py": "python",
        "rb": "ruby",
        "rs": "rust",
        "cs": "csharp",
        "c#": "csharp",
        "c++": "cpp",
    }
    language = aliases.get(language, language)
    
    if language in _parsers:
        return _parsers[language]()
    
    # Try to import and use the generic parser
    from securityscanner.parsers.generic import GenericParser
    return GenericParser(language)


def list_supported_languages() -> list:
    """List all languages with registered parsers."""
    return list(_parsers.keys())


# Import parsers to register them
from securityscanner.parsers.python_parser import PythonParser
from securityscanner.parsers.javascript_parser import JavaScriptParser
from securityscanner.parsers.generic import GenericParser

__all__ = [
    "BaseParser",
    "get_parser",
    "register_parser",
    "list_supported_languages",
    "PythonParser",
    "JavaScriptParser",
    "GenericParser",
]
