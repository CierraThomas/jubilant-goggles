"""
Language-specific analyzers.

Analyzers provide language-specific analysis capabilities that
augment the general rule engine.
"""

from typing import Dict, Type, Optional
from securityscanner.analyzers.base import BaseAnalyzer

# Registry of analyzers
_analyzers: Dict[str, Type[BaseAnalyzer]] = {}


def register_analyzer(language: str):
    """Decorator to register an analyzer for a language."""
    def decorator(cls: Type[BaseAnalyzer]) -> Type[BaseAnalyzer]:
        _analyzers[language.lower()] = cls
        return cls
    return decorator


def get_analyzer(language: str) -> Optional[BaseAnalyzer]:
    """Get an analyzer instance for a language."""
    language = language.lower()
    
    if language in _analyzers:
        return _analyzers[language]()
    
    return None


# Import analyzers to register them
from securityscanner.analyzers.base import BaseAnalyzer
from securityscanner.analyzers.python_analyzer import PythonAnalyzer
from securityscanner.analyzers.javascript_analyzer import JavaScriptAnalyzer

__all__ = [
    "BaseAnalyzer",
    "get_analyzer",
    "register_analyzer",
    "PythonAnalyzer",
    "JavaScriptAnalyzer",
]
