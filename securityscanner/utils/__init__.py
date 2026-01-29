"""
Utility functions for the security scanner.
"""

import os
import hashlib
from typing import List, Optional


def get_file_hash(file_path: str) -> str:
    """Get the SHA-256 hash of a file."""
    with open(file_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


def normalize_path(path: str) -> str:
    """Normalize a file path."""
    return os.path.normpath(os.path.abspath(path))


def is_binary_file(file_path: str) -> bool:
    """Check if a file is binary."""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            if b'\x00' in chunk:
                return True
            # Check for high proportion of non-text bytes
            text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
            non_text = sum(1 for byte in chunk if byte not in text_chars)
            return non_text / len(chunk) > 0.3 if chunk else False
    except Exception:
        return False


def get_git_root(path: str) -> Optional[str]:
    """Find the git root directory."""
    current = os.path.abspath(path)
    
    while current != os.path.dirname(current):
        if os.path.isdir(os.path.join(current, '.git')):
            return current
        current = os.path.dirname(current)
    
    return None


def read_gitignore(path: str) -> List[str]:
    """Read patterns from .gitignore file."""
    gitignore_path = os.path.join(path, '.gitignore')
    
    if not os.path.exists(gitignore_path):
        return []
    
    patterns = []
    with open(gitignore_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                patterns.append(line)
    
    return patterns


def truncate_string(s: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate a string to a maximum length."""
    if len(s) <= max_length:
        return s
    return s[:max_length - len(suffix)] + suffix
