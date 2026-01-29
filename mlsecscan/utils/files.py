 from __future__ import annotations
 
 from pathlib import Path
 from typing import Iterable
 
 from mlsecscan.parsing.treesitter import LANGUAGE_SPECS, language_for_path
 
 
 IGNORED_DIRS = {
     ".git",
     ".hg",
     ".svn",
     ".idea",
     ".vscode",
     ".venv",
     "node_modules",
     "dist",
     "build",
     "target",
     "vendor",
     "bin",
     "obj",
     "out",
 }
 
 
 def iter_source_files(root: str, enabled_languages: set[str]) -> Iterable[str]:
     root_path = Path(root)
     for path in root_path.rglob("*"):
         if not path.is_file():
             continue
         if any(part in IGNORED_DIRS for part in path.parts):
             continue
         language = language_for_path(str(path))
         if language is None:
             continue
         if language not in enabled_languages:
             continue
         yield str(path)
