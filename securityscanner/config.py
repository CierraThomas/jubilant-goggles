"""
Configuration system for the security scanner.

Supports YAML and JSON configuration files for customizing
scanning behavior, rules, and output.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict


# Default configuration file names to search for
CONFIG_FILE_NAMES = [
    ".securityscanner.yaml",
    ".securityscanner.yml",
    ".securityscanner.json",
    "securityscanner.yaml",
    "securityscanner.yml",
    "securityscanner.json",
]


@dataclass
class RuleSetConfig:
    """Configuration for a rule set."""
    enabled: List[str] = field(default_factory=list)
    disabled: List[str] = field(default_factory=list)
    severity_overrides: Dict[str, str] = field(default_factory=dict)
    custom_config: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class OutputConfig:
    """Configuration for output formatting."""
    format: str = "text"  # text, json, sarif
    output_file: Optional[str] = None
    verbose: bool = False
    show_suppressed: bool = False
    show_context: bool = True
    context_lines: int = 3
    color: bool = True


@dataclass
class ScanConfig:
    """
    Main configuration for the security scanner.
    
    Example YAML config:
    
    ```yaml
    scan:
      target: ./src
      exclude:
        - "node_modules/**"
        - "vendor/**"
      include:
        - "**/*.py"
        - "**/*.js"
      max_file_size: 10485760
      max_workers: 4
    
    rules:
      preset: strict  # strict, standard, relaxed
      enabled:
        - SEC001
        - SEC002
      disabled:
        - QUAL003
      severity_overrides:
        SEC001: critical
    
    taint_analysis:
      enabled: true
      custom_sources: []
      custom_sinks: []
      custom_sanitizers: []
    
    output:
      format: text
      verbose: false
      color: true
    
    remediation:
      enabled: true
      auto_fix: false
      dry_run: true
    ```
    """
    # Scan settings
    target: str = "."
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "node_modules/**",
        ".git/**",
        "vendor/**",
        "__pycache__/**",
        "*.min.js",
        "dist/**",
        "build/**",
    ])
    include_patterns: Optional[List[str]] = None
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    max_workers: int = 4
    
    # Rule settings
    rule_preset: str = "standard"  # strict, standard, relaxed
    rules: RuleSetConfig = field(default_factory=RuleSetConfig)
    severity_threshold: str = "info"  # critical, high, medium, low, info
    
    # Taint analysis
    enable_taint_analysis: bool = True
    custom_sources: List[Dict[str, Any]] = field(default_factory=list)
    custom_sinks: List[Dict[str, Any]] = field(default_factory=list)
    custom_sanitizers: List[Dict[str, Any]] = field(default_factory=list)
    
    # Output settings
    output: OutputConfig = field(default_factory=OutputConfig)
    
    # Remediation settings
    enable_remediation: bool = True
    auto_fix: bool = False
    dry_run: bool = True
    
    # Language-specific settings
    language_config: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to a dictionary."""
        return asdict(self)
    
    def to_engine_config(self) -> Dict[str, Any]:
        """Convert to engine configuration format."""
        return {
            "max_file_size": self.max_file_size,
            "max_workers": self.max_workers,
            "ignore_patterns": self.exclude_patterns,
            "include_patterns": self.include_patterns,
            "severity_threshold": self.severity_threshold,
            "enable_taint_analysis": self.enable_taint_analysis,
            "rules": {
                "enabled": self.rules.enabled,
                "disabled": self.rules.disabled,
                "severity_overrides": self.rules.severity_overrides,
                **self.rules.custom_config,
            },
            "language_config": self.language_config,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanConfig":
        """Create config from a dictionary."""
        # Handle nested configs
        if "rules" in data and isinstance(data["rules"], dict):
            data["rules"] = RuleSetConfig(**data["rules"])
        if "output" in data and isinstance(data["output"], dict):
            data["output"] = OutputConfig(**data["output"])
        
        # Map some common alternative names
        if "exclude" in data:
            data["exclude_patterns"] = data.pop("exclude")
        if "include" in data:
            data["include_patterns"] = data.pop("include")
        
        # Filter to only known fields
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in known_fields}
        
        return cls(**filtered_data)


def load_config(path: str) -> Dict[str, Any]:
    """
    Load configuration from a file.
    
    Supports YAML and JSON formats.
    """
    path = Path(path)
    
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    
    content = path.read_text()
    
    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml
            return yaml.safe_load(content) or {}
        except ImportError:
            # Fallback: try to parse as JSON
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                raise ImportError(
                    "PyYAML is required to load YAML config files. "
                    "Install it with: pip install pyyaml"
                )
    elif path.suffix == ".json":
        return json.loads(content)
    else:
        # Try both
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            try:
                import yaml
                return yaml.safe_load(content) or {}
            except ImportError:
                raise ValueError(f"Unknown config file format: {path.suffix}")


def find_config(start_path: str = ".") -> Optional[str]:
    """
    Find a configuration file by searching up the directory tree.
    
    Returns the path to the first config file found, or None.
    """
    current = Path(start_path).resolve()
    
    while current != current.parent:
        for name in CONFIG_FILE_NAMES:
            config_path = current / name
            if config_path.exists():
                return str(config_path)
        current = current.parent
    
    return None


def load_scan_config(path: Optional[str] = None, start_dir: str = ".") -> ScanConfig:
    """
    Load a ScanConfig from a file or create a default one.
    
    If path is None, searches for a config file starting from start_dir.
    """
    if path is None:
        path = find_config(start_dir)
    
    if path is None:
        return ScanConfig()
    
    data = load_config(path)
    
    # Handle nested 'scan' section
    if "scan" in data:
        scan_data = data.pop("scan")
        data.update(scan_data)
    
    return ScanConfig.from_dict(data)


def create_default_config() -> str:
    """
    Create a default configuration file content.
    """
    config = {
        "scan": {
            "target": ".",
            "exclude": [
                "node_modules/**",
                ".git/**",
                "vendor/**",
                "__pycache__/**",
                "dist/**",
                "build/**",
            ],
            "max_file_size": 10485760,
            "max_workers": 4,
        },
        "rules": {
            "preset": "standard",
            "enabled": [],
            "disabled": [],
            "severity_overrides": {},
        },
        "taint_analysis": {
            "enabled": True,
        },
        "output": {
            "format": "text",
            "verbose": False,
            "color": True,
            "show_context": True,
            "context_lines": 3,
        },
        "remediation": {
            "enabled": True,
            "auto_fix": False,
            "dry_run": True,
        },
    }
    
    try:
        import yaml
        return yaml.dump(config, default_flow_style=False, sort_keys=False)
    except ImportError:
        return json.dumps(config, indent=2)


# Rule presets
RULE_PRESETS: Dict[str, Dict[str, List[str]]] = {
    "strict": {
        "enabled": ["*"],
        "disabled": [],
    },
    "standard": {
        "enabled": ["*"],
        "disabled": [
            "QUAL-NAMING-*",  # Naming conventions can be project-specific
        ],
    },
    "relaxed": {
        "enabled": ["SEC-*"],  # Security rules only
        "disabled": ["QUAL-*"],
    },
    "security-only": {
        "enabled": ["SEC-*", "TAINT-*"],
        "disabled": ["QUAL-*"],
    },
    "quality-only": {
        "enabled": ["QUAL-*"],
        "disabled": ["SEC-*", "TAINT-*"],
    },
}


def get_preset_rules(preset: str) -> Dict[str, List[str]]:
    """Get the rule configuration for a preset."""
    return RULE_PRESETS.get(preset, RULE_PRESETS["standard"])
