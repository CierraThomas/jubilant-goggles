"""
Command-line interface for the security scanner.

Provides a user-friendly CLI for running security scans,
viewing results, and applying remediations.
"""

import argparse
import sys
import os
from typing import Optional, List

from securityscanner import __version__
from securityscanner.core.engine import ScanEngine
from securityscanner.core.findings import Severity
from securityscanner.config import load_scan_config, find_config, create_default_config
from securityscanner.formatters import get_formatter
from securityscanner.remediation import RemediationEngine


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="securityscanner",
        description="Multi-language security scanner for code vulnerability detection and remediation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  securityscanner scan ./src                    # Scan a directory
  securityscanner scan app.py                   # Scan a single file
  securityscanner scan . --format json          # Output as JSON
  securityscanner scan . --format sarif -o out  # SARIF output to file
  securityscanner scan . --severity high        # Only high+ severity
  securityscanner init                          # Create config file
  securityscanner fix ./src --dry-run          # Show fixes without applying
        """
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan code for security issues")
    scan_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target file or directory to scan (default: current directory)",
    )
    scan_parser.add_argument(
        "-c", "--config",
        help="Path to configuration file",
    )
    scan_parser.add_argument(
        "-f", "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "-o", "--output",
        help="Output file (default: stdout)",
    )
    scan_parser.add_argument(
        "-s", "--severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="Minimum severity to report (default: info)",
    )
    scan_parser.add_argument(
        "--include",
        action="append",
        help="Include patterns (can be specified multiple times)",
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        help="Exclude patterns (can be specified multiple times)",
    )
    scan_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    scan_parser.add_argument(
        "--show-suppressed",
        action="store_true",
        help="Show suppressed findings",
    )
    scan_parser.add_argument(
        "--security-only",
        action="store_true",
        help="Only run security rules (skip code quality)",
    )
    scan_parser.add_argument(
        "--quality-only",
        action="store_true",
        help="Only run code quality rules (skip security)",
    )
    scan_parser.add_argument(
        "-j", "--jobs",
        type=int,
        default=4,
        help="Number of parallel workers (default: 4)",
    )
    
    # Fix command
    fix_parser = subparsers.add_parser("fix", help="Apply automatic fixes")
    fix_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Target file or directory",
    )
    fix_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show fixes without applying them",
    )
    fix_parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Don't create backup files",
    )
    fix_parser.add_argument(
        "-c", "--config",
        help="Path to configuration file",
    )
    
    # Init command
    init_parser = subparsers.add_parser("init", help="Create a configuration file")
    init_parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Overwrite existing config file",
    )
    
    # List-rules command
    rules_parser = subparsers.add_parser("list-rules", help="List available rules")
    rules_parser.add_argument(
        "--category",
        choices=["security", "quality", "all"],
        default="all",
        help="Filter by category",
    )
    rules_parser.add_argument(
        "--language",
        help="Filter by language",
    )
    
    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute the scan command."""
    # Load configuration
    config = {}
    
    if args.config:
        from securityscanner.config import load_config
        config = load_config(args.config)
    else:
        config_path = find_config(args.target)
        if config_path:
            from securityscanner.config import load_config
            config = load_config(config_path)
    
    # Apply command-line overrides
    config["severity_threshold"] = args.severity
    config["max_workers"] = args.jobs
    
    if args.include:
        config["include_patterns"] = args.include
    if args.exclude:
        config["ignore_patterns"] = config.get("ignore_patterns", []) + args.exclude
    
    # Create engine and run scan
    engine = ScanEngine(config)
    
    if args.verbose and args.format == "text":
        print(f"Scanning {os.path.abspath(args.target)}...")
    
    result = engine.scan(args.target)
    
    # Format output
    formatter = get_formatter(args.format)
    
    if hasattr(formatter, 'verbose'):
        formatter.verbose = args.verbose
    if hasattr(formatter, 'use_color'):
        formatter.use_color = not args.no_color
    if hasattr(formatter, 'include_suppressed'):
        formatter.include_suppressed = args.show_suppressed
    
    output = formatter.format_result(result)
    
    # Write output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        if args.format == "text":
            print(f"Results written to {args.output}")
    else:
        print(output)
    
    # Return exit code based on findings
    if result.critical_count > 0:
        return 2
    elif result.high_count > 0:
        return 1
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    """Execute the fix command."""
    # First, run a scan
    config = {}
    if args.config:
        from securityscanner.config import load_config
        config = load_config(args.config)
    
    engine = ScanEngine(config)
    result = engine.scan(args.target)
    
    if result.total_findings == 0:
        print("No findings to fix!")
        return 0
    
    # Create remediation plan
    remediation_engine = RemediationEngine({
        "dry_run": args.dry_run,
        "backup": not args.no_backup,
    })
    
    plan = remediation_engine.generate_remediation_plan(result)
    
    # Print remediation report
    print(remediation_engine.format_remediation_report(plan))
    
    if args.dry_run:
        print("\n[DRY RUN] No files were modified.")
    else:
        # Apply fixes
        applied = remediation_engine.apply_fixes(plan.fixes, dry_run=False)
        successful = sum(1 for f in applied if f.success)
        print(f"\nApplied {successful}/{len(applied)} fixes.")
    
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    """Execute the init command."""
    config_file = ".securityscanner.yaml"
    
    if os.path.exists(config_file) and not args.force:
        print(f"Configuration file {config_file} already exists.")
        print("Use --force to overwrite.")
        return 1
    
    content = create_default_config()
    
    with open(config_file, 'w') as f:
        f.write(content)
    
    print(f"Created configuration file: {config_file}")
    return 0


def cmd_list_rules(args: argparse.Namespace) -> int:
    """Execute the list-rules command."""
    from securityscanner.core.rules import RuleRegistry
    
    # Import rules to register them
    import securityscanner.rules
    
    registry = RuleRegistry.get_instance()
    
    print("\nAvailable Rules")
    print("=" * 70)
    
    rules = registry.get_all_rules()
    
    # Filter by category
    if args.category != "all":
        from securityscanner.core.rules import RuleType
        rule_type = RuleType.SECURITY if args.category == "security" else RuleType.CODE_QUALITY
        rules = [r for r in rules if r.metadata.rule_type == rule_type]
    
    # Filter by language
    if args.language:
        rules = [r for r in rules if r.supports_language(args.language)]
    
    # Group by category
    security_rules = [r for r in rules if r.metadata.rule_type.value == "security"]
    quality_rules = [r for r in rules if r.metadata.rule_type.value != "security"]
    
    if security_rules:
        print("\nSecurity Rules:")
        print("-" * 70)
        for rule in security_rules:
            meta = rule.metadata
            status = "✓" if rule.is_enabled() else "○"
            print(f"  {status} {meta.rule_id:<16} {meta.name:<30} [{meta.severity.value}]")
    
    if quality_rules:
        print("\nCode Quality Rules:")
        print("-" * 70)
        for rule in quality_rules:
            meta = rule.metadata
            status = "✓" if rule.is_enabled() else "○"
            print(f"  {status} {meta.rule_id:<16} {meta.name:<30} [{meta.severity.value}]")
    
    print(f"\nTotal: {len(rules)} rules")
    print("✓ = enabled by default, ○ = disabled by default")
    
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args(argv)
    
    if args.command is None:
        parser.print_help()
        return 0
    
    try:
        if args.command == "scan":
            return cmd_scan(args)
        elif args.command == "fix":
            return cmd_fix(args)
        elif args.command == "init":
            return cmd_init(args)
        elif args.command == "list-rules":
            return cmd_list_rules(args)
        else:
            parser.print_help()
            return 0
    
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if os.environ.get("DEBUG"):
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
