 from __future__ import annotations
 
 import argparse
 from pathlib import Path
 
 from mlsecscan.core.config import Config
 from mlsecscan.core.engine import ScanEngine
 from mlsecscan.reporting import format_json, format_sarif, format_text
 
 
 SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
 
 
 def main(argv: list[str] | None = None) -> int:
     parser = argparse.ArgumentParser(prog="mlsecscan", description="Multi-language security scanner")
     subparsers = parser.add_subparsers(dest="command", required=True)
 
     scan_parser = subparsers.add_parser("scan", help="Scan a repository or file")
     scan_parser.add_argument("path", nargs="?", default=".", help="Path to scan")
     scan_parser.add_argument("--config", dest="config_path", help="Path to YAML/JSON config file")
     scan_parser.add_argument(
         "--format",
         choices=["text", "json", "sarif"],
         help="Output format (overrides config)",
     )
     scan_parser.add_argument("--output", help="Write output to file instead of stdout")
     scan_parser.add_argument(
         "--apply-fixes",
         action="store_true",
         help="Apply safe fixes (if available)",
     )
     scan_parser.add_argument(
         "--dry-run",
         action="store_true",
         help="Show fixes without applying changes",
     )
 
     args = parser.parse_args(argv)
 
     if args.command == "scan":
         config = Config.load(args.config_path)
         engine = ScanEngine(config)
         report = engine.scan(
             args.path,
             apply_fixes=args.apply_fixes,
             dry_run=args.dry_run or not args.apply_fixes,
         )
         fmt = args.format or config.reporting().get("format", "text")
         if fmt == "json":
             output = format_json(report.findings, report.suppressed, report.applied_fixes, report.skipped_fixes)
         elif fmt == "sarif":
             output = format_sarif(report.findings)
         else:
             output = format_text(report.findings, report.suppressed, report.applied_fixes, report.skipped_fixes)
         if args.output:
             Path(args.output).write_text(output, encoding="utf-8")
         else:
             print(output, end="")
         return _exit_code(report.findings, config.reporting().get("fail_on_severity", "High"))
     return 0
 
 
 def _exit_code(findings, threshold: str) -> int:
     threshold_value = SEVERITY_ORDER.get(threshold, 3)
     for finding in findings:
         if SEVERITY_ORDER.get(finding.severity, 0) >= threshold_value:
             return 2
     return 0
