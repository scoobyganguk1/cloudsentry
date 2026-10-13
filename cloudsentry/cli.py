"""Command-line interface."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .report import html_report, json_report, terminal_report
from .scanner import SEVERITIES, scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloudsentry", description="Scan Terraform files for common security risks.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan a Terraform file or directory")
    scan.add_argument("path", type=Path, help="Terraform .tf file or directory")
    scan.add_argument("--format", choices=("terminal", "json", "html"), default="terminal")
    scan.add_argument("--output", type=Path, help="Write output to a file (defaults to stdout)")
    scan.add_argument("--severity", choices=SEVERITIES, default="INFO", help="Minimum severity to include")
    scan.add_argument("--exclude-dir", action="append", default=[], help="Directory name to exclude; can be repeated")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        findings = scan_path(args.path, set(args.exclude_dir) | {".terraform", ".git"})
    except (OSError, UnicodeError) as error:
        print(f"cloudsentry: {error}", file=sys.stderr)
        return 2
    threshold = SEVERITIES.index(args.severity)
    findings = [finding for finding in findings if SEVERITIES.index(finding.severity) <= threshold]
    rendered = {"terminal": terminal_report, "json": json_report, "html": html_report}[args.format](findings)
    if args.output:
        try:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as error:
            print(f"cloudsentry: {error}", file=sys.stderr)
            return 2
        if args.format == "terminal":
            print(f"Report written to {args.output}")
    else:
        print(rendered)
    return 1 if findings else 0

