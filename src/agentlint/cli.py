from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .reporters import render_console, write_html, write_json
from .scanner import rule_catalog, scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentlint",
        description="Audit effective Codex instructions, skills, plugins, and MCP configuration without executing them.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan an agent configuration tree")
    scan_parser.add_argument("path", nargs="?", default=".", help="project directory to scan (default: current directory)")
    scan_parser.add_argument("--json", dest="json_path", metavar="PATH", help="write a machine-readable JSON report")
    scan_parser.add_argument("--html", dest="html_path", metavar="PATH", help="write a self-contained HTML report")
    scan_parser.add_argument(
        "--fail-on",
        choices=("error", "warning", "never"),
        default="error",
        help="exit 1 at this severity threshold (default: error)",
    )
    scan_parser.add_argument("--exclude", action="append", default=[], metavar="DIR", help="exclude a directory name; repeatable")
    scan_parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    scan_parser.add_argument("--quiet", action="store_true", help="suppress console findings")

    rules_parser = subparsers.add_parser("rules", help="list deterministic rule IDs")
    rules_parser.add_argument("--json", action="store_true", help="print the rule catalog as JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "rules":
        return _rules_command(args.json)
    if args.command == "scan":
        return _scan_command(args)
    parser.error("unknown command")
    return 2


def _rules_command(as_json: bool) -> int:
    catalog = rule_catalog()
    if as_json:
        print(json.dumps(catalog, indent=2))
        return 0
    print("ID         SEVERITY  CATEGORY        TITLE")
    for rule in catalog:
        print(f"{rule['id']:<10} {rule['severity']:<9} {rule['category']:<15} {rule['title']}")
    return 0


def _scan_command(args: argparse.Namespace) -> int:
    try:
        result = scan(Path(args.path), args.exclude)
        if args.json_path:
            write_json(result, args.json_path)
        if args.html_path:
            write_html(result, args.html_path)
    except (OSError, ValueError) as exc:
        print(f"agentlint: {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        render_console(result, color=not args.no_color)
        if args.json_path:
            print(f"\nJSON report: {Path(args.json_path).resolve()}")
        if args.html_path:
            print(f"HTML report: {Path(args.html_path).resolve()}")
    return _exit_code(result.counts, args.fail_on)


def _exit_code(counts: dict[str, int], threshold: str) -> int:
    if threshold == "never":
        return 0
    if threshold == "warning" and (counts.get("warning", 0) or counts.get("error", 0)):
        return 1
    if threshold == "error" and counts.get("error", 0):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
