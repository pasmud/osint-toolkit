"""Command-line interface for the offline inventory report."""

import argparse
import json
import sys
from pathlib import Path

from .inventory import InputError, build_report, render_text, write_csv
from .names import normalize_domain


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m osint_toolkit",
        description="Report asset evidence from local exports for one owned domain.",
        allow_abbrev=False,
    )
    parser.add_argument("--domain", required=True, help="owned domain to match by DNS label")
    parser.add_argument("--ct", action="append", type=Path, default=[], help="CT JSON file (repeatable)")
    parser.add_argument("--dns", action="append", type=Path, default=[], help="DNS JSON file (repeatable)")
    parser.add_argument("--format", choices=("text", "json", "csv"), default="text", help="report format")
    options = parser.parse_args(argv)
    if not (options.ct or options.dns):
        parser.error("at least one --ct or --dns file is required")
    try:
        domain = normalize_domain(options.domain)
    except ValueError as exc:
        parser.error(f"invalid --domain: {exc}")
    try:
        report = build_report(domain, options.ct, options.dns)
    except InputError as exc:
        parser.exit(1, f"error: {exc}\n")
    if options.format == "csv":
        write_csv(report, sys.stdout)
    else:
        print(json.dumps(report, indent=2) if options.format == "json" else render_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
