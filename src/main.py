"""Command-line entry point for the website analysis tool.

Run from the repository root with: python -m src.main example.com
"""

import argparse

from src.helpers.helper import Helper
from src.scanners.http_scanner import HttpScanner
from src.scanners.scanner import ScanError


def build_parser() -> argparse.ArgumentParser:
    """Define the command-line arguments and automatically generated help."""
    parser = argparse.ArgumentParser(
        description="Run low-impact checks against a website you are authorized to assess."
    )
    parser.add_argument(
        "target",
        help="Website domain or HTTP(S) URL to analyze",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    try:
        parsed_url = Helper.parse_url(args.target)
        print(f"Analyzing {parsed_url.geturl()}\n")
        findings = HttpScanner().scan(parsed_url)
    except (ValueError, ScanError) as exc:
        print(f"Scan could not be completed: {exc}")
        return 1

    # Keep terminal formatting here; keep HTTP and check logic in HttpScanner.
    if not findings:
        print("No findings from the checks currently implemented.")
        print("This is not a guarantee that the website is secure.")
        return 0

    print(f"Findings: {len(findings)}\n")
    for finding in findings:
        print(f"[{finding.severity.value}] {finding.title}")
        print(f"  Check: {finding.check_id}")
        print(f"  What we found: {finding.description}")
        print(f"  Evidence: {finding.evidence}")
        print(f"  How to fix: {finding.remediation}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
