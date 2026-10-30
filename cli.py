"""CLI: python cli.py <path> [--fail-on high|medium|low] [--json]

Scans a file or a directory tree of .py files and prints findings.
Exit code 1 if any finding meets the fail threshold (default: high),
so it slots into a pre-commit hook or CI step without ceremony.
"""

import argparse
import json
import sys
from pathlib import Path

from scanner import scan_file

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def collect(path):
    path = Path(path)
    if path.is_file():
        return [path]
    return sorted(p for p in path.rglob("*.py") if p.is_file())


def main(argv=None):
    parser = argparse.ArgumentParser(description="code-triage: tiny Python security scanner")
    parser.add_argument("path", help="file or directory to scan")
    parser.add_argument("--fail-on", default="high",
                        choices=["high", "medium", "low"],
                        help="exit 1 if a finding at or above this severity appears")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    all_findings = []
    for filepath in collect(args.path):
        for finding in scan_file(filepath):
            all_findings.append((str(filepath), finding))

    if args.json:
        print(json.dumps([
            {"file": f, "rule": x.rule, "severity": x.severity,
             "line": x.line, "message": x.message, "snippet": x.snippet}
            for f, x in all_findings
        ], indent=2))
    else:
        if not all_findings:
            print("clean — no findings")
        for filepath, finding in all_findings:
            print(f"{filepath}:{finding.line}  {finding}")
            if finding.snippet:
                print(f"    > {finding.snippet}")
        print(f"\n{len(all_findings)} finding(s)")

    threshold = SEVERITY_RANK[args.fail_on]
    failed = any(SEVERITY_RANK[f.severity] >= threshold for _, f in all_findings)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
