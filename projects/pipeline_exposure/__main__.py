"""CLI for the offline CI/CD exposure scanner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .scanner import _SEVERITY_ORDER, meets_or_exceeds, scan_path


def _render_text(findings: list[object]) -> str:
    if not findings:
        return "No exposure indicators found."
    return "\n".join(
        f"[{finding.severity.upper()}] {finding.path}:{finding.line} {finding.rule_id} — {finding.message}\n  {finding.excerpt}"
        for finding in findings
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan local CI/CD configuration for exposure indicators.")
    parser.add_argument("path", type=Path, help="File or directory to scan locally")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--fail-on", choices=tuple(_SEVERITY_ORDER), help="Exit nonzero when a finding meets this severity")
    args = parser.parse_args()
    try:
        findings = scan_path(args.path)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    if args.format == "json":
        print(json.dumps([finding.to_dict() for finding in findings], indent=2, sort_keys=True))
    else:
        print(_render_text(findings))
    return int(bool(args.fail_on and any(meets_or_exceeds(finding, args.fail_on) for finding in findings)))


if __name__ == "__main__":
    raise SystemExit(main())
