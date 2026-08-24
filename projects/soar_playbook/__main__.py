"""CLI for a dry-run-first SOAR planning exercise."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import Alert, PlaybookEngine


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a dry-run incident-response playbook plan from local alert JSON.")
    parser.add_argument("--alert", required=True, type=Path, help="Path to a local alert JSON file")
    parser.add_argument("--simulate", action="store_true", help="Record simulated actions in memory; never contacts an external system")
    parser.add_argument(
        "--approve",
        action="append",
        default=[],
        metavar="ACTION_ID",
        help="Explicitly approve a named action only for the in-memory simulation",
    )
    args = parser.parse_args()
    try:
        payload = json.loads(args.alert.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Alert JSON must be an object")
        alert = Alert.from_mapping(payload)
        result = PlaybookEngine().run(
            alert,
            mode="in-memory-simulation" if args.simulate else "dry-run",
            approved_action_ids=args.approve,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
