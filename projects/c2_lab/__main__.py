"""CLI for the safe local training scenario runner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .simulation import LabSafetyError, run_scenario


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a no-network C2 training simulation from local JSON.")
    parser.add_argument("--scenario", required=True, type=Path, help="Path to a synthetic scenario JSON file")
    args = parser.parse_args()
    try:
        scenario = json.loads(args.scenario.read_text(encoding="utf-8"))
        if not isinstance(scenario, dict):
            raise LabSafetyError("Scenario JSON must be an object")
        result = run_scenario(scenario)
    except (OSError, LabSafetyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
