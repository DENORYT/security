from __future__ import annotations

import json
from pathlib import Path
import unittest


SCHEDULE_FILE = Path(__file__).parents[1] / ".pi" / "subagents" / "schedules" / "99c6ec4f" / "schedule.json"


class TellnovaScheduleTests(unittest.TestCase):
    def test_active_schedule_is_present_and_fail_closed(self) -> None:
        payload = json.loads(SCHEDULE_FILE.read_text(encoding="utf-8"))
        self.assertEqual("99c6ec4f", payload["id"])
        self.assertFalse(payload["paused"])
        self.assertEqual("interval", payload["trigger"]["kind"])
        self.assertEqual("24h", payload["trigger"]["every"])
        self.assertEqual("skip", payload["overlap"])
        workflow = payload["target"]["workflowScript"]
        self.assertIn("scripts/validate.py", workflow)
        self.assertIn("scripts/safe_maintenance.py --check", workflow)
        self.assertIn("scripts/safe_maintenance.py --commit --push", workflow)
        self.assertNotIn("--force", workflow)


if __name__ == "__main__":
    unittest.main()
