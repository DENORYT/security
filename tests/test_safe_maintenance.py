from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
import tempfile
import unittest
from unittest.mock import patch

from scripts import safe_maintenance as guard


class SafeMaintenanceGuardTests(unittest.TestCase):
    def test_staged_paths_retains_runtime_state_for_fail_closed_review(self) -> None:
        staged_output = ".pi/goals/goal_events.jsonl\nREADME.md\n"
        with patch.object(guard, "run", return_value=CompletedProcess([], 0, stdout=staged_output, stderr="")):
            self.assertEqual([".pi/goals/goal_events.jsonl", "README.md"], guard.staged_paths())

    def test_validation_blocks_preexisting_staged_runtime_state(self) -> None:
        def fake_run(*args: str, capture: bool = False) -> CompletedProcess[str]:
            output = ".pi/goals/goal_events.jsonl\n" if args == ("git", "diff", "--cached", "--name-only") else ""
            return CompletedProcess(list(args), 0, stdout=output, stderr="")

        with patch.object(guard, "run", side_effect=fake_run):
            failures = guard.validate(["README.md"])
        self.assertIn("pre-existing staged changes require human review", failures)

    def test_oversized_changed_file_is_rejected_before_secret_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            oversized = root / "large-notes.md"
            oversized.write_bytes(b"x" * (guard.ExposureScanner().max_file_bytes + 1))
            with patch.object(guard, "ROOT", root):
                failures = guard.uninspectable_changed_files(["large-notes.md"])
        self.assertTrue(any("exceeds" in failure for failure in failures))


if __name__ == "__main__":
    unittest.main()
