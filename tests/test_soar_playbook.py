from __future__ import annotations

import unittest

from projects.soar_playbook import Alert, PlaybookEngine


class SOARPlaybookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alert = Alert(
            alert_id="ALRT-001",
            source="training-scanner",
            severity="high",
            category="credential_exposure",
            asset="sample-service",
            summary="Synthetic training alert",
            indicators=("fixture-only",),
        )
        self.engine = PlaybookEngine()

    def test_dry_run_creates_approval_gated_actions_without_side_effects(self) -> None:
        result = self.engine.run(self.alert)
        statuses = {action.action_id: action.status for action in result.actions}
        self.assertEqual("dry-run", result.mode)
        self.assertEqual((), result.audit_log)
        self.assertEqual("planned", statuses["request-containment"])
        self.assertEqual("planned", statuses["request-credential-rotation"])

    def test_simulation_holds_unapproved_containment(self) -> None:
        result = self.engine.run(self.alert, mode="in-memory-simulation")
        statuses = {action.action_id: action.status for action in result.actions}
        self.assertEqual("simulated", statuses["open-case"])
        self.assertEqual("awaiting_approval", statuses["request-containment"])
        self.assertEqual(len(result.actions), len(result.audit_log))
        self.assertTrue(all("in-memory" in entry.note or "No approval" in entry.note for entry in result.audit_log))

    def test_explicit_lab_approval_only_changes_simulation_status(self) -> None:
        result = self.engine.run(
            self.alert,
            mode="in-memory-simulation",
            approved_action_ids=("request-containment",),
        )
        statuses = {action.action_id: action.status for action in result.actions}
        self.assertEqual("simulated", statuses["request-containment"])
        self.assertEqual("awaiting_approval", statuses["request-credential-rotation"])

    def test_invalid_alert_severity_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Alert("ALRT-002", "source", "urgent", "malware", "asset", "summary")


if __name__ == "__main__":
    unittest.main()
