from __future__ import annotations

from pathlib import Path
import unittest

from projects.c2_lab import AgentProfile, LabSafetyError, Task, run_scenario
from scripts.validate import c2_safety_violations, validate_c2_lab


class C2LabSafetyTests(unittest.TestCase):
    def test_safe_scenario_produces_synthetic_transcript(self) -> None:
        result = run_scenario(
            {
                "agents": [
                    {
                        "agent_id": "lab-node-01",
                        "display_name": "training-workstation",
                        "platform": "windows-lab",
                        "asset_tag": "LAB-001",
                    }
                ],
                "tasks": [
                    {"task_id": "inventory-001", "agent_id": "lab-node-01", "kind": "inventory_snapshot", "parameters": {}}
                ],
            }
        )
        self.assertEqual("offline-simulation", result["mode"])
        self.assertEqual(["agent_enrolled", "task_queued", "task_simulated"], [event["event_type"] for event in result["events"]])
        self.assertEqual("simulated", result["events"][-1]["detail"]["status"])

    def test_rejects_non_simulation_task_type(self) -> None:
        with self.assertRaises(LabSafetyError):
            Task(task_id="bad-001", agent_id="lab-node-01", kind="remote_control", parameters={})

    def test_rejects_unsafe_parameter_content(self) -> None:
        with self.assertRaises(LabSafetyError):
            Task(
                task_id="bad-002",
                agent_id="lab-node-01",
                kind="evidence_label",
                parameters={"label": "please download data"},
            )

    def test_profile_validation_rejects_unsafe_labels(self) -> None:
        with self.assertRaises(LabSafetyError):
            AgentProfile("lab-node-02", "network agent", "windows-lab", "LAB-002")

    def test_validator_inspects_every_c2_python_module(self) -> None:
        self.assertEqual([], validate_c2_lab())

    def test_validator_rejects_transport_and_execution_in_any_module(self) -> None:
        synthetic_path = Path("alternate-module.py")
        self.assertTrue(c2_safety_violations("import socket\n", synthetic_path))
        self.assertTrue(c2_safety_violations("subprocess.run([])\n", synthetic_path))
        self.assertTrue(c2_safety_violations("eval('1 + 1')\n", synthetic_path))
        self.assertTrue(
            c2_safety_violations(
                "import importlib\ngetattr(importlib, 'import_module')('subprocess')\n",
                synthetic_path,
            )
        )


if __name__ == "__main__":
    unittest.main()
