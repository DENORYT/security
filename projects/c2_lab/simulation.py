"""Deterministic, no-network simulation for C2-oriented training discussions.

This module only produces synthetic records. It has no transport, no process
control, no filesystem mutation, and no facility for running instructions on a
host.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

SAFE_TASK_KINDS = frozenset({"inventory_snapshot", "training_check_in", "evidence_label"})
_BLOCKED_TERMS = frozenset(
    {
        "shell",
        "command",
        "execute",
        "download",
        "upload",
        "payload",
        "beacon",
        "socket",
        "network",
        "process",
        "credential",
    }
)


class LabSafetyError(ValueError):
    """Raised when a scenario tries to cross the simulator's safety boundary."""


def _validate_text(value: object, field_name: str) -> None:
    if not isinstance(value, str):
        raise LabSafetyError(f"{field_name} must be a string")
    normalized = value.casefold()
    if any(term in normalized for term in _BLOCKED_TERMS):
        raise LabSafetyError(f"{field_name} contains a prohibited capability term")


def _validate_mapping(value: Mapping[str, Any], prefix: str = "parameters") -> None:
    for key, item in value.items():
        _validate_text(str(key), f"{prefix} key")
        if isinstance(item, Mapping):
            _validate_mapping(item, f"{prefix}.{key}")
        elif isinstance(item, str):
            _validate_text(item, f"{prefix}.{key}")
        elif not isinstance(item, (bool, int, float, type(None))):
            raise LabSafetyError(f"{prefix}.{key} has an unsupported value type")


@dataclass(frozen=True)
class AgentProfile:
    agent_id: str
    display_name: str
    platform: str
    asset_tag: str

    def __post_init__(self) -> None:
        for field_name, value in asdict(self).items():
            _validate_text(value, field_name)


@dataclass(frozen=True)
class Task:
    task_id: str
    agent_id: str
    kind: str
    parameters: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_text(self.task_id, "task_id")
        _validate_text(self.agent_id, "agent_id")
        if self.kind not in SAFE_TASK_KINDS:
            raise LabSafetyError(f"Task kind {self.kind!r} is not a safe simulation task")
        if not isinstance(self.parameters, Mapping):
            raise LabSafetyError("parameters must be an object")
        _validate_mapping(self.parameters)


@dataclass(frozen=True)
class SimulationEvent:
    sequence: int
    event_type: str
    agent_id: str
    task_id: str | None
    detail: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class TrainingController:
    """In-memory state machine that creates a synthetic training transcript."""

    def __init__(self) -> None:
        self._agents: dict[str, AgentProfile] = {}
        self._queued_tasks: list[Task] = []
        self._events: list[SimulationEvent] = []

    def enroll(self, agent: AgentProfile) -> None:
        if agent.agent_id in self._agents:
            raise LabSafetyError(f"Agent {agent.agent_id!r} is already enrolled")
        self._agents[agent.agent_id] = agent
        self._record("agent_enrolled", agent.agent_id, None, {"display_name": agent.display_name, "asset_tag": agent.asset_tag})

    def queue(self, task: Task) -> None:
        if task.agent_id not in self._agents:
            raise LabSafetyError(f"Task references an unknown agent: {task.agent_id!r}")
        if any(existing.task_id == task.task_id for existing in self._queued_tasks):
            raise LabSafetyError(f"Task {task.task_id!r} is already queued")
        self._queued_tasks.append(task)
        self._record("task_queued", task.agent_id, task.task_id, {"kind": task.kind})

    def simulate_all(self) -> list[SimulationEvent]:
        """Generate safe, fabricated results for every queued task in FIFO order."""
        while self._queued_tasks:
            task = self._queued_tasks.pop(0)
            agent = self._agents[task.agent_id]
            self._record("task_simulated", task.agent_id, task.task_id, self._synthetic_result(agent, task))
        return list(self._events)

    def transcript(self) -> list[dict[str, Any]]:
        return [event.to_dict() for event in self._events]

    def _record(self, event_type: str, agent_id: str, task_id: str | None, detail: Mapping[str, Any]) -> None:
        self._events.append(
            SimulationEvent(
                sequence=len(self._events) + 1,
                event_type=event_type,
                agent_id=agent_id,
                task_id=task_id,
                detail=dict(detail),
            )
        )

    @staticmethod
    def _synthetic_result(agent: AgentProfile, task: Task) -> dict[str, Any]:
        if task.kind == "inventory_snapshot":
            return {
                "status": "simulated",
                "observation": {
                    "asset_tag": agent.asset_tag,
                    "platform": agent.platform,
                    "label": agent.display_name,
                    "source": "synthetic-lab-record",
                },
            }
        if task.kind == "training_check_in":
            return {"status": "simulated", "observation": "training check-in recorded; no host was contacted"}
        # evidence_label is intentionally only metadata labelling.
        return {
            "status": "simulated",
            "observation": {"label": str(task.parameters.get("label", "unlabelled")), "source": "synthetic-lab-record"},
        }


def run_scenario(scenario: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and run a local JSON scenario, returning only synthetic records."""
    agents = scenario.get("agents", [])
    tasks = scenario.get("tasks", [])
    if not isinstance(agents, list) or not isinstance(tasks, list):
        raise LabSafetyError("Scenario fields 'agents' and 'tasks' must be arrays")

    controller = TrainingController()
    for entry in agents:
        if not isinstance(entry, Mapping):
            raise LabSafetyError("Every agent entry must be an object")
        controller.enroll(
            AgentProfile(
                agent_id=str(entry.get("agent_id", "")),
                display_name=str(entry.get("display_name", "")),
                platform=str(entry.get("platform", "")),
                asset_tag=str(entry.get("asset_tag", "")),
            )
        )
    for entry in tasks:
        if not isinstance(entry, Mapping):
            raise LabSafetyError("Every task entry must be an object")
        parameters = entry.get("parameters", {})
        if not isinstance(parameters, Mapping):
            raise LabSafetyError("Task parameters must be an object")
        controller.queue(
            Task(
                task_id=str(entry.get("task_id", "")),
                agent_id=str(entry.get("agent_id", "")),
                kind=str(entry.get("kind", "")),
                parameters=parameters,
            )
        )
    controller.simulate_all()
    return {"mode": "offline-simulation", "events": controller.transcript()}
