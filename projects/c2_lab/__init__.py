"""Offline, non-deployable C2 control-flow training simulator."""

from .simulation import AgentProfile, LabSafetyError, Task, TrainingController, run_scenario

__all__ = ["AgentProfile", "LabSafetyError", "Task", "TrainingController", "run_scenario"]
