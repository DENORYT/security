"""Auditable incident-response planning with no live integrations.

Every action is either planned (dry-run), simulated in memory, or held for
approval. Nothing in this module contacts an external system or changes a host.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

_VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


@dataclass(frozen=True)
class Alert:
    alert_id: str
    source: str
    severity: str
    category: str
    asset: str
    summary: str
    indicators: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not all(isinstance(value, str) and value.strip() for value in (self.alert_id, self.source, self.category, self.asset, self.summary)):
            raise ValueError("alert_id, source, category, asset, and summary must be non-empty strings")
        if self.severity.casefold() not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(_VALID_SEVERITIES)}")
        if not all(isinstance(value, str) and value.strip() for value in self.indicators):
            raise ValueError("indicators must be non-empty strings")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "Alert":
        indicators = value.get("indicators", [])
        if not isinstance(indicators, list):
            raise ValueError("indicators must be an array")
        return cls(
            alert_id=str(value.get("alert_id", "")),
            source=str(value.get("source", "")),
            severity=str(value.get("severity", "")).casefold(),
            category=str(value.get("category", "")).casefold(),
            asset=str(value.get("asset", "")),
            summary=str(value.get("summary", "")),
            indicators=tuple(str(indicator) for indicator in indicators),
        )


@dataclass(frozen=True)
class PlannedAction:
    action_id: str
    action_type: str
    target: str
    reason: str
    requires_approval: bool
    status: str = "planned"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AuditEntry:
    timestamp: str
    alert_id: str
    action_id: str
    status: str
    note: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class PlaybookRun:
    mode: str
    alert_id: str
    actions: tuple[PlannedAction, ...]
    audit_log: tuple[AuditEntry, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "alert_id": self.alert_id,
            "actions": [action.to_dict() for action in self.actions],
            "audit_log": [entry.to_dict() for entry in self.audit_log],
        }


class InMemoryAuditLog:
    """A transient audit trail used only for a local simulation run."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def record(self, alert_id: str, action: PlannedAction, status: str, note: str) -> None:
        self._entries.append(
            AuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                alert_id=alert_id,
                action_id=action.action_id,
                status=status,
                note=note,
            )
        )

    def entries(self) -> tuple[AuditEntry, ...]:
        return tuple(self._entries)


class PlaybookEngine:
    """Generate a conservative response plan and optionally simulate it in memory."""

    def plan(self, alert: Alert) -> tuple[PlannedAction, ...]:
        actions = [
            PlannedAction(
                "open-case",
                "case_management_record",
                alert.alert_id,
                "Create an auditable case record for analyst triage.",
                False,
            ),
            PlannedAction(
                "preserve-evidence",
                "evidence_preservation_request",
                alert.asset,
                "Request preservation of relevant logs and volatile evidence.",
                False,
            ),
            PlannedAction(
                "notify-oncall",
                "analyst_notification",
                alert.source,
                f"Notify the on-call analyst about: {alert.summary}",
                False,
            ),
        ]
        if alert.severity in {"high", "critical"}:
            actions.append(
                PlannedAction(
                    "request-containment",
                    "containment_approval_request",
                    alert.asset,
                    "High-severity alert requires human approval before containment.",
                    True,
                )
            )
        if alert.category == "credential_exposure":
            actions.append(
                PlannedAction(
                    "request-credential-rotation",
                    "credential_rotation_approval_request",
                    alert.asset,
                    "Potential exposure requires an owner-approved rotation request.",
                    True,
                )
            )
        return tuple(actions)

    def run(self, alert: Alert, *, mode: str = "dry-run", approved_action_ids: Sequence[str] = ()) -> PlaybookRun:
        if mode not in {"dry-run", "in-memory-simulation"}:
            raise ValueError("mode must be 'dry-run' or 'in-memory-simulation'")
        actions = self.plan(alert)
        if mode == "dry-run":
            return PlaybookRun(mode=mode, alert_id=alert.alert_id, actions=actions, audit_log=())

        approved = set(approved_action_ids)
        audit = InMemoryAuditLog()
        simulated_actions: list[PlannedAction] = []
        for action in actions:
            if action.requires_approval and action.action_id not in approved:
                updated = replace(action, status="awaiting_approval")
                audit.record(alert.alert_id, updated, updated.status, "No approval token supplied; held without side effect.")
            else:
                updated = replace(action, status="simulated")
                audit.record(alert.alert_id, updated, updated.status, "Recorded only in the in-memory lab ledger.")
            simulated_actions.append(updated)
        return PlaybookRun(mode=mode, alert_id=alert.alert_id, actions=tuple(simulated_actions), audit_log=audit.entries())
