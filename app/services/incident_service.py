# app/services/incident_service.py - Incident Management & State Machine (Step 8 PRD v1.1)
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from pydantic import UUID4
import uuid

from app.models.monitoring import (
    AlertSeverity,
    IncidentStatus,
    IncidentRecord,
    IncidentTransitionRequest,
    IncidentTransitionRecord,
    ALLOWED_INCIDENT_TRANSITIONS,
)

logger = logging.getLogger(__name__)


class IncidentService:
    """
    Manages incident creation and strict state-machine transitions with immutable audit history.
    """

    def __init__(self):
        self._incidents: Dict[UUID4, IncidentRecord] = {}
        self._transitions_ledger: List[IncidentTransitionRecord] = []

    def create_incident_from_alert(
        self,
        company_id: UUID4,
        title: str,
        severity: AlertSeverity,
        alert_id: Optional[UUID4] = None,
        summary: Optional[str] = None,
        actor_id: Optional[UUID4] = None,
    ) -> IncidentRecord:
        """Creates a new incident in OPEN status and logs transition."""
        inc_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        incident = IncidentRecord(
            id=inc_id,
            company_id=company_id,
            alert_id=alert_id,
            title=title,
            severity=severity,
            status=IncidentStatus.OPEN,
            summary=summary,
            created_at=now,
            updated_at=now,
        )
        self._incidents[inc_id] = incident

        # Initial transition record
        transition = IncidentTransitionRecord(
            incident_id=inc_id,
            company_id=company_id,
            from_status=IncidentStatus.OPEN,
            to_status=IncidentStatus.OPEN,
            actor_id=actor_id or uuid.uuid4(),
            notes="Incident automatically opened from security alert.",
            created_at=now,
        )
        self._transitions_ledger.append(transition)

        logger.info(
            f"[INCIDENT_CREATED] ID={inc_id} | Title='{title}' | Severity={severity.value}"
        )
        return incident

    def transition_incident(
        self,
        incident_id: UUID4,
        company_id: UUID4,
        actor_id: UUID4,
        from_status: IncidentStatus,
        to_status: IncidentStatus,
        notes: Optional[str] = None,
    ) -> IncidentRecord:
        """
        Transitions incident state via authorized security path.
        STRICT STATE MACHINE: Validates from_status against current state and ALLOWED_INCIDENT_TRANSITIONS.
        """
        incident = self._incidents.get(incident_id)
        if not incident:
            raise KeyError(f"Incident with ID {incident_id} not found.")

        # Multi-tenancy check
        if incident.company_id != company_id:
            raise PermissionError(
                "TENANT_ISOLATION_VIOLATION: Unauthorized incident access."
            )

        current_status = incident.status

        # Stale state conflict check
        if current_status != from_status:
            raise ValueError(
                f"STALE_STATE_CONFLICT: Current incident status is '{current_status.value}', expected '{from_status.value}'."
            )

        # Target identical check
        if current_status == to_status:
            return incident

        # Validate allowed transition
        allowed_targets = ALLOWED_INCIDENT_TRANSITIONS.get(current_status, [])
        if to_status not in allowed_targets:
            err_msg = (
                f"INVALID_STATE_TRANSITION: Cannot transition incident from "
                f"'{current_status.value}' to '{to_status.value}'. "
                f"Allowed transitions: {[s.value for s in allowed_targets]}"
            )
            logger.warning(
                f"[INCIDENT_TRANSITION_REJECTED] ID={incident_id} | {err_msg}"
            )
            raise ValueError(err_msg)

        now = datetime.now(timezone.utc)

        # Update incident state
        incident.status = to_status
        incident.updated_at = now
        if notes and to_status in (
            IncidentStatus.MITIGATED,
            IncidentStatus.RESOLVED,
        ):
            incident.mitigation_notes = notes

        # Record immutable transition in ledger
        transition = IncidentTransitionRecord(
            incident_id=incident_id,
            company_id=company_id,
            from_status=current_status,
            to_status=to_status,
            actor_id=actor_id,
            notes=notes,
            created_at=now,
        )
        self._transitions_ledger.append(transition)

        logger.info(
            f"[INCIDENT_TRANSITIONED] ID={incident_id} | From={current_status.value} -> To={to_status.value} | Actor={actor_id}"
        )
        return incident

    # Client Direct Mutation Blocker Methods
    def direct_client_update(self, incident_id: UUID4, **kwargs):
        """Prohibits direct client updates without going through transition state machine."""
        raise PermissionError(
            "SECURITY_VIOLATION: Direct client updates on incidents are permanently prohibited. All state transitions must use transition_incident()."
        )

    def direct_client_delete(self, incident_id: UUID4):
        """Prohibits incident deletion."""
        raise PermissionError(
            "SECURITY_VIOLATION: Incidents cannot be deleted. Deletion is permanently prohibited for audit integrity."
        )

    def direct_transition_insert(self, record: IncidentTransitionRecord):
        """Prohibits direct manual insertion of transitions."""
        raise PermissionError(
            "SECURITY_VIOLATION: Direct client insertion of incident transitions is prohibited. Transitions must occur via authorized state machine."
        )

    def get_incident(self, incident_id: UUID4) -> Optional[IncidentRecord]:
        return self._incidents.get(incident_id)

    def list_incidents(
        self, company_id: Optional[UUID4] = None
    ) -> List[IncidentRecord]:
        incidents = list(self._incidents.values())
        if company_id:
            incidents = [i for i in incidents if i.company_id == company_id]
        return incidents

    def get_transitions(
        self, incident_id: UUID4
    ) -> List[IncidentTransitionRecord]:
        return [
            t for t in self._transitions_ledger if t.incident_id == incident_id
        ]


# Global instance
incident_service = IncidentService()
