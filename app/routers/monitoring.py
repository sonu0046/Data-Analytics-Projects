# app/routers/monitoring.py - Monitoring & Alerting Router (Step 8 PRD v1.1)
import logging
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import uuid

from app.models.monitoring import (
    AlertSeverity,
    AlertEventInput,
    AlertRecord,
    IncidentStatus,
    IncidentRecord,
    IncidentTransitionRequest,
    IncidentTransitionRecord,
    SystemMetricsSummary,
)
from app.services.alert_service import alert_service
from app.services.incident_service import incident_service
from app.services.monitoring_service import monitoring_service
from app.security import get_current_user_and_company

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/monitoring",
    tags=["Monitoring & Alerting"],
)


class IncidentTransitionApiRequest(BaseModel):
    incident_id: uuid.UUID
    from_status: IncidentStatus
    to_status: IncidentStatus
    notes: Optional[str] = Field(
        default="", description="Forensic rationale for transition"
    )


@router.post(
    "/alerts",
    status_code=status.HTTP_201_CREATED,
    summary="Ingest monitoring alert event (Atomic Deduplication & Anti-Storm)",
)
async def ingest_alert(
    event: AlertEventInput,
    user_context: dict = Depends(get_current_user_and_company),
):
    """
    Ingests an alert event with canonical versioned fingerprinting and anti-alert-storm deduplication.
    """
    if str(event.company_id) != str(user_context["company_id"]):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="TENANT_ISOLATION_VIOLATION: Cannot ingest alert for another company.",
        )

    result = await alert_service.ingest_alert_event(event)
    return {
        "message": "Alert processed.",
        "action": result["action"],
        "event_count": result["event_count"],
        "is_storm_suppressed": result["is_storm_suppressed"],
    }


@router.get(
    "/alerts",
    response_model=List[AlertRecord],
    status_code=status.HTTP_200_OK,
    summary="Query active alerts for authenticated tenant",
)
async def get_active_alerts(
    user_context: dict = Depends(get_current_user_and_company),
):
    """Returns all active firing alerts for the tenant."""
    company_id = user_context["company_id"]
    return alert_service.get_active_alerts(company_id=uuid.UUID(company_id))


@router.post(
    "/incidents/transition",
    response_model=IncidentRecord,
    status_code=status.HTTP_200_OK,
    summary="Transition incident state (Strict State Machine Validated)",
)
async def transition_incident_state(
    transition_req: IncidentTransitionApiRequest,
    user_context: dict = Depends(get_current_user_and_company),
):
    """
    Transitions an incident through its strict lifecycle state machine.
    Invalid transitions or stale states are rejected with 400 Bad Request.
    """
    company_id = uuid.UUID(user_context["company_id"])
    user_id = uuid.UUID(user_context["user_id"])

    # Verify incident exists and belongs to company
    incident = incident_service.get_incident(transition_req.incident_id)
    if not incident or incident.company_id != company_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found or unauthorized.",
        )

    try:
        updated_incident = incident_service.transition_incident(
            incident_id=transition_req.incident_id,
            company_id=company_id,
            actor_id=user_id,
            from_status=transition_req.from_status,
            to_status=transition_req.to_status,
            notes=transition_req.notes,
        )
        return updated_incident
    except (ValueError, PermissionError) as ex:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ex),
        )


@router.get(
    "/incidents",
    response_model=List[IncidentRecord],
    status_code=status.HTTP_200_OK,
    summary="List all incidents for authenticated tenant",
)
async def list_incidents(
    user_context: dict = Depends(get_current_user_and_company),
):
    """Lists all incidents scoped to authenticated tenant."""
    company_id = uuid.UUID(user_context["company_id"])
    return incident_service.list_incidents(company_id=company_id)


@router.get(
    "/metrics",
    response_model=SystemMetricsSummary,
    status_code=status.HTTP_200_OK,
    summary="Live system health and anti-storm telemetry metrics",
)
async def get_metrics(
    user_context: dict = Depends(get_current_user_and_company),
):
    """Returns real-time telemetry metrics and suppression rates."""
    company_id = uuid.UUID(user_context["company_id"])
    return monitoring_service.get_system_metrics(company_id=company_id)
