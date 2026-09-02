# app/models/monitoring.py - Monitoring & Alerting Models (Step 8 PRD v1.1)
from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from pydantic import BaseModel, Field, UUID4


class AlertSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    FIRING = "FIRING"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    MITIGATED = "MITIGATED"
    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"


# Valid state machine transitions
ALLOWED_INCIDENT_TRANSITIONS = {
    IncidentStatus.OPEN: [
        IncidentStatus.INVESTIGATING,
        IncidentStatus.ESCALATED,
        IncidentStatus.RESOLVED,
    ],
    IncidentStatus.INVESTIGATING: [
        IncidentStatus.MITIGATED,
        IncidentStatus.ESCALATED,
        IncidentStatus.RESOLVED,
    ],
    IncidentStatus.MITIGATED: [
        IncidentStatus.RESOLVED,
        IncidentStatus.INVESTIGATING,
    ],
    IncidentStatus.ESCALATED: [
        IncidentStatus.INVESTIGATING,
        IncidentStatus.MITIGATED,
        IncidentStatus.RESOLVED,
    ],
    IncidentStatus.RESOLVED: [
        IncidentStatus.OPEN,  # Re-opening requires explicit authorized justification
    ],
}


class AlertEventInput(BaseModel):
    """Input for firing a new or updated monitoring alert."""

    company_id: UUID4 = Field(..., description="Tenant identifier")
    alert_type: str = Field(
        ...,
        description="Type of alert (e.g. VELOCITY_ANOMALY, SPOOF_DETECTED, AUTH_FAILURE)",
    )
    severity: AlertSeverity = Field(
        default=AlertSeverity.WARNING, description="Alert severity level"
    )
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(default=None)
    entity_type: Optional[str] = Field(
        default=None, description="Entity type: VENDOR, REQUEST, USER, SYSTEM"
    )
    entity_id: Optional[UUID4] = Field(
        default=None, description="Entity UUID reference"
    )
    payload_sanitized: Dict[str, Any] = Field(
        default_factory=dict, description="Sanitized metadata (no raw PII)"
    )


class AlertRecord(BaseModel):
    """Persisted Alert schema."""

    id: Optional[UUID4] = None
    company_id: UUID4
    fingerprint: str
    alert_type: str
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.FIRING
    title: str
    description: Optional[str] = None
    entity_type: Optional[str] = None
    entity_id: Optional[UUID4] = None
    event_count: int = 1
    first_seen_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_seen_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    payload_sanitized: Dict[str, Any] = Field(default_factory=dict)


class IncidentRecord(BaseModel):
    """Persisted Incident schema."""

    id: Optional[UUID4] = None
    company_id: UUID4
    alert_id: Optional[UUID4] = None
    title: str
    severity: AlertSeverity
    status: IncidentStatus = IncidentStatus.OPEN
    assigned_to: Optional[UUID4] = None
    summary: Optional[str] = None
    mitigation_notes: Optional[str] = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class IncidentTransitionRequest(BaseModel):
    """Request to transition incident state."""

    incident_id: UUID4
    to_status: IncidentStatus
    notes: Optional[str] = Field(
        default="", description="Forensic rationale for transition"
    )


class IncidentTransitionRecord(BaseModel):
    """Immutable record of incident state transition."""

    id: Optional[UUID4] = None
    incident_id: UUID4
    company_id: UUID4
    from_status: IncidentStatus
    to_status: IncidentStatus
    actor_id: UUID4
    notes: Optional[str] = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class SystemMetricsSummary(BaseModel):
    """System telemetry and health metrics."""

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    active_alerts_count: int = 0
    open_incidents_count: int = 0
    high_risk_requests_last_24h: int = 0
    system_health_status: str = "HEALTHY"
    anti_storm_suppression_rate: float = 0.0
