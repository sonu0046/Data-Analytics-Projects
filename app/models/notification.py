# app/models/notification.py - Notification Models (Step 7 PRD v1.1)
from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from pydantic import BaseModel, Field, UUID4


class NotificationChannel(str, Enum):
    EMAIL = "EMAIL"
    SMS = "SMS"
    WEBHOOK = "WEBHOOK"


class NotificationStatus(str, Enum):
    PENDING = "PENDING"
    SENT = "SENT"
    FAILED = "FAILED"
    RETRYING = "RETRYING"


class NotificationEvent(str, Enum):
    REQUEST_INTAKED = "REQUEST_INTAKED"
    CRITICAL_FRAUD_BLOCK = "CRITICAL_FRAUD_BLOCK"
    MAKER_VERIFIED = "MAKER_VERIFIED"
    CHECKER_APPROVED_COOLING_OFF = "CHECKER_APPROVED_COOLING_OFF"
    COOLING_OFF_REMINDER_24H = "COOLING_OFF_REMINDER_24H"
    COOLING_OFF_COMPLETED = "COOLING_OFF_COMPLETED"
    REQUEST_REJECTED = "REQUEST_REJECTED"


# Security-Critical Events cannot be opted out
NON_OPT_OUT_EVENTS = {
    NotificationEvent.REQUEST_INTAKED,
    NotificationEvent.CRITICAL_FRAUD_BLOCK,
    NotificationEvent.MAKER_VERIFIED,
    NotificationEvent.CHECKER_APPROVED_COOLING_OFF,
    NotificationEvent.COOLING_OFF_REMINDER_24H,
    NotificationEvent.COOLING_OFF_COMPLETED,
    NotificationEvent.REQUEST_REJECTED,
}


class NotificationPayload(BaseModel):
    """Sanitized payload for notification dispatch."""

    company_id: UUID4 = Field(..., description="Tenant identifier")
    request_id: Optional[UUID4] = Field(
        default=None, description="Change request reference"
    )
    event_type: NotificationEvent = Field(
        ..., description="Triggering security event"
    )
    channel: NotificationChannel = Field(
        default=NotificationChannel.EMAIL, description="Dispatch channel"
    )
    recipient: str = Field(..., description="Recipient email address or phone")
    vendor_name: str = Field(..., description="Target vendor name")
    masked_account_number: Optional[str] = Field(
        default=None,
        description="Strictly masked account number (e.g. 1234XXXX5678)",
    )
    cooling_off_hours: Optional[int] = Field(
        default=None, description="Authoritative cooling off duration"
    )
    effective_date: Optional[str] = Field(
        default=None, description="Authoritative activation timestamp"
    )
    actor_id: Optional[str] = Field(
        default=None, description="Actor initiating the event"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional sanitized context"
    )


class NotificationDeliveryRecord(BaseModel):
    """Immutable audit record for each delivery attempt."""

    id: Optional[UUID4] = None
    notification_id: Optional[UUID4] = None
    company_id: UUID4
    channel: NotificationChannel
    provider_name: str
    attempt_number: int = Field(..., ge=1)
    status: NotificationStatus
    duration_ms: int = Field(default=0, ge=0)
    safe_error: Optional[str] = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class NotificationRecord(BaseModel):
    """Persisted notification record."""

    id: Optional[UUID4] = None
    company_id: UUID4
    request_id: Optional[UUID4] = None
    event_type: str
    channel: NotificationChannel
    recipient_masked: str
    template_key: str
    payload_sanitized: Dict[str, Any]
    status: NotificationStatus = NotificationStatus.PENDING
    retry_count: int = 0
    max_retries: int = 3
    last_error: Optional[str] = None
    sent_at: Optional[datetime] = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    deliveries: List[NotificationDeliveryRecord] = Field(default_factory=list)
