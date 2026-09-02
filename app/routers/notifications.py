# app/routers/notifications.py - Notification API Router (Step 7 PRD v1.1)
import logging
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

from app.models.notification import (
    NotificationPayload,
    NotificationEvent,
    NotificationChannel,
    NotificationDeliveryRecord,
)
from app.services.notification_service import notification_service
from app.security import get_current_user_and_company

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/notifications",
    tags=["Notifications"],
)


class NotificationDispatchRequest(BaseModel):
    event_type: NotificationEvent = Field(
        ..., description="Security event triggering notification"
    )
    channel: NotificationChannel = Field(
        default=NotificationChannel.EMAIL, description="Dispatch channel"
    )
    recipient: str = Field(..., description="Target email address / phone")
    vendor_name: str = Field(..., description="Target vendor name")
    request_id: Optional[str] = Field(
        default=None, description="Change request ID"
    )
    masked_account_number: Optional[str] = Field(
        default=None, description="Masked account reference"
    )
    cooling_off_hours: Optional[int] = Field(
        default=48, description="Cooling off period in hours"
    )
    effective_date: Optional[str] = Field(
        default=None, description="Authoritative effective date"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Sanitized metadata"
    )


class CoolingOffCheckRequest(BaseModel):
    effective_date_iso: str = Field(
        ..., description="Authoritative ISO effective_date from database"
    )


@router.post(
    "/dispatch",
    status_code=status.HTTP_200_OK,
    summary="Dispatch security notification (Asynchronous with Exponential Retries & Delivery Ledger)",
)
async def dispatch_security_notification(
    dispatch_req: NotificationDispatchRequest,
    user_context: dict = Depends(get_current_user_and_company),
):
    """
    Triggers an asynchronous, PII-masked security notification.
    Enforces backend-only tenant resolution and records attempts in delivery ledger.
    """
    company_id = user_context["company_id"]
    user_id = user_context["user_id"]

    payload = NotificationPayload(
        company_id=company_id,
        request_id=dispatch_req.request_id,
        event_type=dispatch_req.event_type,
        channel=dispatch_req.channel,
        recipient=dispatch_req.recipient,
        vendor_name=dispatch_req.vendor_name,
        masked_account_number=dispatch_req.masked_account_number,
        cooling_off_hours=dispatch_req.cooling_off_hours,
        effective_date=dispatch_req.effective_date,
        actor_id=user_id,
        metadata=dispatch_req.metadata,
    )

    result = await notification_service.dispatch_with_retry(payload)

    return {
        "message": "Notification dispatch processed.",
        "delivery_result": result,
    }


@router.post(
    "/cooling-off-check",
    status_code=status.HTTP_200_OK,
    summary="Backend-Authoritative 48-Hour Cooling-Off Reminder Evaluator",
)
async def check_cooling_off_status(
    check_req: CoolingOffCheckRequest,
    user_context: dict = Depends(get_current_user_and_company),
):
    """
    Evaluates cooling-off reminder/completion timing strictly from authoritative database effective_date.
    """
    result = notification_service.evaluate_cooling_off_reminder(
        check_req.effective_date_iso
    )
    return {"cooling_off_evaluation": result}


@router.get(
    "/deliveries/{notification_id}",
    response_model=List[NotificationDeliveryRecord],
    status_code=status.HTTP_200_OK,
    summary="Query audit delivery ledger for notification attempts",
)
async def get_notification_deliveries(
    notification_id: str,
    user_context: dict = Depends(get_current_user_and_company),
):
    """
    Returns auditable delivery attempts from the immutable ledger.
    """
    return notification_service.ledger.get_attempts_for_notification(
        notification_id
    )
