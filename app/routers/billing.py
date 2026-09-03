# app/routers/billing.py - SaaS Billing & Subscription API Router (Step 10 PRD v1.1)
from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from pydantic import UUID4
from typing import Dict, Any, List

from app.models.billing import (
    SubscriptionResponse,
    SubscriptionLedgerEntry,
    WebhookPayloadInput,
)
from app.services.billing_service import BillingService

router = APIRouter(prefix="/api/v1/billing", tags=["SaaS Billing & Subscriptions"])
billing_service = BillingService()


@router.get(
    "/subscription",
    response_model=SubscriptionResponse,
    summary="Get Tenant Authoritative Subscription State",
)
async def get_tenant_subscription(
    company_id: UUID4,
):
    """
    Returns server-side authoritative subscription entitlements, usage, and locks.
    """
    try:
        return billing_service.get_subscription(company_id)
    except KeyError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Subscription not found for company {company_id}",
        )


@router.post(
    "/webhook/{provider}",
    summary="Secure Webhook Receiver (Idempotent & Signature Verified)",
)
async def handle_payment_webhook(
    provider: str,
    payload: WebhookPayloadInput,
    request: Request,
):
    """
    Processes incoming payment events from Razorpay/Stripe with HMAC verification and idempotency.
    """
    raw_body = await request.body()
    raw_body_str = raw_body.decode("utf-8") if raw_body else ""

    try:
        result = billing_service.process_payment_webhook(
            raw_body=raw_body_str or payload.signature,
            signature=payload.signature,
            provider_event_id=payload.provider_event_id,
            event_type=payload.event_type,
            company_id=payload.company_id,
        )
        return result
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(pe),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get(
    "/ledger",
    response_model=List[SubscriptionLedgerEntry],
    summary="Immutable Subscription Audit Trail",
)
async def get_subscription_ledger(
    company_id: UUID4,
):
    """
    Returns immutable audit entries for all subscription transitions of the tenant.
    """
    return [
        entry
        for entry in billing_service.store.ledger
        if entry.company_id == company_id
    ]
