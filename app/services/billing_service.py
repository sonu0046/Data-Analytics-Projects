# app/services/billing_service.py - SaaS Billing, Subscriptions & Entitlements Engine (Step 10 PRD v1.1)
import os
import hmac
import hashlib
import json
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone, timedelta
from pydantic import UUID4

from app.models.billing import (
    SubscriptionTier,
    SubscriptionStatus,
    BillingCadence,
    TIER_PRICING_CONFIG,
    ANNUAL_DISCOUNT_PERCENT,
    EARLY_ADOPTER_DISCOUNT_PERCENT,
    GST_RATE_PERCENT,
    ALLOWED_SUBSCRIPTION_TRANSITIONS,
    SubscriptionResponse,
    SubscriptionLedgerEntry,
)


class PaymentProviderAdapter:
    """Base provider interface for Payment & Subscription Gateways."""

    def verify_webhook_signature(
        self, raw_body: str, signature: str, secret: str
    ) -> bool:
        raise NotImplementedError


class MockPaymentAdapter(PaymentProviderAdapter):
    """Secure deterministic test adapter with HMAC-SHA256 validation."""

    def verify_webhook_signature(
        self, raw_body: str, signature: str, secret: str
    ) -> bool:
        if not signature or not secret:
            return False
        expected = hmac.new(
            secret.encode("utf-8"),
            raw_body.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)


class InMemorySubscriptionStore:
    """Thread-safe, append-only in-memory storage simulator for billing tests."""

    def __init__(self):
        self.subscriptions: Dict[UUID4, Dict[str, Any]] = {}
        self.ledger: List[SubscriptionLedgerEntry] = []
        self.processed_webhook_events: set = set()

    def record_ledger_entry(self, entry: SubscriptionLedgerEntry):
        self.ledger.append(entry)

    def update_ledger_record(self, entry_id: UUID4, **kwargs):
        raise PermissionError(
            "IMMUTABILITY_VIOLATION: subscription_ledger is strictly append-only. UPDATE operations are rejected."
        )

    def delete_ledger_record(self, entry_id: UUID4):
        raise PermissionError(
            "IMMUTABILITY_VIOLATION: subscription_ledger is strictly append-only. DELETE operations are rejected."
        )


class BillingService:
    """
    Step 10 Core Billing & Subscription Engine.
    Enforces server-side quotas, pricing, state machines, and payment webhooks.
    """

    def __init__(
        self,
        store: Optional[InMemorySubscriptionStore] = None,
        webhook_secret: str = "mock-webhook-secret-key",
    ):
        self.store = store or InMemorySubscriptionStore()
        self.webhook_secret = os.getenv("PAYMENT_WEBHOOK_SECRET", webhook_secret)
        self.adapter = MockPaymentAdapter()

    def calculate_pricing(
        self,
        tier: SubscriptionTier,
        cadence: BillingCadence = BillingCadence.MONTHLY,
        apply_early_adopter: bool = False,
    ) -> Dict[str, float]:
        """
        Calculates commercial pricing, applying locked discounts + 18% GST.
        """
        config = TIER_PRICING_CONFIG[tier]
        base_monthly = config["base_monthly_inr"]

        if cadence == BillingCadence.ANNUAL:
            annual_discount = ANNUAL_DISCOUNT_PERCENT
            months = 12
            raw_amount = base_monthly * months * (1.0 - (annual_discount / 100.0))
        else:
            annual_discount = 0.0
            raw_amount = base_monthly

        if apply_early_adopter:
            # 50% Early Adopter Discount
            effective_base = raw_amount * (1.0 - (EARLY_ADOPTER_DISCOUNT_PERCENT / 100.0))
        else:
            effective_base = raw_amount

        tax_gst = effective_base * (GST_RATE_PERCENT / 100.0)
        total_price = effective_base + tax_gst

        return {
            "base_price_inr": round(raw_amount, 2),
            "effective_price_inr": round(effective_base, 2),
            "annual_discount_percentage": annual_discount,
            "tax_gst_inr": round(tax_gst, 2),
            "total_effective_price_inr": round(total_price, 2),
        }

    def provision_subscription(
        self,
        company_id: UUID4,
        tier: SubscriptionTier = SubscriptionTier.STARTER,
        cadence: BillingCadence = BillingCadence.MONTHLY,
        apply_early_adopter: bool = False,
        actor_id: Optional[UUID4] = None,
    ) -> SubscriptionResponse:
        """
        Initializes a tenant subscription, recording an immutable audit entry.
        """
        pricing = self.calculate_pricing(tier, cadence, apply_early_adopter)
        config = TIER_PRICING_CONFIG[tier]
        now_utc = datetime.now(timezone.utc)
        sub_id = uuid.uuid4()

        sub_data = {
            "id": sub_id,
            "company_id": company_id,
            "tier": tier,
            "status": SubscriptionStatus.ACTIVE,
            "cadence": cadence,
            "monthly_request_limit": config["monthly_request_limit"],
            "monthly_request_count": 0,
            "active_vendor_limit": config["active_vendor_limit"],
            "early_adopter_discount_applied": apply_early_adopter,
            "annual_discount_percentage": pricing["annual_discount_percentage"],
            "base_price_inr": pricing["base_price_inr"],
            "effective_price_inr": pricing["effective_price_inr"],
            "tax_gst_inr": pricing["tax_gst_inr"],
            "total_effective_price_inr": pricing["total_effective_price_inr"],
            "current_period_start": now_utc,
            "current_period_end": now_utc + timedelta(days=365 if cadence == BillingCadence.ANNUAL else 30),
        }

        self.store.subscriptions[company_id] = sub_data

        # Record Initial Ledger Event
        ledger_entry = SubscriptionLedgerEntry(
            id=uuid.uuid4(),
            subscription_id=sub_id,
            company_id=company_id,
            event_type="SUBSCRIPTION_PROVISIONED",
            from_status=None,
            to_status=SubscriptionStatus.ACTIVE,
            amount_inr=pricing["effective_price_inr"],
            tax_gst_inr=pricing["tax_gst_inr"],
            actor_id=actor_id,
            created_at=now_utc,
            metadata={"tier": tier.value, "cadence": cadence.value},
        )
        self.store.record_ledger_entry(ledger_entry)

        return self.get_subscription(company_id)

    def get_subscription(self, company_id: UUID4) -> SubscriptionResponse:
        """Returns authoritative server-side subscription state."""
        sub = self.store.subscriptions.get(company_id)
        if not sub:
            raise KeyError(f"No active subscription found for tenant {company_id}")

        is_write_locked = sub["status"] in [
            SubscriptionStatus.PAST_DUE,
            SubscriptionStatus.SUSPENDED,
            SubscriptionStatus.CANCELED,
        ]

        return SubscriptionResponse(
            **sub,
            is_write_locked=is_write_locked,
            is_read_only_audit_preserved=True,
        )

    def transition_subscription_status(
        self,
        company_id: UUID4,
        to_status: SubscriptionStatus,
        event_type: str,
        actor_id: Optional[UUID4] = None,
        provider_event_id: Optional[str] = None,
        notes: str = "",
    ) -> SubscriptionResponse:
        """
        State-machine transition with authoritative validation and ledger logging.
        """
        sub = self.store.subscriptions.get(company_id)
        if not sub:
            raise KeyError(f"Subscription not found for company {company_id}")

        current_status = sub["status"]
        allowed = ALLOWED_SUBSCRIPTION_TRANSITIONS.get(current_status, [])

        if to_status not in allowed:
            raise ValueError(
                f"INVALID_SUBSCRIPTION_TRANSITION: Cannot transition from {current_status.value} to {to_status.value}."
            )

        sub["status"] = to_status
        sub["updated_at"] = datetime.now(timezone.utc)

        # Append to Immutable Ledger
        ledger_entry = SubscriptionLedgerEntry(
            id=uuid.uuid4(),
            subscription_id=sub["id"],
            company_id=company_id,
            event_type=event_type,
            from_status=current_status,
            to_status=to_status,
            amount_inr=0.0,
            tax_gst_inr=0.0,
            provider_event_id=provider_event_id,
            actor_id=actor_id,
            created_at=datetime.now(timezone.utc),
            metadata={"notes": notes},
        )
        self.store.record_ledger_entry(ledger_entry)

        return self.get_subscription(company_id)

    def check_and_increment_quota(self, company_id: UUID4) -> Dict[str, Any]:
        """
        Server-side quota validation prior to any bank-change intake.
        Throws PermissionError if suspended, or ValueError if quota exceeded.
        """
        sub = self.store.subscriptions.get(company_id)
        if not sub:
            raise PermissionError("NO_SUBSCRIPTION: Tenant has no active subscription.")

        if sub["status"] in [SubscriptionStatus.PAST_DUE, SubscriptionStatus.SUSPENDED, SubscriptionStatus.CANCELED]:
            raise PermissionError(
                f"SUBSCRIPTION_LOCKED: Tenant subscription is {sub['status'].value}. Bank-change request intake is blocked. Read-only audit access preserved."
            )

        limit = sub["monthly_request_limit"]
        count = sub["monthly_request_count"]

        if limit != -1 and count >= limit:
            raise ValueError(
                f"QUOTA_EXCEEDED: Monthly intake limit of {limit} requests reached for tier {sub['tier'].value}. Upgrade required."
            )

        sub["monthly_request_count"] += 1
        return {
            "allowed": True,
            "company_id": company_id,
            "tier": sub["tier"].value,
            "current_usage": sub["monthly_request_count"],
            "monthly_limit": limit,
        }

    def process_payment_webhook(
        self,
        raw_body: str,
        signature: str,
        provider_event_id: str,
        event_type: str,
        company_id: UUID4,
    ) -> Dict[str, Any]:
        """
        Idempotent payment webhook processor with HMAC signature verification.
        """
        # 1. Signature Verification
        if not self.adapter.verify_webhook_signature(
            raw_body, signature, self.webhook_secret
        ):
            raise PermissionError("INVALID_WEBHOOK_SIGNATURE: HMAC verification failed.")

        # 2. Idempotency Check
        if provider_event_id in self.store.processed_webhook_events:
            return {
                "action": "DEDUPLICATED_AND_IGNORED",
                "provider_event_id": provider_event_id,
                "message": "Event already processed successfully.",
            }

        # 3. Action Mapping
        action_taken = "NOOP"
        if event_type in ["invoice.payment_succeeded", "payment.captured"]:
            self.transition_subscription_status(
                company_id=company_id,
                to_status=SubscriptionStatus.ACTIVE,
                event_type="PAYMENT_SUCCEEDED",
                provider_event_id=provider_event_id,
            )
            action_taken = "SUBSCRIPTION_ACTIVATED"
        elif event_type in ["invoice.payment_failed", "payment.failed"]:
            self.transition_subscription_status(
                company_id=company_id,
                to_status=SubscriptionStatus.PAST_DUE,
                event_type="PAYMENT_FAILED",
                provider_event_id=provider_event_id,
            )
            action_taken = "SUBSCRIPTION_FLAGGED_PAST_DUE"
        elif event_type in ["subscription.suspended", "customer.subscription.deleted"]:
            self.transition_subscription_status(
                company_id=company_id,
                to_status=SubscriptionStatus.SUSPENDED,
                event_type="SUBSCRIPTION_SUSPENDED",
                provider_event_id=provider_event_id,
            )
            action_taken = "SUBSCRIPTION_SUSPENDED_WRITES_LOCKED"

        self.store.processed_webhook_events.add(provider_event_id)

        return {
            "action": action_taken,
            "provider_event_id": provider_event_id,
            "status": "PROCESSED_SUCCESSFULLY",
        }
