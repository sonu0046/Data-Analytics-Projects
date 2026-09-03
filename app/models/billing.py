# app/models/billing.py - Step 10 SaaS Billing & Subscription Models (PRD v1.1)
from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field, UUID4, model_validator


class SubscriptionTier(str, Enum):
    STARTER = "STARTER"
    GROWTH = "GROWTH"
    ENTERPRISE = "ENTERPRISE"
    ENTERPRISE_PLUS = "ENTERPRISE_PLUS"


class SubscriptionStatus(str, Enum):
    TRIALING = "TRIALING"
    ACTIVE = "ACTIVE"
    PAST_DUE = "PAST_DUE"
    SUSPENDED = "SUSPENDED"
    CANCELED = "CANCELED"


class BillingCadence(str, Enum):
    MONTHLY = "MONTHLY"
    ANNUAL = "ANNUAL"


# --- Commercial Pricing Table (INR Base Rates) ---
TIER_PRICING_CONFIG = {
    SubscriptionTier.STARTER: {
        "base_monthly_inr": 49999.0,
        "monthly_request_limit": 50,
        "active_vendor_limit": 100,
        "support_sla": "Standard 24h",
    },
    SubscriptionTier.GROWTH: {
        "base_monthly_inr": 149999.0,
        "monthly_request_limit": 250,
        "active_vendor_limit": 500,
        "support_sla": "Priority 8h",
    },
    SubscriptionTier.ENTERPRISE: {
        "base_monthly_inr": 499999.0,
        "monthly_request_limit": 1000,
        "active_vendor_limit": 2500,
        "support_sla": "Dedicated 1h",
    },
    SubscriptionTier.ENTERPRISE_PLUS: {
        "base_monthly_inr": 999999.0,
        "monthly_request_limit": -1,  # Unlimited
        "active_vendor_limit": -1,   # Unlimited
        "support_sla": "24/7 Dedicated SRE & Incident Response",
    },
}

ANNUAL_DISCOUNT_PERCENT = 20.0  # 15-20% locked
EARLY_ADOPTER_DISCOUNT_PERCENT = 50.0  # 50% for first 6 months
GST_RATE_PERCENT = 18.0

# Authoritative Allowed State Transitions
ALLOWED_SUBSCRIPTION_TRANSITIONS: Dict[SubscriptionStatus, List[SubscriptionStatus]] = {
    SubscriptionStatus.TRIALING: [
        SubscriptionStatus.ACTIVE,
        SubscriptionStatus.CANCELED,
    ],
    SubscriptionStatus.ACTIVE: [
        SubscriptionStatus.PAST_DUE,
        SubscriptionStatus.SUSPENDED,
        SubscriptionStatus.CANCELED,
    ],
    SubscriptionStatus.PAST_DUE: [
        SubscriptionStatus.ACTIVE,
        SubscriptionStatus.SUSPENDED,
        SubscriptionStatus.CANCELED,
    ],
    SubscriptionStatus.SUSPENDED: [
        SubscriptionStatus.ACTIVE,
        SubscriptionStatus.CANCELED,
    ],
    SubscriptionStatus.CANCELED: [
        SubscriptionStatus.ACTIVE,  # Re-subscription
    ],
}


class SubscriptionResponse(BaseModel):
    id: UUID4
    company_id: UUID4
    tier: SubscriptionTier
    status: SubscriptionStatus
    cadence: BillingCadence
    monthly_request_limit: int
    monthly_request_count: int
    active_vendor_limit: int
    early_adopter_discount_applied: bool
    annual_discount_percentage: float
    base_price_inr: float
    effective_price_inr: float
    tax_gst_inr: float
    total_effective_price_inr: float
    current_period_start: datetime
    current_period_end: datetime
    is_write_locked: bool = Field(
        description="True if status is PAST_DUE, SUSPENDED, or CANCELED"
    )
    is_read_only_audit_preserved: bool = Field(
        default=True,
        description="Always True: Audit logs remain readable even under suspension",
    )


class SubscriptionLedgerEntry(BaseModel):
    id: UUID4
    subscription_id: UUID4
    company_id: UUID4
    event_type: str
    from_status: Optional[SubscriptionStatus] = None
    to_status: Optional[SubscriptionStatus] = None
    amount_inr: float = 0.0
    tax_gst_inr: float = 0.0
    provider_event_id: Optional[str] = None
    actor_id: Optional[UUID4] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class WebhookPayloadInput(BaseModel):
    provider: str = Field(..., description="RAZORPAY, STRIPE, or MOCK")
    event_type: str
    provider_event_id: str
    company_id: UUID4
    signature: str
    data: Dict[str, Any]
