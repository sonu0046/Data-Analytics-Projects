# app/models/risk_engine.py - Base Input/Output Validation (PRD v1.1 Compliant)

from typing import List
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field, UUID4


class RiskLevelEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskEngineInput(BaseModel):
    """
    Input schema for the Deterministic Risk Engine.
    PRD v1.1 Sections 8, 9, 10:
    All signals must be explicitly passed as boolean flags.
    Scoring weights are handled in the engine logic,
    NOT in this schema.
    """

    # --- Tenant & Vendor Identification (PRD Sec 16) ---
    company_id: UUID4 = Field(
        ...,
        description="Unique tenant identification identifier"
    )

    vendor_id: UUID4 = Field(
        ...,
        description="Target vendor baseline ID"
    )

    # --- Email & Identity Security (PRD Sec 9) ---
    is_spf_dkim_dmarc_failed: bool = Field(
        default=False,
        description="CRITICAL: Email authentication failure triggers CRITICAL_SPOOF_BLOCK"
    )

    is_domain_mismatch: bool = Field(
        default=False,
        description="Sender domain does not match trusted vendor domain"
    )

    # --- Core Bank Detail Changes (PRD Sec 6 & 8) ---
    is_bank_account_changed: bool = Field(
        default=False,
        description="New bank account number differs from trusted baseline"
    )

    is_ifsc_changed: bool = Field(
        default=False,
        description="New IFSC code differs from trusted baseline"
    )

    is_account_holder_changed: bool = Field(
        default=False,
        description="Account holder name differs from trusted baseline"
    )

    # --- Vendor & Contact Anomalies (PRD Sec 6 & 8) ---
    is_ghost_vendor_match: bool = Field(
        default=False,
        description="Fuzzy match detected with existing vendor (Ghost Vendor)"
    )

    is_trusted_phone_mismatch: bool = Field(
        default=False,
        description="Contact phone number altered in request"
    )

    # --- Context & Velocity (PRD Sec 8) ---
    is_urgent_language: bool = Field(
        default=False,
        description="NLP detected urgency/social engineering in text"
    )

    is_velocity_anomaly: bool = Field(
        default=False,
        description="Multiple requests from same IP/domain/vendor within 24h (Time-bomb)"
    )


class RiskEngineOutput(BaseModel):
    """
    Pydantic Output schema for the Deterministic Risk Engine.
    PRD v1.1 Section 10: Explainable, versioned, reproducible output.
    """

    score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Deterministic risk score (0-100)"
    )

    level: RiskLevelEnum = Field(
        ...,
        description="Risk level classification"
    )

    triggered_rules: List[str] = Field(
        default_factory=list,
        description="List of triggered risk rules"
    )

    evidence: List[str] = Field(
        default_factory=list,
        description="Human-readable evidence for each triggered rule"
    )

    is_blocked: bool = Field(
        default=False,
        description="Whether request is blocked (CRITICAL_SPOOF_BLOCK)"
    )

    block_reason: str = Field(
        default="",
        description="Reason for block if is_blocked=True"
    )

    rule_set_version: str = Field(
        default="v1.1-mvp-001",
        description="Version of scoring rules used"
    )

    calculated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of calculation"
    )

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
