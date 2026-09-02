# app/services/risk_engine.py - Deterministic Risk Scoring Logic (PRD v1.1 Compliant)
from typing import Dict, Any
from datetime import datetime, timezone
from app.models.risk_engine import RiskEngineInput, RiskEngineOutput, RiskLevelEnum

# --- Configuration: Rule Weights & Thresholds (PRD Sec 10) ---
RULE_WEIGHTS = {
    "is_spf_dkim_dmarc_failed": 100,
    "is_domain_mismatch": 40,
    "is_bank_account_changed": 25,
    "is_ifsc_changed": 15,
    "is_account_holder_changed": 20,
    "is_ghost_vendor_match": 40,
    "is_trusted_phone_mismatch": 30,
    "is_urgent_language": 20,
    "is_velocity_anomaly": 50,
}

RISK_THRESHOLDS = {
    "CRITICAL": 70,
    "HIGH": 40,
    "MEDIUM": 20,
    "LOW": 0,
}

RULE_SET_VERSION = "v1.1-mvp-001"


def calculate_deterministic_risk(input_data: RiskEngineInput) -> Dict[str, Any]:
    """
    Deterministic Risk Scoring Engine.
    PRD v1.1 Section 10: Explainable, reproducible, rule-based scoring.
    PRD v1.1 Section 9: CRITICAL_SPOOF_BLOCK for auth failures.
    """
    score = 0
    triggered_rules = []
    evidence = []
    is_blocked = False
    block_reason = ""
    level = RiskLevelEnum.LOW

    # 1. CRITICAL_SPOOF_BLOCK Check (PRD Sec 9)
    if input_data.is_spf_dkim_dmarc_failed:
        is_blocked = True
        block_reason = (
            "CRITICAL_SPOOF_BLOCK: Email authentication (SPF/DKIM/DMARC) failed."
        )
        score = 100
        level = RiskLevelEnum.CRITICAL
        triggered_rules.append("is_spf_dkim_dmarc_failed")
        evidence.append(
            "Mandatory authentication failure. Automated AI parsing blocked."
        )
    else:
        # 2. Deterministic Scoring (PRD Sec 10)
        for field, weight in RULE_WEIGHTS.items():
            if field == "is_spf_dkim_dmarc_failed":
                continue

            if getattr(input_data, field, False):
                score += weight
                triggered_rules.append(field)
                evidence.append(
                    f"Signal '{field}' detected. Added {weight} points."
                )

        # 3. Determine Risk Level based on Thresholds
        if score >= RISK_THRESHOLDS["CRITICAL"]:
            level = RiskLevelEnum.CRITICAL
        elif score >= RISK_THRESHOLDS["HIGH"]:
            level = RiskLevelEnum.HIGH
        elif score >= RISK_THRESHOLDS["MEDIUM"]:
            level = RiskLevelEnum.MEDIUM
        else:
            level = RiskLevelEnum.LOW

    # --- CRITICAL FIX: Cap score at 100 (PRD Sec 10 & Pydantic constraint) ---
    score = min(score, 100)

    return {
        "score": score,
        "level": level,
        "triggered_rules": triggered_rules,
        "evidence": evidence,
        "is_blocked": is_blocked,
        "block_reason": block_reason,
        "rule_set_version": RULE_SET_VERSION,
        "calculated_at": datetime.now(timezone.utc),
    }
