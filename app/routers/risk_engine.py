# app/routers/risk_engine.py - Risk Engine API Integration (PRD v1.1 Compliant)
import logging
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.models.risk_engine import RiskEngineInput, RiskEngineOutput
from app.services.risk_engine import calculate_deterministic_risk
from app.security import get_current_user_and_company
from app.database import get_system_db_for_audit

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/risk-engine", tags=["Risk Engine"])


# --- Fail-Closed Audit Logger (PRD Sec 21 + 24 - Option A) ---
def _strict_audit_log(
    company_id: str,
    vendor_id: str,
    user_id: str,
    action: str,
    details: dict,
    client_ip: Optional[str] = None,
):
    """
    Writes audit log using Service Role Client.
    FAIL-CLOSED: If DB is down, raises RuntimeError to force MANUAL_SYS_OVERRIDE.
    """
    log_payload = {
        "company_id": str(company_id),
        "record_id": str(vendor_id),
        "table_name": "change_requests",
        "action": action,
        "actor_id": str(user_id) if user_id else None,
        "details": details,
        "ip_address": client_ip,
        "previous_row_hash": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        system_db = get_system_db_for_audit(
            operation_name="RISK_ENGINE_AUDIT", authorized_actor_id=str(user_id)
        )
        system_db.table("audit_logs").insert(log_payload).execute()
    except Exception as db_error:
        # CRITICAL: Audit failure = Security Control Failure (SOC 2 / ISO 27001)
        logger.critical(
            f"AUDIT_LOG_DB_FAILURE: Auto-progression halted. "
            f"company_id={company_id} | vendor_id={vendor_id} | error={str(db_error)}"
        )
        raise RuntimeError("Audit system unavailable. Cannot proceed securely.")


@router.post(
    "/calculate",
    response_model=RiskEngineOutput,
    status_code=status.HTTP_200_OK,
    summary="Calculate deterministic risk score for a bank-change request",
)
async def calculate_risk_endpoint(
    input_data: RiskEngineInput,
    request: Request,
    user_context: dict = Depends(get_current_user_and_company),
):
    """
    Calculate deterministic risk score.
    PRD v1.1 Sections: 10 (Scoring), 16 (Multi-Tenancy), 21 (Audit), 24 (Fail-Secure).
    """
    company_id = user_context["company_id"]
    user_id = user_context["user_id"]
    client_ip = request.client.host if request.client else None

    # 1. Multi-Tenancy Isolation Check (PRD Sec 16)
    if str(input_data.company_id) != str(company_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Company ID mismatch. Multi-tenancy violation detected.",
        )

    # 2. Risk Calculation & Fail-Closed Audit (PRD Sec 10, 21, 24)
    try:
        # Calculate Risk
        risk_result = calculate_deterministic_risk(input_data)

        # Strict Audit Logging (Fails closed if DB is down)
        _strict_audit_log(
            company_id=company_id,
            vendor_id=str(input_data.vendor_id),
            user_id=user_id,
            action="RISK_CALCULATED",
            details={
                "risk_score": risk_result.get("score"),
                "risk_level": risk_result.get("level"),
                "triggered_rules": risk_result.get("triggered_rules", []),
                "is_blocked": risk_result.get("is_blocked", False),
            },
            client_ip=client_ip,
        )

        return RiskEngineOutput(**risk_result)

    except RuntimeError as audit_err:
        # MANUAL_SYS_OVERRIDE due to Audit Failure (Option A)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Audit system failure. Request routed to MANUAL_SYS_OVERRIDE.",
        )
    except Exception as e:
        # MANUAL_SYS_OVERRIDE due to Risk Engine or other failure
        logger.critical(
            f"RISK_ENGINE_FAILURE: company_id={company_id} | error={str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Risk engine unavailable. Request routed to MANUAL_SYS_OVERRIDE.",
        )
