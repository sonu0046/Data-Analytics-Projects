# app/routers/checker_approval.py
# Step 5 Part 3 - Checker Approval with Step-Up MFA
# PRD v1.1 Sections 13, 14, 15, 24

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.security import get_current_user_and_company, get_secure_db

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/review",
    tags=["Checker Approval"],
)


class CheckerApprovalRequest(BaseModel):
    """Checker decision with mandatory Step-Up MFA proof."""

    request_id: str = Field(..., description="Change request UUID")

    mfa_verification_proof: str = Field(
        ...,
        min_length=1,
        description="Step-Up MFA verification proof/session reference",
    )

    approval_decision: str = Field(
        ...,
        pattern="^(APPROVE|REJECT)$",
        description="Independent checker decision",
    )

    checker_notes: str = Field(
        default="",
        description="Checker review notes",
    )


@router.post(
    "/checker-approve",
    status_code=status.HTTP_200_OK,
    summary="Checker approval with Step-Up MFA",
)
async def checker_approve_request(
    approval_data: CheckerApprovalRequest,
    request: Request,
    user_context: dict = Depends(get_current_user_and_company),
):
    """
    Independent Checker approval.

    Security requirements:
    - Authenticated user
    - Admin / Checker / Finance Manager role
    - Step-Up MFA / AAL2
    - Maker != Checker
    - Request must be PENDING_VERIFICATION
    - Approval sets effective_date >= 48 hours
    - Checker identity stored in approved_by
    - Atomic state + audit transaction
    - Fail-closed on errors
    """

    company_id = user_context["company_id"]
    user_id = user_context["user_id"]
    client_ip = request.client.host if request.client else None

    # Role is also enforced inside the SQL RPC.
    if user_context.get("role") not in (
        "admin",
        "checker",
        "finance_manager",
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Checker approval authority required.",
        )

    if not approval_data.mfa_verification_proof.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Step-Up MFA verification proof is required.",
        )

    # Authenticated client preserves JWT context for auth.uid()/auth.jwt()
    db = get_secure_db(user_context)

    try:
        result = db.rpc(
            "checker_approve_request_with_mfa",
            {
                "p_request_id": str(approval_data.request_id),
                "p_company_id": str(company_id),
                "p_actor_id": str(user_id),
                "p_mfa_verification_proof": approval_data.mfa_verification_proof.strip(),
                "p_decision": approval_data.approval_decision,
                "p_checker_notes": approval_data.checker_notes.strip(),
                "p_ip_address": client_ip,
            },
        ).execute()

        if not result.data:
            raise RuntimeError("Checker approval RPC returned no data.")

        return {
            "message": "Checker decision recorded successfully.",
            "request_id": result.data["request_id"],
            "status": result.data["status"],
            "decision": result.data["decision"],
            "effective_date": result.data.get("effective_date"),
        }

    except Exception as e:
        error_msg = str(e)

        if "MFA_REQUIRED" in error_msg or "aal2" in error_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Step-Up MFA (AAL2) is required.",
            )

        if "MAKER_CHECKER_SEPARATION" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Maker and Checker must be different users.",
            )

        if "STATE_INVALID" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Invalid request state. "
                    "Checker approval requires PENDING_VERIFICATION."
                ),
            )

        logger.critical(
            "CHECKER_APPROVAL_FAILED | "
            f"company_id={company_id} | "
            f"request_id={approval_data.request_id} | "
            f"error={error_msg} | "
            "MANUAL_SYS_OVERRIDE_TRIGGERED"
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Checker approval failed. "
                "Request routed to MANUAL_SYS_OVERRIDE."
            ),
        )
