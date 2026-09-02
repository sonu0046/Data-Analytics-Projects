# app/routers/maker_verification.py - Maker Verification Router (PRD v1.1 Compliant)
import logging

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    status,
)
from pydantic import BaseModel, Field

from app.security import (
    get_current_user_and_company,
    get_secure_db,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/review",
    tags=["Maker Verification"],
)


class MakerVerificationInput(BaseModel):
    request_id: str = Field(
        ...,
        description="Change request UUID",
    )

    is_called_trusted_phone: bool = Field(
        ...,
        description="Must be true after trusted-phone call",
    )

    vendor_representative_name: str = Field(
        ...,
        min_length=1,
        max_length=255,
    )

    verification_transcript: str = Field(
        ...,
        min_length=1,
    )

    verification_proof: str = Field(
        ...,
        min_length=1,
        description="OTP verification token or verified call session ID",
    )


@router.post(
    "/maker-verify",
    status_code=status.HTTP_200_OK,
)
async def maker_verify(
    input_data: MakerVerificationInput,
    request: Request,
    user_context: dict = Depends(get_current_user_and_company),
):
    """
    Step 5 Part 2.

    Atomic flow:

    PENDING_REVIEW
        ->
    trusted-phone Maker verification
        ->
    PENDING_VERIFICATION
        ->
    Step 5 Part 3: Checker + Step-up MFA
    """

    company_id = user_context["company_id"]
    user_id = user_context["user_id"]

    client_ip = request.client.host if request.client else None

    # Mandatory boolean gate
    if not input_data.is_called_trusted_phone:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=("Trusted-phone verification is mandatory."),
        )

    # Mandatory evidence
    if not input_data.verification_proof.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification proof is required.",
        )

    if not input_data.vendor_representative_name.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Vendor representative name is required.",
        )

    if not input_data.verification_transcript.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification transcript is required.",
        )

    db = get_secure_db(user_context)

    try:
        # IMPORTANT:
        # No direct change_requests UPDATE here.
        # SQL RPC performs UPDATE + AUDIT atomically.
        result = db.rpc(
            "maker_verify_request_with_audit",
            {
                "p_request_id": str(input_data.request_id),
                "p_company_id": str(company_id),
                "p_actor_id": str(user_id),
                "p_vendor_rep_name": input_data.vendor_representative_name.strip(),
                "p_transcript": input_data.verification_transcript.strip(),
                "p_verification_proof": input_data.verification_proof.strip(),
                "p_ip_address": client_ip,
            },
        ).execute()

        if not result.data:
            raise RuntimeError("Maker verification RPC returned no data.")

        return {
            "message": "Maker verification completed successfully.",
            "request_id": result.data["request_id"],
            "status": result.data["status"],
            "next_step": "CHECKER_STEP_UP_MFA",
        }

    except Exception as e:
        error_msg = str(e)

        logger.critical(
            "MAKER_VERIFICATION_FAILED | "
            f"company_id={company_id} | "
            f"request_id={input_data.request_id} | "
            f"error={error_msg}"
        )

        if "Invalid state transition" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=error_msg,
            )

        if (
            "Authentication" in error_msg
            or "authorization" in error_msg.lower()
            or "Actor ID mismatch" in error_msg
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Maker verification authorization failed.",
            )

        # Fail closed
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Maker verification failed. "
                "Request routed to MANUAL_SYS_OVERRIDE."
            ),
        )
