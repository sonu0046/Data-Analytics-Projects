# app/routers/ingestion.py - Ingestion API Integration with Authenticated RPC (PRD v1.1 Compliant)
import hashlib
import logging
from typing import Optional, Literal
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.security import get_current_user_and_company, get_secure_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/ingestion", tags=["Ingestion"])


# --- Schemas ---
class ChangeRequestIntake(BaseModel):
    vendor_id: str = Field(..., description="Target vendor baseline UUID")
    request_source: Literal["PDF_UPLOAD", "IMAP_FETCH"] = Field(
        ..., description="Source of the bank change request"
    )
    file_content_base64: Optional[str] = Field(
        default=None, description="Base64 encoded PDF payload (for PDF_UPLOAD)"
    )
    imap_message_id: Optional[str] = Field(
        default=None,
        description="Unique IMAP email message ID (for IMAP_FETCH)",
    )
    new_account_holder_name: Optional[str] = Field(
        default=None, description="Extracted account holder name"
    )
    new_account_number: Optional[str] = Field(
        default=None, description="Extracted new account number"
    )
    new_ifsc_code: Optional[str] = Field(
        default=None, description="Extracted new IFSC code"
    )


def generate_file_hash(content: str) -> str:
    """Generates SHA-256 hash for idempotency checking."""
    return hashlib.sha256(content.encode()).hexdigest()


@router.post("/intake", status_code=status.HTTP_201_CREATED)
async def intake_change_request(
    intake_data: ChangeRequestIntake,
    request: Request,
    user_context: dict = Depends(get_current_user_and_company),
):
    """
    Intake request using AUTHENTICATED RPC call.
    PRD v1.1 Sections: 22 (Idempotency), 14 (State Machine), 24 (Fail-Secure).
    """
    company_id = user_context["company_id"]
    user_id = user_context["user_id"]
    client_ip = request.client.host if request.client else None

    # Generate file hash
    if intake_data.request_source == "PDF_UPLOAD":
        if not intake_data.file_content_base64:
            raise HTTPException(
                status_code=400, detail="file_content_base64 required"
            )
        file_hash = generate_file_hash(intake_data.file_content_base64)
    else:  # IMAP_FETCH
        if not intake_data.imap_message_id:
            raise HTTPException(
                status_code=400, detail="imap_message_id required"
            )
        file_hash = generate_file_hash(intake_data.imap_message_id)

    # CORRECT: Use authenticated client (NOT supabase_base)
    # This preserves JWT context for auth.uid() in SQL function
    db = get_secure_db(user_context)

    try:
        # RPC call with authenticated client
        result = db.rpc(
            "intake_change_request_with_audit",
            {
                "p_company_id": str(company_id),
                "p_vendor_id": str(intake_data.vendor_id),
                "p_request_source": intake_data.request_source,
                "p_file_hash": file_hash,
                "p_imap_message_id": intake_data.imap_message_id,
                "p_new_account_holder_name": intake_data.new_account_holder_name,
                "p_new_account_number_hashed": (
                    hashlib.sha256(
                        intake_data.new_account_number.encode()
                    ).hexdigest()[:32]
                    if intake_data.new_account_number
                    else None
                ),
                "p_new_ifsc_code": intake_data.new_ifsc_code,
                "p_requested_by": str(user_id),
                "p_actor_id": str(user_id),
                "p_action": "REQUEST_INTAKED",
                "p_details": {
                    "vendor_id": str(intake_data.vendor_id),
                    "request_source": intake_data.request_source,
                    "file_hash": file_hash[:16] + "...",
                    "status": "PENDING_REVIEW",
                },
                "p_ip_address": client_ip,
            },
        ).execute()

        if not result.data:
            raise RuntimeError("RPC function returned no data")

        return {
            "message": "Request intaked successfully",
            "request_id": result.data["request_id"],
            "status": result.data["status"],
            "file_hash": file_hash,
        }

    except Exception as e:
        error_msg = str(e)

        # Handle unique violation (duplicate)
        if "duplicate" in error_msg.lower() or "409" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Duplicate request detected. Idempotency enforced.",
            )

        # Handle authentication failure
        if "Authentication required" in error_msg:
            logger.critical("JWT_CONTEXT_LOST: RPC call missing authentication")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication context lost. Please re-login.",
            )

        # All other errors → Fail-Closed → MANUAL_SYS_OVERRIDE
        logger.critical(
            f"ATOMIC_INTAKE_FAILED | company_id={company_id} | error={error_msg}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Request intake failed. System routed to MANUAL_SYS_OVERRIDE.",
        )
