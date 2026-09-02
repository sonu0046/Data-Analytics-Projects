import re
from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

try:
    from app.database import supabase_base, get_rls_enforced_client
except ImportError:
    from database import supabase_base, get_rls_enforced_client

security = HTTPBearer()


async def get_current_user_and_company(
    credentials: HTTPAuthorizationCredentials = Security(security),
):
    try:
        token = credentials.credentials
        if not supabase_base:
            raise HTTPException(
                status_code=500, detail="Database client not configured."
            )

        user_response = supabase_base.auth.get_user(token)
        user = user_response.user

        company_id = user.user_metadata.get("company_id")

        if not company_id:
            raise HTTPException(
                status_code=403,
                detail="Multi-tenancy violation: User not assigned to a company.",
            )

        aal = getattr(user, "aal", None) or user.user_metadata.get(
            "aal", "aal1"
        )

        return {
            "user_id": user.id,
            "company_id": company_id,
            "jwt_token": token,
            "role": user.user_metadata.get("role", "reviewer"),
            "aal": aal,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=401, detail=f"Authentication failed: {str(e)}"
        )


async def require_step_up_mfa(
    user_context: dict = Depends(get_current_user_and_company),
):
    if user_context["role"] not in ["admin", "checker", "finance_manager"]:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Checker role required.",
        )

    if user_context.get("aal") != "aal2":
        raise HTTPException(
            status_code=403,
            detail="Step-up MFA required. Please complete MFA challenge.",
        )

    return user_context


def mask_account_number(account_number: str) -> str:
    if not account_number:
        return account_number

    clean_number = re.sub(r"[\s\-]", "", str(account_number))

    return re.sub(
        r"\b(\d{4})\d{4,10}(\d{4})\b", r"\g<1>XXXX\g<2>", clean_number
    )


def mask_pii_for_llm(text: str) -> str:
    if not text:
        return text

    # Bank account
    text = re.sub(
        r"\b(\d{4})[\s\-]?(\d{4,10})[\s\-]?(\d{4})\b",
        r"\g<1>XXXX\g<3>",
        text,
    )

    # IFSC
    text = re.sub(
        r"\b([A-Z]{4})0[A-Z0-9]{6}\b",
        r"\g<1>0XXXXXX",
        text,
    )

    # PAN
    text = re.sub(
        r"\b([A-Z]{5})\d{4}([A-Z])\b",
        r"\g<1>XXXX\g<2>",
        text,
    )

    # GSTIN
    text = re.sub(
        r"\b(\d{2})([A-Z]{5})\d{4}([A-Z])(\d)([A-Z0-9])\b",
        r"\g<1>\g<2>XXXX\g<3>\g<4>\g<5>",
        text,
    )

    return text


def get_secure_db(user_context: dict):
    return get_rls_enforced_client(user_context["jwt_token"])
