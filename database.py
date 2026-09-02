import os
from dotenv import load_dotenv
from typing import Optional

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip().strip('"').strip("'")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "").strip().strip('"').strip("'")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip().strip('"').strip("'")

# Base client with ANON KEY (for RLS-enforced queries)
supabase_base = None
if SUPABASE_URL and SUPABASE_ANON_KEY:
    try:
        from supabase import create_client
        supabase_base = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        print("[INFO] Supabase Base Client Initialized Successfully ✅")
    except Exception as e:
        print(f"[INFO] Supabase Base Client Note: {e}")

# Service role client ONLY for system tasks
supabase_service = None
if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    try:
        from supabase import create_client
        supabase_service = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
        print("[INFO] Supabase Service Client Initialized Successfully ✅")
    except Exception as e:
        print(f"[INFO] Supabase Service Client Note: {e}")


def get_rls_enforced_client(user_jwt_token: str):
    """
    Returns a PostgREST client that injects the user's JWT into the request headers.
    This forces PostgreSQL to evaluate RLS policies using auth.uid() and auth.jwt()->>'company_id'.
    PRD v1.1 Section 16: Genuine Multi-Tenancy Isolation at DB Level.
    """
    if not supabase_base:
        raise ValueError("CRITICAL: Supabase URL and ANON KEY are required or initializing.")
    if not user_jwt_token:
        raise ValueError("JWT token is required for RLS enforcement")

    return supabase_base.postgrest.auth(user_jwt_token)


def get_system_db_for_audit(operation_name: str, authorized_actor_id: str):
    """
    STRICTLY ISOLATED: Only for system tasks. 
    Requires explicit actor logging to prevent silent abuse.
    """
    if not supabase_service:
        raise RuntimeError("Service role key not configured. System operation blocked.")

    print(
        f"[SECURITY AUDIT] Service Role Key accessed for operation: {operation_name} by actor: {authorized_actor_id}"
    )
    return supabase_service
