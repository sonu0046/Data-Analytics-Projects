import os
from supabase import create_client, Client
from dotenv import load_dotenv
from typing import Optional

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

if not SUPABASE_URL or not SUPABASE_ANON_KEY:
    raise ValueError("CRITICAL: Supabase URL and ANON KEY are required.")

# Base client with ANON KEY (for RLS-enforced queries)
supabase_base: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# Service role client ONLY for system tasks
supabase_service: Optional[Client] = None
if SUPABASE_SERVICE_ROLE_KEY:
    supabase_service = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

def get_rls_enforced_client(user_jwt_token: str):
    """
    CRITICAL FIX: This returns a PostgREST client that injects the user's JWT 
    into the request headers. This forces PostgreSQL to evaluate RLS policies 
    using auth.uid() and auth.jwt()->>'company_id'.
    
    PRD v1.1 Section 16: Genuine Multi-Tenancy Isolation at DB Level.
    """
    if not user_jwt_token:
        raise ValueError("JWT token is required for RLS enforcement")
    
    # This is the magic line that enforces DB-level RLS
    return supabase_base.postgrest.auth(user_jwt_token)

def get_system_db_for_audit(operation_name: str, authorized_actor_id: str):
    """
    STRICTLY ISOLATED: Only for system tasks. 
    Requires explicit actor logging to prevent silent abuse.
    """
    if not supabase_service:
        raise RuntimeError("Service role key not configured. System operation blocked.")
    
    # In a real app, log this usage to an internal admin log
    print(f"[SECURITY AUDIT] Service Role Key accessed for operation: {operation_name} by actor: {authorized_actor_id}")
    
    return supabase_service
