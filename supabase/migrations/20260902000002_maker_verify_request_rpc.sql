-- =========================================================
-- VENDOR BANK-CHANGE FRAUD GUARDIAN
-- STEP 5 PART 2 — MAKER VERIFICATION & AUDIT (RPC)
-- PRD v1.1 Compliant
-- =========================================================

-- 1. Ensure verification columns exist on change_requests
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'change_requests' AND column_name = 'is_called_trusted_phone'
    ) THEN
        ALTER TABLE public.change_requests
        ADD COLUMN is_called_trusted_phone BOOLEAN DEFAULT FALSE,
        ADD COLUMN vendor_representative_name VARCHAR(255),
        ADD COLUMN verification_transcript TEXT,
        ADD COLUMN verified_by UUID,
        ADD COLUMN verified_at TIMESTAMP WITH TIME ZONE;
    END IF;
END $$;

-- 2. Create Atomic Maker Verify RPC Function
CREATE OR REPLACE FUNCTION public.maker_verify_request_with_audit(
    p_request_id UUID,
    p_company_id UUID,
    p_actor_id UUID,
    p_vendor_rep_name TEXT,
    p_transcript TEXT,
    p_verification_proof TEXT,
    p_ip_address TEXT
)
RETURNS JSON
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_caller_uid UUID;
    v_jwt_company_id TEXT;
    v_role TEXT;
    v_vendor_id UUID;
    v_status TEXT;
BEGIN

    -- 1. Authentication
    v_caller_uid := auth.uid();

    IF v_caller_uid IS NULL THEN
        RAISE EXCEPTION
            'Authentication required.';
    END IF;

    -- 2. Actor must equal authenticated caller
    IF p_actor_id != v_caller_uid THEN
        RAISE EXCEPTION
            'Actor ID mismatch.';
    END IF;

    -- 3. Reviewer / Maker authorization (support both user_metadata.role and custom claim)
    v_role := COALESCE(
        auth.jwt()->>'role',
        auth.jwt()->'user_metadata'->>'role',
        auth.jwt()->>'reviewer'
    );

    IF v_role IS NULL OR (v_role NOT IN ('reviewer', 'maker', 'admin', 'finance_manager', 'checker')) THEN
        RAISE EXCEPTION
            'Reviewer authorization required.';
    END IF;

    -- 4. Tenant validation
    v_jwt_company_id := COALESCE(
        auth.jwt()->>'company_id',
        auth.jwt()->'user_metadata'->>'company_id'
    );

    IF v_jwt_company_id IS NULL THEN
        RAISE EXCEPTION
            'Company ID missing from JWT.';
    END IF;

    IF p_company_id::text != v_jwt_company_id THEN
        RAISE EXCEPTION
            'Company ID mismatch.';
    END IF;

    -- 5. Mandatory verification evidence
    IF p_verification_proof IS NULL
       OR length(trim(p_verification_proof)) = 0 THEN
        RAISE EXCEPTION
            'Verification proof is mandatory.';
    END IF;

    IF p_vendor_rep_name IS NULL
       OR length(trim(p_vendor_rep_name)) = 0 THEN
        RAISE EXCEPTION
            'Vendor representative name is mandatory.';
    END IF;

    IF p_transcript IS NULL
       OR length(trim(p_transcript)) = 0 THEN
        RAISE EXCEPTION
            'Verification transcript is mandatory.';
    END IF;

    -- 6. Lock request to current tenant + expected state
    SELECT vendor_id, status
    INTO v_vendor_id, v_status
    FROM public.change_requests
    WHERE id = p_request_id
      AND company_id = p_company_id
    FOR UPDATE;

    IF v_vendor_id IS NULL THEN
        RAISE EXCEPTION
            'Change request not found.';
    END IF;

    IF v_status != 'PENDING_REVIEW' THEN
        RAISE EXCEPTION
            'Invalid state transition. Expected PENDING_REVIEW.';
    END IF;

    -- 7. Trusted contact must exist
    IF NOT EXISTS (
        SELECT 1
        FROM public.vendors
        WHERE id = v_vendor_id
          AND company_id = p_company_id
          AND is_deleted = FALSE
          AND trusted_phone_number_encrypted IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'Trusted phone is not configured for this vendor.';
    END IF;

    -- 8. ATOMIC STATE + VERIFICATION UPDATE
    UPDATE public.change_requests
    SET
        is_called_trusted_phone = TRUE,
        vendor_representative_name = trim(p_vendor_rep_name),
        verification_transcript = trim(p_transcript),
        verified_by = p_actor_id,
        verified_at = NOW(),
        status = 'PENDING_VERIFICATION'
    WHERE id = p_request_id
      AND company_id = p_company_id
      AND status = 'PENDING_REVIEW';

    -- 9. Audit in SAME transaction
    INSERT INTO public.audit_logs (
        company_id,
        record_id,
        table_name,
        action,
        actor_id,
        details,
        ip_address,
        created_at
    )
    VALUES (
        p_company_id,
        p_request_id,
        'change_requests',
        'MAKER_VERIFICATION_COMPLETED',
        p_actor_id,
        jsonb_build_object(
            'vendor_id', v_vendor_id,
            'verification_method',
                'TRUSTED_PHONE_OUT_OF_BAND',
            'is_called_trusted_phone', TRUE,
            'vendor_representative_name',
                trim(p_vendor_rep_name),
            'verification_transcript_present', TRUE,
            'verification_proof_present', TRUE,
            'previous_status', 'PENDING_REVIEW',
            'new_status', 'PENDING_VERIFICATION'
        ),
        p_ip_address::inet,
        NOW()
    );

    -- 10. Success
    RETURN json_build_object(
        'request_id', p_request_id,
        'status', 'PENDING_VERIFICATION'
    );

EXCEPTION
    WHEN OTHERS THEN
        -- PostgreSQL automatically rolls back
        -- both UPDATE + AUDIT INSERT.
        RAISE;
END;
$$;


-- Permissions
REVOKE EXECUTE ON FUNCTION public.maker_verify_request_with_audit(
    UUID, UUID, UUID, TEXT, TEXT, TEXT, TEXT
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.maker_verify_request_with_audit(
    UUID, UUID, UUID, TEXT, TEXT, TEXT, TEXT
) TO authenticated;
