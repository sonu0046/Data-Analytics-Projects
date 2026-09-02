-- =========================================================
-- VENDOR BANK-CHANGE FRAUD GUARDIAN
-- STEP 5 PART 3 — CHECKER APPROVAL WITH STEP-UP MFA (RPC)
-- PRD v1.1 Sections 13, 14, 15, 24
-- =========================================================

-- 1. Ensure approved_by and effective_date columns exist on change_requests
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'change_requests' AND column_name = 'approved_by'
    ) THEN
        ALTER TABLE public.change_requests
        ADD COLUMN approved_by UUID,
        ADD COLUMN effective_date TIMESTAMP WITH TIME ZONE;
    END IF;
END $$;

-- 2. Create Atomic Checker Approve RPC Function
CREATE OR REPLACE FUNCTION public.checker_approve_request_with_mfa(
    p_request_id UUID,
    p_company_id UUID,
    p_actor_id UUID,
    p_mfa_verification_proof TEXT,
    p_decision TEXT,
    p_checker_notes TEXT,
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
    v_jwt_role TEXT;
    v_jwt_aal TEXT;

    v_current_status TEXT;
    v_maker_id UUID;
    v_new_status request_status;
    v_effective_date TIMESTAMPTZ;
BEGIN

    -- =====================================================
    -- 1. Authentication
    -- =====================================================

    v_caller_uid := auth.uid();

    IF v_caller_uid IS NULL THEN
        RAISE EXCEPTION 'Authentication required.';
    END IF;


    -- =====================================================
    -- 2. Actor identity
    -- =====================================================

    IF p_actor_id != v_caller_uid THEN
        RAISE EXCEPTION
            'Actor ID mismatch. Possible privilege escalation attempt.';
    END IF;


    -- =====================================================
    -- 3. Company isolation
    -- =====================================================

    v_jwt_company_id := COALESCE(
        auth.jwt()->>'company_id',
        auth.jwt()->'user_metadata'->>'company_id'
    );

    IF v_jwt_company_id IS NULL THEN
        RAISE EXCEPTION 'Company ID not found in JWT.';
    END IF;

    IF p_company_id::TEXT != v_jwt_company_id THEN
        RAISE EXCEPTION
            'Company ID mismatch. Multi-tenancy violation detected.';
    END IF;


    -- =====================================================
    -- 4. Checker role
    -- =====================================================

    v_jwt_role := COALESCE(
        auth.jwt()->>'role',
        auth.jwt()->'user_metadata'->>'role'
    );

    IF v_jwt_role NOT IN (
        'admin',
        'checker',
        'finance_manager'
    ) THEN
        RAISE EXCEPTION
            'Insufficient database permissions. '
            'Checker role authority required.';
    END IF;


    -- =====================================================
    -- 5. Step-Up MFA / AAL2
    -- =====================================================

    v_jwt_aal := COALESCE(
        auth.jwt()->>'aal',
        auth.jwt()->'user_metadata'->>'aal'
    );

    IF v_jwt_aal != 'aal2' THEN
        RAISE EXCEPTION
            'MFA_REQUIRED: Step-Up MFA (AAL2) required.';
    END IF;

    IF p_mfa_verification_proof IS NULL
       OR length(trim(p_mfa_verification_proof)) = 0 THEN

        RAISE EXCEPTION
            'MFA_REQUIRED: Verification proof is required.';
    END IF;


    -- =====================================================
    -- 6. Decision validation
    -- =====================================================

    IF p_decision NOT IN ('APPROVE', 'REJECT') THEN
        RAISE EXCEPTION
            'Invalid checker decision.';
    END IF;


    -- =====================================================
    -- 7. Lock request + read Maker identity
    -- =====================================================

    SELECT
        status,
        verified_by
    INTO
        v_current_status,
        v_maker_id
    FROM public.change_requests
    WHERE id = p_request_id
      AND company_id = p_company_id
    FOR UPDATE;

    IF v_current_status IS NULL THEN
        RAISE EXCEPTION 'Change request not found.';
    END IF;


    -- =====================================================
    -- 8. State machine gate
    -- =====================================================

    IF v_current_status != 'PENDING_VERIFICATION' THEN
        RAISE EXCEPTION
            'STATE_INVALID: Checker action requires '
            'PENDING_VERIFICATION.';
    END IF;


    -- =====================================================
    -- 9. Strict Maker-Checker separation
    -- =====================================================

    IF v_maker_id IS NULL THEN
        RAISE EXCEPTION
            'MAKER_CHECKER_SEPARATION: '
            'Maker verification is missing.';
    END IF;

    IF v_maker_id = p_actor_id THEN
        RAISE EXCEPTION
            'MAKER_CHECKER_SEPARATION: '
            'Maker cannot approve own verification.';
    END IF;


    -- =====================================================
    -- 10. Final decision + 48-hour cooling-off
    -- =====================================================

    IF p_decision = 'APPROVE' THEN

        v_new_status := 'APPROVED';

        -- PRD Sec 15
        v_effective_date := NOW() + INTERVAL '48 hours';

    ELSE

        v_new_status := 'REJECTED';

        v_effective_date := NULL;

    END IF;


    -- =====================================================
    -- 11. Update request
    -- =====================================================

    UPDATE public.change_requests
    SET
        status = v_new_status,
        approved_by = p_actor_id,
        effective_date = v_effective_date
    WHERE id = p_request_id
      AND company_id = p_company_id;


    -- =====================================================
    -- 12. Atomic audit trail
    -- =====================================================

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

        CASE
            WHEN p_decision = 'APPROVE'
                THEN 'CHECKER_APPROVED'
            ELSE
                'CHECKER_REJECTED'
        END,

        p_actor_id,

        jsonb_build_object(
            'decision', p_decision,
            'previous_status', v_current_status,
            'new_status', v_new_status,

            'maker_id', v_maker_id,
            'checker_id', p_actor_id,

            -- Forensic approver role
            'approver_role', v_jwt_role,

            'mfa_verified', TRUE,
            'mfa_aal', v_jwt_aal,

            'effective_date', v_effective_date,

            'cooling_off_hours',
                CASE
                    WHEN p_decision = 'APPROVE'
                        THEN 48
                    ELSE 0
                END,

            'checker_notes', p_checker_notes
        ),

        p_ip_address::inet,
        NOW()
    );


    -- =====================================================
    -- 13. Success
    -- =====================================================

    RETURN jsonb_build_object(
        'request_id', p_request_id,
        'status', v_new_status,
        'decision', p_decision,
        'mfa_verified', TRUE,
        'effective_date', v_effective_date
    );


EXCEPTION
    WHEN OTHERS THEN
        RAISE;
END;
$$;


-- Permissions
REVOKE EXECUTE ON FUNCTION public.checker_approve_request_with_mfa(
    UUID, UUID, UUID, TEXT, TEXT, TEXT, TEXT
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.checker_approve_request_with_mfa(
    UUID, UUID, UUID, TEXT, TEXT, TEXT, TEXT
) TO authenticated;
