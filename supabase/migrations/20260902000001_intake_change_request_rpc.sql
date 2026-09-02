-- =========================================================
-- VENDOR BANK-CHANGE FRAUD GUARDIAN
-- STEP 5 PART 1 — INTAKE CHANGE REQUEST WITH AUDIT (RPC)
-- PRD v1.1 Sections 14, 21, 22, 24
-- =========================================================

CREATE OR REPLACE FUNCTION intake_change_request_with_audit(
    p_company_id UUID,
    p_vendor_id UUID,
    p_request_source VARCHAR,
    p_file_hash VARCHAR,
    p_imap_message_id VARCHAR,
    p_new_account_holder_name VARCHAR,
    p_new_account_number_hashed VARCHAR,
    p_new_ifsc_code VARCHAR,
    p_requested_by TEXT,
    p_actor_id UUID,
    p_action VARCHAR,
    p_details JSONB,
    p_ip_address INET DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_caller_uid UUID;
    v_caller_company_id UUID;
    v_new_request_id UUID;
    v_status request_status := 'PENDING_REVIEW';
BEGIN
    -- 1. Caller Authentication & Multi-Tenancy Verification
    v_caller_uid := auth.uid();
    IF v_caller_uid IS NULL THEN
        RAISE EXCEPTION 'Authentication required';
    END IF;

    v_caller_company_id := (auth.jwt() ->> 'company_id')::UUID;
    IF v_caller_company_id IS NULL OR v_caller_company_id <> p_company_id THEN
        RAISE EXCEPTION 'Multi-tenancy violation: unauthorized company access';
    END IF;

    -- 2. Verify Vendor belongs to Tenant
    IF NOT EXISTS (
        SELECT 1 FROM vendors 
        WHERE id = p_vendor_id 
          AND company_id = p_company_id 
          AND is_deleted = FALSE
    ) THEN
        RAISE EXCEPTION 'Vendor not found or deleted for this company';
    END IF;

    -- 3. Atomic INSERT with Idempotency Handling
    BEGIN
        INSERT INTO change_requests (
            company_id,
            vendor_id,
            request_source,
            file_hash,
            imap_message_id,
            new_account_holder_name,
            new_account_number_hashed,
            new_ifsc_code,
            status,
            requested_by
        ) VALUES (
            p_company_id,
            p_vendor_id,
            p_request_source,
            p_file_hash,
            p_imap_message_id,
            p_new_account_holder_name,
            p_new_account_number_hashed,
            p_new_ifsc_code,
            v_status,
            p_requested_by
        )
        RETURNING id INTO v_new_request_id;
    EXCEPTION
        WHEN unique_violation THEN
            RAISE EXCEPTION 'Duplicate request detected. Idempotency enforced.';
    END;

    -- 4. Atomic Audit Log Entry (Fail-Closed)
    INSERT INTO audit_logs (
        company_id,
        record_id,
        table_name,
        action,
        actor_id,
        details,
        ip_address
    ) VALUES (
        p_company_id,
        v_new_request_id,
        'change_requests',
        p_action,
        p_actor_id,
        p_details,
        p_ip_address
    );

    -- 5. Return success result
    RETURN jsonb_build_object(
        'request_id', v_new_request_id,
        'status', v_status
    );
END;
$$;

-- Security hardening: restrict permissions
REVOKE EXECUTE ON FUNCTION intake_change_request_with_audit FROM public;
GRANT EXECUTE ON FUNCTION intake_change_request_with_audit TO authenticated;
