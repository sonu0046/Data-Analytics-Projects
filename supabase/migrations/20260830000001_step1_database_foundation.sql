-- =========================================================
-- VENDOR BANK-CHANGE FRAUD GUARDIAN
-- STEP 1 — FINAL DATABASE FOUNDATION
-- PRD v1.1
-- =========================================================
-- Status:
-- LOCKED & APPROVED BY 3 BROTHERS
--
-- Scope:
-- Database foundation ONLY.
-- Do NOT implement AI, OCR, IMAP processing logic,
-- frontend, MFA, alerts, or risk-engine runtime logic here.
-- =========================================================
BEGIN;
-- =========================================================
-- 1. REQUIRED EXTENSIONS
-- =========================================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
-- =========================================================
-- 2. ENUMS
-- =========================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_type
        WHERE typname = 'request_status'
    ) THEN
        CREATE TYPE request_status AS ENUM (
            'PENDING_REVIEW',
            'PENDING_VERIFICATION',
            'VERIFIED',
            'APPROVED',
            'REJECTED',
            'ESCALATED',
            'SYSTEM_INVALIDATED'
        );
    END IF;
END
$$;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_type
        WHERE typname = 'risk_level'
    ) THEN
        CREATE TYPE risk_level AS ENUM (
            'LOW',
            'MEDIUM',
            'HIGH',
            'CRITICAL'
        );
    END IF;
END
$$;
-- =========================================================
-- 3. VENDORS
-- =========================================================
CREATE TABLE IF NOT EXISTS vendors (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    company_id UUID NOT NULL,
    vendor_name VARCHAR(255) NOT NULL,
    gstin VARCHAR(15),
    trusted_email_domain VARCHAR(255),
    trusted_phone_number_encrypted TEXT NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    is_deleted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
-- =========================================================
-- 4. VENDOR BANK ACCOUNTS
-- =========================================================
CREATE TABLE IF NOT EXISTS vendor_bank_accounts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    company_id UUID NOT NULL,
    vendor_id UUID NOT NULL
        REFERENCES vendors(id)
        ON DELETE RESTRICT,
    account_holder_name VARCHAR(255),
    account_number_encrypted TEXT NOT NULL,
    ifsc_code VARCHAR(11),
    bank_name VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    effective_date TIMESTAMP WITH TIME ZONE,
    verified_by_user_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
-- =========================================================
-- 5. CHANGE REQUESTS
-- =========================================================
CREATE TABLE IF NOT EXISTS change_requests (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    company_id UUID NOT NULL,
    vendor_id UUID NOT NULL
        REFERENCES vendors(id)
        ON DELETE RESTRICT,
    request_source VARCHAR(50)
        CHECK (
            request_source IN (
                'PDF_UPLOAD',
                'IMAP_FETCH'
            )
        ),
    -- PDF idempotency
    file_hash VARCHAR(255),
    -- IMAP idempotency
    imap_message_id VARCHAR(255),
    new_account_holder_name VARCHAR(255),
    new_account_number_hashed VARCHAR(255),
    new_ifsc_code VARCHAR(11),
    status request_status DEFAULT 'PENDING_REVIEW',
    risk_score INT DEFAULT 0,
    risk_level risk_level DEFAULT 'LOW',
    detected_signals TEXT[],
    verification_method VARCHAR(50),
    verification_result TEXT,
    human_decision_reason TEXT,
    requested_by VARCHAR(255),
    reviewed_by UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    -- Prevent duplicate PDF processing
    CONSTRAINT unique_change_request_file_hash
        UNIQUE (file_hash)
);
-- =========================================================
-- 6. AUDIT LOGS
-- =========================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    company_id UUID NOT NULL,
    record_id UUID NOT NULL,
    table_name VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    actor_id UUID,
    details JSONB,
    ip_address INET,
    previous_row_hash VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
-- =========================================================
-- 7. PERFORMANCE INDEXES
-- =========================================================
CREATE INDEX IF NOT EXISTS idx_company_risk
ON change_requests (
    company_id,
    risk_level,
    created_at DESC
);
CREATE INDEX IF NOT EXISTS idx_vendor_company
ON vendors(company_id);
CREATE INDEX IF NOT EXISTS idx_requests_vendor
ON change_requests(vendor_id);
CREATE INDEX IF NOT EXISTS idx_requests_created_at
ON change_requests(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_record
ON audit_logs(table_name, record_id);
CREATE INDEX IF NOT EXISTS idx_audit_company
ON audit_logs(company_id);
-- =========================================================
-- 8. IMAP IDEMPOTENCY
-- =========================================================
-- Prevent the same IMAP message from being processed twice
-- within the same company/tenant.
CREATE UNIQUE INDEX IF NOT EXISTS idx_imap_unique
ON change_requests (
    company_id,
    imap_message_id
)
WHERE request_source = 'IMAP_FETCH'
  AND imap_message_id IS NOT NULL;
-- =========================================================
-- 9. VENDOR SOFT-DELETE SAFETY
-- =========================================================
CREATE OR REPLACE FUNCTION handle_vendor_soft_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.is_deleted = TRUE
       AND OLD.is_deleted = FALSE THEN
        UPDATE change_requests
        SET
            status = 'SYSTEM_INVALIDATED',
            updated_at = NOW()
        WHERE vendor_id = NEW.id
          AND status IN (
              'PENDING_REVIEW',
              'PENDING_VERIFICATION'
          );
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trigger_vendor_soft_delete
ON vendors;
CREATE TRIGGER trigger_vendor_soft_delete
AFTER UPDATE OF is_deleted
ON vendors
FOR EACH ROW
EXECUTE FUNCTION handle_vendor_soft_delete();
-- =========================================================
-- 10. UPDATED_AT TRIGGER
-- =========================================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trigger_vendors_updated_at
ON vendors;
CREATE TRIGGER trigger_vendors_updated_at
BEFORE UPDATE ON vendors
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();
DROP TRIGGER IF EXISTS trigger_change_requests_updated_at
ON change_requests;
CREATE TRIGGER trigger_change_requests_updated_at
BEFORE UPDATE ON change_requests
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();
-- =========================================================
-- 11. DATA INTEGRITY
-- =========================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_ifsc_length'
    ) THEN
        ALTER TABLE vendor_bank_accounts
        ADD CONSTRAINT chk_ifsc_length
        CHECK (
            ifsc_code IS NULL
            OR length(ifsc_code) = 11
        );
    END IF;
END
$$;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_risk_score_non_negative'
    ) THEN
        ALTER TABLE change_requests
        ADD CONSTRAINT chk_risk_score_non_negative
        CHECK (risk_score >= 0);
    END IF;
END
$$;
-- =========================================================
-- 12. ROW LEVEL SECURITY — MULTI-TENANCY
-- =========================================================
-- Supabase environment.
--
-- IMPORTANT:
-- These policies assume the authenticated JWT contains:
-- company_id
--
-- JWT company_id must represent the tenant UUID.
ALTER TABLE vendors ENABLE ROW LEVEL SECURITY;
ALTER TABLE vendor_bank_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE change_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
-- =========================================================
-- 13. RLS POLICIES — VENDORS
-- =========================================================
DROP POLICY IF EXISTS vendor_company_isolation
ON vendors;
CREATE POLICY vendor_company_isolation
ON vendors
FOR ALL
TO authenticated
USING (
    company_id = (auth.jwt() ->> 'company_id')::UUID
)
WITH CHECK (
    company_id = (auth.jwt() ->> 'company_id')::UUID
);
-- =========================================================
-- 14. RLS POLICIES — BANK ACCOUNTS
-- =========================================================
DROP POLICY IF EXISTS bank_account_company_isolation
ON vendor_bank_accounts;
CREATE POLICY bank_account_company_isolation
ON vendor_bank_accounts
FOR ALL
TO authenticated
USING (
    company_id = (auth.jwt() ->> 'company_id')::UUID
)
WITH CHECK (
    company_id = (auth.jwt() ->> 'company_id')::UUID
);
-- =========================================================
-- 15. RLS POLICIES — CHANGE REQUESTS
-- =========================================================
DROP POLICY IF EXISTS change_request_company_isolation
ON change_requests;
CREATE POLICY change_request_company_isolation
ON change_requests
FOR ALL
TO authenticated
USING (
    company_id = (auth.jwt() ->> 'company_id')::UUID
)
WITH CHECK (
    company_id = (auth.jwt() ->> 'company_id')::UUID
);
-- =========================================================
-- 16. RLS POLICIES — AUDIT LOGS
-- =========================================================
DROP POLICY IF EXISTS audit_company_isolation
ON audit_logs;
CREATE POLICY audit_company_isolation
ON audit_logs
FOR ALL
TO authenticated
USING (
    company_id = (auth.jwt() ->> 'company_id')::UUID
)
WITH CHECK (
    company_id = (auth.jwt() ->> 'company_id')::UUID
);
-- =========================================================
-- 17. FINAL
-- =========================================================
COMMIT;
-- =========================================================
-- STEP 1 DATABASE FOUNDATION
-- LOCKED & APPROVED BY 3 BROTHERS
-- =========================================================
