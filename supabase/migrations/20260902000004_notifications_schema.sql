-- =========================================================
-- VENDOR BANK-CHANGE FRAUD GUARDIAN
-- STEP 7 — NOTIFICATION & HARDENED IMMUTABLE DELIVERY AUDIT SYSTEM (PRD v1.1)
-- =========================================================

-- 1. Notification Enums
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'notification_channel') THEN
        CREATE TYPE notification_channel AS ENUM ('EMAIL', 'SMS', 'WEBHOOK');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'notification_status') THEN
        CREATE TYPE notification_status AS ENUM ('PENDING', 'SENT', 'FAILED', 'RETRYING');
    END IF;
END $$;

-- 2. Notifications Table
CREATE TABLE IF NOT EXISTS public.notifications (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    company_id UUID NOT NULL,
    request_id UUID REFERENCES public.change_requests(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL,
    channel notification_channel NOT NULL DEFAULT 'EMAIL',
    recipient_masked VARCHAR(255) NOT NULL,
    template_key VARCHAR(100) NOT NULL,
    payload_sanitized JSONB NOT NULL DEFAULT '{}'::jsonb,
    status notification_status NOT NULL DEFAULT 'PENDING',
    retry_count INT NOT NULL DEFAULT 0,
    max_retries INT NOT NULL DEFAULT 3,
    last_error TEXT,
    sent_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. Dedicated Immutable Notification Deliveries Ledger (Strictly Append-Only)
CREATE TABLE IF NOT EXISTS public.notification_deliveries (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    notification_id UUID REFERENCES public.notifications(id) ON DELETE CASCADE,
    company_id UUID NOT NULL,
    channel notification_channel NOT NULL,
    provider_name VARCHAR(100) NOT NULL,
    attempt_number INT NOT NULL,
    status notification_status NOT NULL,
    duration_ms INT DEFAULT 0,
    safe_error TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. DB-Level Immutability Enforcement (Trigger Guard)
CREATE OR REPLACE FUNCTION public.prevent_notification_deliveries_tamper()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABILITY_VIOLATION: notification_deliveries is strictly append-only. UPDATE and DELETE operations are permanently prohibited.';
END;
$$;

DROP TRIGGER IF EXISTS trigger_prevent_notification_deliveries_tamper ON public.notification_deliveries;
CREATE TRIGGER trigger_prevent_notification_deliveries_tamper
BEFORE UPDATE OR DELETE ON public.notification_deliveries
FOR EACH ROW
EXECUTE FUNCTION public.prevent_notification_deliveries_tamper();

-- 5. Indexes for Performance and Audits
CREATE INDEX IF NOT EXISTS idx_notifications_company ON public.notifications(company_id);
CREATE INDEX IF NOT EXISTS idx_notifications_request ON public.notifications(request_id);
CREATE INDEX IF NOT EXISTS idx_notifications_status ON public.notifications(status, created_at);
CREATE INDEX IF NOT EXISTS idx_deliveries_notification ON public.notification_deliveries(notification_id);
CREATE INDEX IF NOT EXISTS idx_deliveries_company ON public.notification_deliveries(company_id);

-- 6. Row Level Security (RLS) — Hardened Split Policies
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notification_deliveries ENABLE ROW LEVEL SECURITY;

-- Notifications Policies
DROP POLICY IF EXISTS notifications_company_isolation ON public.notifications;
CREATE POLICY notifications_company_isolation ON public.notifications FOR ALL TO authenticated
USING (company_id = (auth.jwt() ->> 'company_id')::UUID)
WITH CHECK (company_id = (auth.jwt() ->> 'company_id')::UUID);

-- Immutable Deliveries Policies (Strictly SELECT and INSERT only, NO UPDATE/DELETE)
DROP POLICY IF EXISTS notification_deliveries_company_isolation ON public.notification_deliveries;
DROP POLICY IF EXISTS notification_deliveries_select_policy ON public.notification_deliveries;
DROP POLICY IF EXISTS notification_deliveries_insert_policy ON public.notification_deliveries;

CREATE POLICY notification_deliveries_select_policy
ON public.notification_deliveries
FOR SELECT
TO authenticated
USING (company_id = (auth.jwt() ->> 'company_id')::UUID);

CREATE POLICY notification_deliveries_insert_policy
ON public.notification_deliveries
FOR INSERT
TO authenticated
WITH CHECK (company_id = (auth.jwt() ->> 'company_id')::UUID);

-- Explicitly revoke permissions from public
REVOKE ALL ON public.notification_deliveries FROM PUBLIC;
GRANT SELECT, INSERT ON public.notification_deliveries TO authenticated;
