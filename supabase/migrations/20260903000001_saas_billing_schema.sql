-- ==============================================================================
-- STEP 10 — SAAS BILLING & SUBSCRIPTION ARCHITECTURE SCHEMA (PRD v1.1)
-- ==============================================================================

-- 1. Create Enums for Billing & Subscriptions
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'subscription_tier') THEN
        CREATE TYPE subscription_tier AS ENUM ('STARTER', 'GROWTH', 'ENTERPRISE', 'ENTERPRISE_PLUS');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'subscription_status') THEN
        CREATE TYPE subscription_status AS ENUM ('TRIALING', 'ACTIVE', 'PAST_DUE', 'SUSPENDED', 'CANCELED');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'billing_cadence') THEN
        CREATE TYPE billing_cadence AS ENUM ('MONTHLY', 'ANNUAL');
    END IF;
END $$;

-- 2. Multi-Tenant Subscriptions Table (Authoritative Server-Side State)
CREATE TABLE IF NOT EXISTS public.subscriptions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    company_id UUID NOT NULL UNIQUE,
    tier subscription_tier NOT NULL DEFAULT 'STARTER',
    status subscription_status NOT NULL DEFAULT 'TRIALING',
    cadence billing_cadence NOT NULL DEFAULT 'MONTHLY',
    monthly_request_limit INT NOT NULL DEFAULT 50,
    monthly_request_count INT NOT NULL DEFAULT 0,
    active_vendor_limit INT NOT NULL DEFAULT 100,
    early_adopter_discount_applied BOOLEAN NOT NULL DEFAULT FALSE,
    annual_discount_percentage NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    base_price_inr NUMERIC(12,2) NOT NULL DEFAULT 49999.00,
    effective_price_inr NUMERIC(12,2) NOT NULL DEFAULT 49999.00,
    payment_provider VARCHAR(50) NOT NULL DEFAULT 'RAZORPAY',
    external_customer_id VARCHAR(255),
    external_subscription_id VARCHAR(255),
    current_period_start TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    current_period_end TIMESTAMP WITH TIME ZONE DEFAULT (NOW() + INTERVAL '30 days'),
    cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. Immutable Subscription Ledger (Financial & State Audit Trail)
CREATE TABLE IF NOT EXISTS public.subscription_ledger (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    subscription_id UUID NOT NULL REFERENCES public.subscriptions(id) ON DELETE RESTRICT,
    company_id UUID NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    from_status subscription_status,
    to_status subscription_status,
    amount_inr NUMERIC(12,2) NOT NULL DEFAULT 0.00,
    tax_gst_inr NUMERIC(12,2) NOT NULL DEFAULT 0.00,
    provider_event_id VARCHAR(255),
    actor_id UUID,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. Idempotent Payment Webhook Events Table
CREATE TABLE IF NOT EXISTS public.payment_webhook_events (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    provider_event_id VARCHAR(255) NOT NULL UNIQUE,
    provider VARCHAR(50) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    company_id UUID,
    payload_sanitized JSONB NOT NULL DEFAULT '{}'::jsonb,
    processed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 5. Immutability Triggers (Permanent Block on UPDATE and DELETE)
CREATE OR REPLACE FUNCTION public.prevent_subscription_ledger_tamper()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABILITY_VIOLATION: subscription_ledger is strictly append-only. UPDATE and DELETE operations are permanently prohibited.';
END;
$$;

DROP TRIGGER IF EXISTS trigger_prevent_subscription_ledger_tamper ON public.subscription_ledger;
CREATE TRIGGER trigger_prevent_subscription_ledger_tamper
BEFORE UPDATE OR DELETE ON public.subscription_ledger
FOR EACH ROW EXECUTE FUNCTION public.prevent_subscription_ledger_tamper();

CREATE OR REPLACE FUNCTION public.prevent_payment_webhook_events_tamper()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABILITY_VIOLATION: payment_webhook_events is strictly append-only. UPDATE and DELETE operations are permanently prohibited.';
END;
$$;

DROP TRIGGER IF EXISTS trigger_prevent_payment_webhook_events_tamper ON public.payment_webhook_events;
CREATE TRIGGER trigger_prevent_payment_webhook_events_tamper
BEFORE UPDATE OR DELETE ON public.payment_webhook_events
FOR EACH ROW EXECUTE FUNCTION public.prevent_payment_webhook_events_tamper();

-- 6. Server-Side Quota Enforcement Security Definer RPC
CREATE OR REPLACE FUNCTION public.check_and_increment_subscription_quota(
    p_company_id UUID
)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    v_sub RECORD;
BEGIN
    SELECT * INTO v_sub
    FROM public.subscriptions
    WHERE company_id = p_company_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'NO_SUBSCRIPTION_FOUND: Tenant has no configured subscription.';
    END IF;

    -- Block Write RPCs if Suspended or Past Due
    IF v_sub.status IN ('SUSPENDED', 'PAST_DUE', 'CANCELED') THEN
        RAISE EXCEPTION 'SUBSCRIPTION_LOCKED: Tenant subscription is %, writes are blocked. Read-only audit access preserved.', v_sub.status;
    END IF;

    -- Check Monthly Quota Limit (-1 represents unlimited enterprise quota)
    IF v_sub.monthly_request_limit != -1 AND v_sub.monthly_request_count >= v_sub.monthly_request_limit THEN
        RAISE EXCEPTION 'QUOTA_EXCEEDED: Monthly change request quota of % reached. Upgrade plan for higher limits.', v_sub.monthly_request_limit;
    END IF;

    -- Increment usage
    UPDATE public.subscriptions
    SET monthly_request_count = monthly_request_count + 1,
        updated_at = NOW()
    WHERE company_id = p_company_id;

    RETURN json_build_object(
        'success', true,
        'company_id', p_company_id,
        'tier', v_sub.tier,
        'status', v_sub.status,
        'new_count', v_sub.monthly_request_count + 1,
        'limit', v_sub.monthly_request_limit
    );
END;
$$;

-- 7. Row Level Security Policies
ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.subscription_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payment_webhook_events ENABLE ROW LEVEL SECURITY;

-- Tenants can only SELECT their own subscription
CREATE POLICY subscriptions_select_policy ON public.subscriptions FOR SELECT TO authenticated
USING (company_id = (auth.jwt() ->> 'company_id')::UUID);

-- Tenants can only SELECT their own subscription ledger
CREATE POLICY subscription_ledger_select_policy ON public.subscription_ledger FOR SELECT TO authenticated
USING (company_id = (auth.jwt() ->> 'company_id')::UUID);

-- Clients cannot directly query payment_webhook_events
CREATE POLICY webhook_events_select_policy ON public.payment_webhook_events FOR SELECT TO authenticated
USING (company_id = (auth.jwt() ->> 'company_id')::UUID);

-- Revoke dangerous direct permissions from PUBLIC and authenticated
REVOKE ALL ON public.subscriptions FROM PUBLIC;
REVOKE ALL ON public.subscription_ledger FROM PUBLIC;
REVOKE ALL ON public.payment_webhook_events FROM PUBLIC;

GRANT SELECT ON public.subscriptions TO authenticated;
GRANT SELECT ON public.subscription_ledger TO authenticated;
GRANT EXECUTE ON FUNCTION public.check_and_increment_subscription_quota TO authenticated;
