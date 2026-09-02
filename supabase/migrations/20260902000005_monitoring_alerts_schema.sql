-- =========================================================
-- VENDOR BANK-CHANGE FRAUD GUARDIAN
-- STEP 8 — HARDENED MONITORING, ALERTING & INCIDENT SYSTEM (PRD v1.1)
-- =========================================================

-- 1. Enums
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'alert_severity') THEN
        CREATE TYPE alert_severity AS ENUM ('INFO', 'WARNING', 'HIGH', 'CRITICAL');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'alert_status') THEN
        CREATE TYPE alert_status AS ENUM ('FIRING', 'RESOLVED', 'SUPPRESSED');
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'incident_status') THEN
        CREATE TYPE incident_status AS ENUM ('OPEN', 'INVESTIGATING', 'MITIGATED', 'RESOLVED', 'ESCALATED');
    END IF;
END $$;

-- 2. Alerts Table (with Canonical Versioned Fingerprinting & Anti-Storm Deduplication)
CREATE TABLE IF NOT EXISTS public.alerts (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    company_id UUID NOT NULL,
    fingerprint VARCHAR(64) NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    severity alert_severity NOT NULL DEFAULT 'WARNING',
    status alert_status NOT NULL DEFAULT 'FIRING',
    title VARCHAR(255) NOT NULL,
    description TEXT,
    entity_type VARCHAR(50),
    entity_id UUID,
    event_count INT NOT NULL DEFAULT 1,
    first_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    payload_sanitized JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    CONSTRAINT unique_company_fingerprint UNIQUE (company_id, fingerprint)
);

-- 3. Incidents Table (Deletion Prohibited, State Machine Managed)
CREATE TABLE IF NOT EXISTS public.incidents (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    company_id UUID NOT NULL,
    alert_id UUID REFERENCES public.alerts(id) ON DELETE SET NULL,
    title VARCHAR(255) NOT NULL,
    severity alert_severity NOT NULL,
    status incident_status NOT NULL DEFAULT 'OPEN',
    assigned_to UUID,
    summary TEXT,
    mitigation_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 4. Incident Transitions Table (Immutable Audit Ledger, Deletion Prohibited, NO CASCADE DELETE)
CREATE TABLE IF NOT EXISTS public.incident_transitions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    incident_id UUID NOT NULL REFERENCES public.incidents(id) ON DELETE RESTRICT,
    company_id UUID NOT NULL,
    from_status incident_status NOT NULL,
    to_status incident_status NOT NULL,
    actor_id UUID NOT NULL,
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 5. DB-Level Immutability & Anti-Tamper Trigger Guards

-- Guard A: Incidents cannot be deleted
CREATE OR REPLACE FUNCTION public.prevent_incident_deletion()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'SECURITY_VIOLATION: Incidents cannot be deleted. Deletion is permanently prohibited for audit integrity.';
END;
$$;

DROP TRIGGER IF EXISTS trigger_prevent_incident_deletion ON public.incidents;
CREATE TRIGGER trigger_prevent_incident_deletion
BEFORE DELETE ON public.incidents
FOR EACH ROW
EXECUTE FUNCTION public.prevent_incident_deletion();

-- Guard B: Incident Transitions are strictly append-only
CREATE OR REPLACE FUNCTION public.prevent_incident_transitions_tamper()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'IMMUTABILITY_VIOLATION: incident_transitions is strictly append-only. UPDATE and DELETE operations are permanently prohibited.';
END;
$$;

DROP TRIGGER IF EXISTS trigger_prevent_incident_transitions_tamper ON public.incident_transitions;
CREATE TRIGGER trigger_prevent_incident_transitions_tamper
BEFORE UPDATE OR DELETE ON public.incident_transitions
FOR EACH ROW
EXECUTE FUNCTION public.prevent_incident_transitions_tamper();

-- 6. Atomic Authorized Incident Transition RPC
CREATE OR REPLACE FUNCTION public.transition_security_incident_with_audit(
    p_incident_id UUID,
    p_company_id UUID,
    p_actor_id UUID,
    p_from_status incident_status,
    p_to_status incident_status,
    p_notes TEXT
)
RETURNS JSON
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_caller_uid UUID;
    v_jwt_company_id TEXT;
    v_current_status incident_status;
    v_transition_id UUID;
BEGIN
    -- 1. Authentication Check
    v_caller_uid := auth.uid();
    IF v_caller_uid IS NULL THEN
        RAISE EXCEPTION 'Authentication required.';
    END IF;

    IF p_actor_id != v_caller_uid THEN
        RAISE EXCEPTION 'Actor ID mismatch.';
    END IF;

    -- 2. Multi-Tenancy Check
    v_jwt_company_id := auth.jwt()->>'company_id';
    IF v_jwt_company_id IS NULL OR v_jwt_company_id::UUID != p_company_id THEN
        RAISE EXCEPTION 'Tenant isolation violation.';
    END IF;

    -- 3. Lock Incident Row and Verify Current State
    SELECT status INTO v_current_status
    FROM public.incidents
    WHERE id = p_incident_id AND company_id = p_company_id
    FOR UPDATE;

    IF v_current_status IS NULL THEN
        RAISE EXCEPTION 'Incident not found or unauthorized.';
    END IF;

    IF v_current_status != p_from_status THEN
        RAISE EXCEPTION 'STALE_STATE_CONFLICT: Current incident status is %, not %.', v_current_status, p_from_status;
    END IF;

    -- 4. State Machine Validation
    IF v_current_status = 'OPEN' AND p_to_status NOT IN ('INVESTIGATING', 'ESCALATED', 'RESOLVED') THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Cannot transition from OPEN to %', p_to_status;
    ELSIF v_current_status = 'INVESTIGATING' AND p_to_status NOT IN ('MITIGATED', 'ESCALATED', 'RESOLVED') THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Cannot transition from INVESTIGATING to %', p_to_status;
    ELSIF v_current_status = 'MITIGATED' AND p_to_status NOT IN ('RESOLVED', 'INVESTIGATING') THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Cannot transition from MITIGATED to %', p_to_status;
    ELSIF v_current_status = 'ESCALATED' AND p_to_status NOT IN ('INVESTIGATING', 'MITIGATED', 'RESOLVED') THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Cannot transition from ESCALATED to %', p_to_status;
    ELSIF v_current_status = 'RESOLVED' AND p_to_status != 'OPEN' THEN
        RAISE EXCEPTION 'INVALID_STATE_TRANSITION: Cannot transition from RESOLVED to %', p_to_status;
    END IF;

    -- 5. Atomically Update Incident
    UPDATE public.incidents
    SET status = p_to_status,
        mitigation_notes = CASE WHEN p_to_status IN ('MITIGATED', 'RESOLVED') THEN p_notes ELSE mitigation_notes END,
        updated_at = NOW()
    WHERE id = p_incident_id;

    -- 6. Atomically Insert Immutable Transition Record
    INSERT INTO public.incident_transitions (
        incident_id,
        company_id,
        from_status,
        to_status,
        actor_id,
        notes
    ) VALUES (
        p_incident_id,
        p_company_id,
        v_current_status,
        p_to_status,
        p_actor_id,
        p_notes
    ) RETURNING id INTO v_transition_id;

    RETURN json_build_object(
        'success', true,
        'incident_id', p_incident_id,
        'from_status', v_current_status,
        'to_status', p_to_status,
        'transition_id', v_transition_id,
        'actor_id', p_actor_id
    );
END;
$$;

-- 7. Row Level Security (RLS) — Hardened Strict Policies
ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.incident_transitions ENABLE ROW LEVEL SECURITY;

-- Alerts RLS: SELECT and INSERT only for authenticated tenant
DROP POLICY IF EXISTS alerts_select_policy ON public.alerts;
DROP POLICY IF EXISTS alerts_insert_policy ON public.alerts;
CREATE POLICY alerts_select_policy ON public.alerts FOR SELECT TO authenticated
USING (company_id = (auth.jwt() ->> 'company_id')::UUID);

CREATE POLICY alerts_insert_policy ON public.alerts FOR INSERT TO authenticated
WITH CHECK (company_id = (auth.jwt() ->> 'company_id')::UUID);

-- Incidents RLS: SELECT only for authenticated (Client UPDATE/DELETE strictly blocked!)
DROP POLICY IF EXISTS incidents_select_policy ON public.incidents;
CREATE POLICY incidents_select_policy ON public.incidents FOR SELECT TO authenticated
USING (company_id = (auth.jwt() ->> 'company_id')::UUID);

-- Incident Transitions RLS: SELECT only for authenticated (Client direct INSERT/UPDATE/DELETE strictly blocked!)
DROP POLICY IF EXISTS incident_transitions_select_policy ON public.incident_transitions;
CREATE POLICY incident_transitions_select_policy ON public.incident_transitions FOR SELECT TO authenticated
USING (company_id = (auth.jwt() ->> 'company_id')::UUID);

-- 8. Explicit Permissions (Least-Privilege)
REVOKE ALL ON public.alerts FROM PUBLIC;
REVOKE ALL ON public.incidents FROM PUBLIC;
REVOKE ALL ON public.incident_transitions FROM PUBLIC;

GRANT SELECT, INSERT ON public.alerts TO authenticated;
GRANT SELECT ON public.incidents TO authenticated;
GRANT SELECT ON public.incident_transitions TO authenticated;
GRANT EXECUTE ON FUNCTION public.transition_security_incident_with_audit TO authenticated;
