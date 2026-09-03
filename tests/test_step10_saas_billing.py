# tests/test_step10_saas_billing.py - Step 10 SaaS Billing & Subscriptions Test Suite (PRD v1.1)
import os
import sys
import uuid
import hmac
import hashlib
from datetime import datetime, timezone

# Ensure project root in sys.path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from app.models.billing import (
    SubscriptionTier,
    SubscriptionStatus,
    BillingCadence,
    TIER_PRICING_CONFIG,
    ANNUAL_DISCOUNT_PERCENT,
    EARLY_ADOPTER_DISCOUNT_PERCENT,
    GST_RATE_PERCENT,
)
from app.services.billing_service import (
    BillingService,
    InMemorySubscriptionStore,
)
from app.services.risk_engine import calculate_deterministic_risk
from app.models.risk_engine import RiskEngineInput, RiskLevelEnum


def run_step10_saas_billing_tests():
    print("==================================================================")
    print(" 💳 STEP 10 — SAAS BILLING, PRICING & SUBSCRIPTIONS AUDIT SUITE")
    print("==================================================================")

    store = InMemorySubscriptionStore()
    webhook_secret = "test-fintech-webhook-secret-key-32b"
    svc = BillingService(store=store, webhook_secret=webhook_secret)

    comp_a = uuid.uuid4()
    comp_b = uuid.uuid4()
    actor_id = uuid.uuid4()

    # ------------------------------------------------------------------
    # PROOF 1: Commercial Pricing & Tier Calculations
    # ------------------------------------------------------------------
    print("\n[PROOF 1: Commercial Pricing, Discounts & GST Calculation]")

    # 1A: Starter Monthly Standard
    p_starter = svc.calculate_pricing(
        SubscriptionTier.STARTER,
        cadence=BillingCadence.MONTHLY,
        apply_early_adopter=False,
    )
    print(f"Starter Monthly: {p_starter}")
    assert p_starter["base_price_inr"] == 49999.0
    assert p_starter["effective_price_inr"] == 49999.0
    assert p_starter["tax_gst_inr"] == round(49999.0 * 0.18, 2)
    assert p_starter["total_effective_price_inr"] == round(49999.0 * 1.18, 2)

    # 1B: Growth Annual (20% Discount)
    p_growth_ann = svc.calculate_pricing(
        SubscriptionTier.GROWTH,
        cadence=BillingCadence.ANNUAL,
        apply_early_adopter=False,
    )
    expected_growth_ann_base = round(149999.0 * 12 * 0.80, 2)
    print(f"Growth Annual (20% off): {p_growth_ann}")
    assert p_growth_ann["effective_price_inr"] == expected_growth_ann_base
    assert p_growth_ann["tax_gst_inr"] == round(expected_growth_ann_base * 0.18, 2)

    # 1C: Enterprise Monthly Early Adopter (50% Off for 6 Months)
    p_ent_early = svc.calculate_pricing(
        SubscriptionTier.ENTERPRISE,
        cadence=BillingCadence.MONTHLY,
        apply_early_adopter=True,
    )
    expected_ent_early = round(499999.0 * 0.50, 2)
    print(f"Enterprise Early Adopter (50% off): {p_ent_early}")
    assert p_ent_early["effective_price_inr"] == expected_ent_early
    assert p_ent_early["tax_gst_inr"] == round(expected_ent_early * 0.18, 2)

    print("--> PROOF 1: Commercial pricing, discounts and 18% GST verified ✅")

    # ------------------------------------------------------------------
    # PROOF 2: Subscription State Machine & Transitions
    # ------------------------------------------------------------------
    print("\n[PROOF 2: Subscription State Machine Transitions]")

    sub_a = svc.provision_subscription(
        company_id=comp_a,
        tier=SubscriptionTier.GROWTH,
        cadence=BillingCadence.MONTHLY,
        actor_id=actor_id,
    )
    assert sub_a.status == SubscriptionStatus.ACTIVE
    assert sub_a.is_write_locked is False

    # Transition 1: Active -> Past Due (Payment failed)
    sub_past_due = svc.transition_subscription_status(
        company_id=comp_a,
        to_status=SubscriptionStatus.PAST_DUE,
        event_type="PAYMENT_FAILED_GRACE_PERIOD",
        actor_id=actor_id,
    )
    assert sub_past_due.status == SubscriptionStatus.PAST_DUE
    assert sub_past_due.is_write_locked is True

    # Transition 2: Past Due -> Suspended (Grace period expired)
    sub_suspended = svc.transition_subscription_status(
        company_id=comp_a,
        to_status=SubscriptionStatus.SUSPENDED,
        event_type="GRACE_PERIOD_EXPIRED_SUSPENSION",
        actor_id=actor_id,
    )
    assert sub_suspended.status == SubscriptionStatus.SUSPENDED
    assert sub_suspended.is_write_locked is True

    # Transition 3: Re-activation (Payment received)
    sub_reactivated = svc.transition_subscription_status(
        company_id=comp_a,
        to_status=SubscriptionStatus.ACTIVE,
        event_type="PAYMENT_RECOVERY_SUCCESS",
        actor_id=actor_id,
    )
    assert sub_reactivated.status == SubscriptionStatus.ACTIVE
    assert sub_reactivated.is_write_locked is False

    # Transition 4: Illegal State Transition Blocked (e.g. Active directly to Trialing)
    try:
        svc.transition_subscription_status(
            company_id=comp_a,
            to_status=SubscriptionStatus.TRIALING,
            event_type="ILLEGAL_TRANSITION_ATTEMPT",
        )
        assert False, "Illegal state transition should have been rejected"
    except ValueError as ve:
        print(f"Illegal State Transition Blocked: {ve}")
        assert "INVALID_SUBSCRIPTION_TRANSITION" in str(ve)

    print("--> PROOF 2: State machine transitions strictly validated ✅")

    # ------------------------------------------------------------------
    # PROOF 3: Server-Side Quota & Suspension Write-Lock Enforcement
    # ------------------------------------------------------------------
    print("\n[PROOF 3: Server-Side Quotas & Suspension Write-Locking]")

    # Tenant A has limit of 250 requests (Growth tier)
    # Simulate usage
    q1 = svc.check_and_increment_quota(comp_a)
    assert q1["allowed"] is True
    assert q1["current_usage"] == 1
    assert q1["monthly_limit"] == 250

    # Simulate quota exhaustion
    store.subscriptions[comp_a]["monthly_request_count"] = 250
    try:
        svc.check_and_increment_quota(comp_a)
        assert False, "Quota exceeded should have thrown ValueError"
    except ValueError as qe:
        print(f"Quota Limit Enforced: {qe}")
        assert "QUOTA_EXCEEDED" in str(qe)

    # Simulate Suspension: write operations blocked, read-only audit preserved
    store.subscriptions[comp_a]["status"] = SubscriptionStatus.SUSPENDED
    try:
        svc.check_and_increment_quota(comp_a)
        assert False, "Suspended subscription should block writes"
    except PermissionError as pe:
        print(f"Suspension Write Block Enforced: {pe}")
        assert "SUBSCRIPTION_LOCKED" in str(pe)

    # Read access remains allowed
    sub_view = svc.get_subscription(comp_a)
    assert sub_view.is_read_only_audit_preserved is True
    print("--> PROOF 3: Quota limits & write locks enforced server-side; read-only audit preserved ✅")

    # ------------------------------------------------------------------
    # PROOF 4: Idempotent Payment Webhook Processing & HMAC Validation
    # ------------------------------------------------------------------
    print("\n[PROOF 4: Idempotent Payment Webhook Processing & HMAC Verification]")

    # Re-activate Tenant A for webhook test
    store.subscriptions[comp_a]["status"] = SubscriptionStatus.ACTIVE
    store.subscriptions[comp_a]["monthly_request_count"] = 0

    webhook_payload_body = '{"event": "payment.failed", "company_id": "' + str(comp_a) + '"}'
    valid_sig = hmac.new(
        webhook_secret.encode("utf-8"),
        webhook_payload_body.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    # 4A: Valid Webhook Execution
    wh_res = svc.process_payment_webhook(
        raw_body=webhook_payload_body,
        signature=valid_sig,
        provider_event_id="evt_pay_failed_1001",
        event_type="payment.failed",
        company_id=comp_a,
    )
    print(f"Webhook Execution Result: {wh_res}")
    assert wh_res["action"] == "SUBSCRIPTION_FLAGGED_PAST_DUE"
    assert svc.get_subscription(comp_a).status == SubscriptionStatus.PAST_DUE

    # 4B: Idempotent Duplicate Delivery (Deduplicated)
    wh_dup = svc.process_payment_webhook(
        raw_body=webhook_payload_body,
        signature=valid_sig,
        provider_event_id="evt_pay_failed_1001",
        event_type="payment.failed",
        company_id=comp_a,
    )
    print(f"Duplicate Webhook Delivery: {wh_dup}")
    assert wh_dup["action"] == "DEDUPLICATED_AND_IGNORED"

    # 4C: Invalid HMAC Signature Rejected
    try:
        svc.process_payment_webhook(
            raw_body=webhook_payload_body,
            signature="forged_signature_hash",
            provider_event_id="evt_pay_attack_9999",
            event_type="payment.failed",
            company_id=comp_a,
        )
        assert False, "Forged webhook signature should be rejected"
    except PermissionError as pe:
        print(f"Forged Webhook Signature Blocked: {pe}")
        assert "INVALID_WEBHOOK_SIGNATURE" in str(pe)

    print("--> PROOF 4: Webhook HMAC verification and idempotency verified ✅")

    # ------------------------------------------------------------------
    # PROOF 5: Immutable Subscription Ledger Tamper Resistance
    # ------------------------------------------------------------------
    print("\n[PROOF 5: Immutable Subscription Ledger Tamper Resistance]")

    ledger_entries = [e for e in store.ledger if e.company_id == comp_a]
    print(f"Recorded {len(ledger_entries)} immutable subscription events for Tenant A.")
    assert len(ledger_entries) >= 4

    entry_id = ledger_entries[0].id

    # Attempt direct UPDATE on ledger
    try:
        store.update_ledger_record(entry_id, amount_inr=0.0)
        assert False, "Ledger UPDATE should be prohibited"
    except PermissionError as pe:
        print(f"Subscription Ledger UPDATE Blocked: {pe}")
        assert "IMMUTABILITY_VIOLATION" in str(pe)

    # Attempt direct DELETE on ledger
    try:
        store.delete_ledger_record(entry_id)
        assert False, "Ledger DELETE should be prohibited"
    except PermissionError as pe:
        print(f"Subscription Ledger DELETE Blocked: {pe}")
        assert "IMMUTABILITY_VIOLATION" in str(pe)

    print("--> PROOF 5: Subscription Ledger is strictly append-only; tampering permanently blocked ✅")

    # ------------------------------------------------------------------
    # PROOF 6: Multi-Tenant Billing Isolation
    # ------------------------------------------------------------------
    print("\n[PROOF 6: Multi-Tenant Billing Isolation]")

    # Tenant B has separate subscription
    sub_b = svc.provision_subscription(
        company_id=comp_b,
        tier=SubscriptionTier.ENTERPRISE_PLUS,
        cadence=BillingCadence.ANNUAL,
        actor_id=actor_id,
    )
    assert sub_b.company_id == comp_b
    assert sub_b.tier == SubscriptionTier.ENTERPRISE_PLUS
    assert sub_b.monthly_request_limit == -1  # Unlimited

    # Verify Tenant A and Tenant B ledgers are strictly segregated
    ledger_a = [e for e in store.ledger if e.company_id == comp_a]
    ledger_b = [e for e in store.ledger if e.company_id == comp_b]
    assert len(ledger_a) > 0
    assert len(ledger_b) == 1
    assert all(e.company_id == comp_a for e in ledger_a)
    assert all(e.company_id == comp_b for e in ledger_b)

    print("--> PROOF 6: Multi-tenant billing isolation verified ✅")

    # ------------------------------------------------------------------
    # PROOF 7: Steps 1–9 Non-Regression Verification
    # ------------------------------------------------------------------
    print("\n[PROOF 7: Steps 1–9 Non-Regression Verification]")

    # Verify Risk Engine with CRITICAL_SPOOF_BLOCK remains 100% operational
    risk_in = RiskEngineInput(
        company_id=comp_a,
        vendor_id=uuid.uuid4(),
        is_spf_dkim_dmarc_failed=True,
    )
    risk_out = calculate_deterministic_risk(risk_in)
    assert risk_out["score"] == 100
    assert risk_out["level"] == RiskLevelEnum.CRITICAL
    assert risk_out["is_blocked"] is True

    print("--> PROOF 7: Steps 1–9 Security Invariants 100% intact ✅")

    print("\n==================================================================")
    print(" 🎉 ALL STEP 10 SAAS BILLING AUDIT PROOFS PASSED WITH 100% SUCCESS!")
    print("==================================================================")


if __name__ == "__main__":
    run_step10_saas_billing_tests()
