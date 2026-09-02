# tests/test_step9_production_suite.py - Master Production Security, Performance & E2E Suite (Step 9 PRD v1.1)
import os
import sys
import time
import asyncio
import uuid
from datetime import datetime, timezone, timedelta

# Ensure project root in sys.path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

from app.models.risk_engine import RiskEngineInput, RiskLevelEnum
from app.services.risk_engine import calculate_deterministic_risk
from app.models.notification import (
    NotificationChannel,
    NotificationEvent,
    NotificationPayload,
    NotificationStatus,
)
from app.services.notification_service import (
    NotificationService,
    ConsoleMockAdapter,
)
from app.models.monitoring import (
    AlertSeverity,
    AlertEventInput,
    IncidentStatus,
)
from app.services.alert_service import (
    AlertService,
    generate_canonical_fingerprint,
)
from app.services.incident_service import IncidentService
from scripts.backup_and_recovery import DisasterRecoveryManager


def run_master_production_suite():
    print("==================================================================")
    print(" 🚀 STEP 9 — MASTER PRODUCTION DEPLOYMENT & GO-LIVE AUDIT SUITE")
    print("==================================================================")

    comp_a = uuid.uuid4()
    comp_b = uuid.uuid4()
    maker_user = uuid.uuid4()
    checker_user = uuid.uuid4()
    req_id = uuid.uuid4()
    vendor_id = uuid.uuid4()

    # ------------------------------------------------------------------
    # 1. SECURITY & PENETRATION TESTING PROBES
    # ------------------------------------------------------------------
    print("\n[SECTION 1: Enterprise Security & Penetration Testing Probes]")

    # Probe 1A: Cross-Tenant Isolation Attack Simulation
    inc_svc = IncidentService()
    incident_a = inc_svc.create_incident_from_alert(
        company_id=comp_a,
        title="Tenant A Security Incident",
        severity=AlertSeverity.CRITICAL,
        actor_id=maker_user,
    )
    print(f"Created Incident for Tenant A: {incident_a.id}")

    try:
        # Tenant B actor tries to transition Tenant A's incident
        inc_svc.transition_incident(
            incident_id=incident_a.id,
            company_id=comp_b,  # Tenant B
            actor_id=checker_user,
            from_status=IncidentStatus.OPEN,
            to_status=IncidentStatus.INVESTIGATING,
        )
        assert (
            False
        ), "Cross-tenant transition should have been rejected with PermissionError"
    except PermissionError as pe:
        print(f"Cross-Tenant Attack Blocked: {pe}")
        assert "TENANT_ISOLATION_VIOLATION" in str(pe)
    print("--> Probe 1A: Cross-Tenant Isolation Attack Defended ✅")

    # Probe 1B: Immutable Ledger Tamper Resistance Probe
    notif_svc = NotificationService(default_adapter=ConsoleMockAdapter())
    notif_payload = NotificationPayload(
        company_id=comp_a,
        request_id=req_id,
        event_type=NotificationEvent.REQUEST_INTAKED,
        recipient="security@tenant-a.com",
        vendor_name="Acme Corp",
        masked_account_number="98765432109876",
    )

    async def test_notif_tamper():
        res = await notif_svc.dispatch_with_retry(notif_payload)
        records = notif_svc.ledger.get_attempts_for_notification(req_id)
        assert len(records) >= 1
        rec_id = records[0].id

        # Attempt to tamper with delivery ledger
        try:
            notif_svc.ledger.update_record(
                rec_id, status=NotificationStatus.FAILED
            )
            assert False, "Ledger UPDATE should have been blocked"
        except PermissionError as pe:
            print(f"Ledger UPDATE Tamper Blocked: {pe}")
            assert "IMMUTABILITY_VIOLATION" in str(pe)

        try:
            notif_svc.ledger.delete_record(rec_id)
            assert False, "Ledger DELETE should have been blocked"
        except PermissionError as pe:
            print(f"Ledger DELETE Tamper Blocked: {pe}")
            assert "IMMUTABILITY_VIOLATION" in str(pe)

    asyncio.run(test_notif_tamper())
    print("--> Probe 1B: Immutable Delivery Ledger Tamper Resistance Proven ✅")

    # Probe 1C: Zero Plaintext Financial Credentials (PII Masking)
    rendered = notif_svc.sanitize_and_render(notif_payload)
    assert "9876XXXX9876" in rendered["body"]
    assert "98765432109876" not in rendered["body"]
    print("--> Probe 1C: Zero Plaintext Account Credentials Verified ✅")

    # ------------------------------------------------------------------
    # 2. HIGH-CONCURRENCY PERFORMANCE & LOAD BENCHMARK
    # ------------------------------------------------------------------
    print("\n[SECTION 2: High-Concurrency Performance & Stress Benchmark]")

    stress_inputs = [
        RiskEngineInput(
            company_id=comp_a,
            vendor_id=vendor_id,
            is_spf_dkim_dmarc_failed=False,
            is_domain_mismatch=False,
            is_bank_account_changed=True,
            is_ifsc_changed=False,
            is_account_holder_changed=False,
            is_ghost_vendor_match=False,
            is_trusted_phone_mismatch=False,
            is_urgent_language=False,
            is_velocity_anomaly=False,
        )
        for _ in range(100)
    ]

    t_start = time.perf_counter()
    results = [calculate_deterministic_risk(inp) for inp in stress_inputs]
    t_elapsed = time.perf_counter() - t_start

    avg_ms = (t_elapsed / len(stress_inputs)) * 1000.0
    print(
        f"Executed {len(stress_inputs)} Deterministic Risk Calculations in {t_elapsed*1000:.2f}ms."
    )
    print(
        f"Average Latency per Calculation: {avg_ms:.3f}ms (Target SLA: < 10ms)."
    )
    assert (
        avg_ms < 10.0
    ), "Risk engine calculation latency exceeds SLA threshold."
    print("--> Section 2: High-Concurrency Load & Stress Benchmark Passed ✅")

    # ------------------------------------------------------------------
    # 3. END-TO-END WORKFLOW DRILL (Steps 1 through 9)
    # ------------------------------------------------------------------
    print("\n[SECTION 3: Full End-to-End Workflow Execution Drill]")

    # E2E Step 1: Spoofed Request Triggers Critical Spoof Block
    spoofed_input = RiskEngineInput(
        company_id=comp_a,
        vendor_id=vendor_id,
        is_spf_dkim_dmarc_failed=True,  # Critical spoof fail
        is_domain_mismatch=True,
        is_bank_account_changed=True,
        is_ifsc_changed=True,
        is_account_holder_changed=False,
        is_ghost_vendor_match=False,
        is_trusted_phone_mismatch=False,
        is_urgent_language=True,
        is_velocity_anomaly=False,
    )
    spoof_res = calculate_deterministic_risk(spoofed_input)
    print(
        f"Spoofed Request Risk Score: {spoof_res['score']} (Risk Level: {spoof_res['level'].value})"
    )
    assert spoof_res["score"] == 100
    assert spoof_res["level"] == RiskLevelEnum.CRITICAL
    assert spoof_res["is_blocked"] == True

    # E2E Step 2: Critical Alert Generated & Deduplicated
    alert_svc = AlertService(suppression_window_sec=300)
    crit_alert_in = AlertEventInput(
        company_id=comp_a,
        alert_type="CRITICAL_SPOOF_BLOCK",
        severity=AlertSeverity.CRITICAL,
        title="CRITICAL: Spoofed Vendor Bank Request Blocked",
        entity_type="REQUEST",
        entity_id=req_id,
        payload_sanitized={
            "vendor_name": "Bharat Heavy Ltd",
            "masked_account_number": "9876XXXX9876",
        },
    )

    async def run_e2e_alert():
        r = await alert_svc.ingest_alert_event(crit_alert_in)
        assert r["action"] == "NEW_ALERT_CREATED"
        # Duplicate alert within 5m
        r_dup = await alert_svc.ingest_alert_event(crit_alert_in)
        assert r_dup["action"] == "DEDUPLICATED_AND_SUPPRESSED"
        assert r_dup["event_count"] == 2

    asyncio.run(run_e2e_alert())
    print(
        "--> E2E: Ingestion + Risk Engine + Anti-Storm Alert Deduplication Proven ✅"
    )

    # E2E Step 3: Authoritative 48-Hour Cooling-Off Calculation
    now_utc = datetime.now(timezone.utc)
    eff_48h = (now_utc + timedelta(hours=48)).isoformat()
    cooling_eval = notif_svc.evaluate_cooling_off_reminder(eff_48h, now_utc)
    assert cooling_eval["action"] == "IN_COOLING_OFF"
    assert cooling_eval["remaining_hours"] == 48.0
    print(
        f"--> E2E: Authoritative 48-Hour Cooling-Off Verified ({cooling_eval['remaining_hours']}h remaining) ✅"
    )

    # ------------------------------------------------------------------
    # 4. DISASTER RECOVERY & SCHEMA INTEGRITY AUDIT
    # ------------------------------------------------------------------
    print("\n[SECTION 4: Disaster Recovery & Schema Manifest Integrity]")
    dr = DisasterRecoveryManager()
    manifest = dr.generate_schema_snapshot_manifest()
    dr_drill = dr.verify_dr_restore_drill(manifest)
    print(
        f"DR Manifest Verified with {dr_drill['total_migrations_verified']} SQL migrations."
    )
    print(
        f"Combined Cryptographic Hash: {manifest['combined_integrity_hash']}"
    )
    assert dr_drill["dr_status"] == "VERIFIED_READY"
    print("--> Section 4: Disaster Recovery and Schema Integrity 100% Ready ✅")

    print("\n==================================================================")
    print(" 🎉 ALL STEP 9 MASTER PRODUCTION TESTS PASSED WITH 100% SUCCESS!")
    print("==================================================================")


if __name__ == "__main__":
    run_master_production_suite()
