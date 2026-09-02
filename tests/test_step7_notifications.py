# tests/test_step7_notifications.py - Comprehensive Step 7 Verification Suite with Immutability Proofs
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)

import asyncio
import uuid
from datetime import datetime, timezone, timedelta
from app.models.notification import (
    NotificationChannel,
    NotificationEvent,
    NotificationPayload,
    NotificationStatus,
    NON_OPT_OUT_EVENTS,
)
from app.services.notification_service import (
    NotificationService,
    ConsoleMockAdapter,
    TwilioSmsAdapter,
    WebhookAdapter,
    BaseNotificationAdapter,
)


def run_all_tests():
    print("===============================================================")
    print(" STEP 7 FINAL SECURITY GATE — NOTIFICATION & IMMUTABILITY AUDIT")
    print("===============================================================")

    svc = NotificationService(default_adapter=ConsoleMockAdapter())
    req_id = uuid.uuid4()
    comp_id = uuid.uuid4()

    # Proof 1: PII Masking & Data Sanitization
    print("\n[PROOF 1: PII Masking & Data Sanitization]")
    payload = NotificationPayload(
        company_id=comp_id,
        request_id=req_id,
        event_type=NotificationEvent.REQUEST_INTAKED,
        recipient="audit-lead@tenant-finance.com",
        vendor_name="Bharat Heavy Engineering Ltd",
        masked_account_number="98765432109876",
    )
    rendered = svc.sanitize_and_render(payload)
    print("Subject:", rendered["subject"])
    print("Rendered Body:\n", rendered["body"])
    assert "9876XXXX9876" in rendered["body"]
    assert "98765432109876" not in rendered["body"]
    print("--> PROOF 1: VERIFIED (PII strictly masked, raw account never exposed)")

    # Proof 2: Successful INSERT into Immutable Delivery-Attempt Ledger
    print("\n[PROOF 2: Successful INSERT / Append into Delivery Ledger]")

    async def test_insert():
        res = await svc.dispatch_with_retry(payload)
        assert res["status"] == NotificationStatus.SENT.value
        records = svc.ledger.get_attempts_for_notification(req_id)
        assert len(records) >= 1
        rec = records[0]
        print(
            f"Successfully Inserted Ledger Record: Channel={rec.channel}, Provider={rec.provider_name}, Attempt={rec.attempt_number}, Status={rec.status}, Duration={rec.duration_ms}ms"
        )
        assert rec.status == NotificationStatus.SENT
        assert rec.provider_name == "CONSOLE_MOCK"

    asyncio.run(test_insert())
    print("--> PROOF 2: VERIFIED (Delivery attempt successfully appended)")

    # Proof 3: UPDATE Rejection on Immutable Delivery Ledger
    print("\n[PROOF 3: UPDATE Rejection on Immutable Delivery Ledger]")
    records = svc.ledger.get_attempts_for_notification(req_id)
    assert len(records) >= 1
    target_rec_id = records[0].id
    try:
        svc.ledger.update_record(target_rec_id, status=NotificationStatus.FAILED)
        assert False, "UPDATE should have been rejected with PermissionError"
    except PermissionError as pe:
        print(f"UPDATE Rejection Caught: {pe}")
        assert "IMMUTABILITY_VIOLATION" in str(pe)
    print("--> PROOF 3: VERIFIED (UPDATE operations are strictly rejected)")

    # Proof 4: DELETE Rejection on Immutable Delivery Ledger
    print("\n[PROOF 4: DELETE Rejection on Immutable Delivery Ledger]")
    try:
        svc.ledger.delete_record(target_rec_id)
        assert False, "DELETE should have been rejected with PermissionError"
    except PermissionError as pe:
        print(f"DELETE Rejection Caught: {pe}")
        assert "IMMUTABILITY_VIOLATION" in str(pe)
    print("--> PROOF 4: VERIFIED (DELETE operations are strictly rejected)")

    # Proof 5: Bounded Retry & Safe Error Handling
    print("\n[PROOF 5: Bounded Exponential Retries & Safe Error Ledger]")

    class MockFailingAdapter(BaseNotificationAdapter):

        def __init__(self):
            self.tries = 0

        @property
        def provider_name(self):
            return "SMTP_FAILING_MOCK"

        async def send(self, recipient, subject, body, metadata):
            self.tries += 1
            raise ConnectionResetError("Simulated SMTP Socket Reset by Peer")

    fail_adapter = MockFailingAdapter()
    fail_svc = NotificationService(default_adapter=fail_adapter)
    fail_req_id = uuid.uuid4()
    fail_payload = NotificationPayload(
        company_id=comp_id,
        request_id=fail_req_id,
        event_type=NotificationEvent.MAKER_VERIFIED,
        recipient="checker@tenant.com",
        vendor_name="Vendor Corp",
    )

    async def test_fail_retry():
        res = await fail_svc.dispatch_with_retry(fail_payload, max_retries=3)
        assert res["status"] == NotificationStatus.FAILED.value
        assert res["attempts"] == 3
        fail_records = fail_svc.ledger.get_attempts_for_notification(fail_req_id)
        assert len(fail_records) == 3
        for r in fail_records:
            print(
                f"Attempt {r.attempt_number}: Status={r.status.value}, Error={r.safe_error}"
            )
        assert fail_records[-1].status == NotificationStatus.FAILED
        assert "ConnectionResetError" in fail_records[-1].safe_error

    asyncio.run(test_fail_retry())
    print(
        "--> PROOF 5: VERIFIED (3 Bounded retries executed, safe errors logged in ledger)"
    )

    # Proof 6: Backend-Authoritative 48-Hour Cooling-Off Reminder
    print(
        "\n[PROOF 6: Backend-Authoritative 48-Hour Cooling-Off Calculation]"
    )
    now_utc = datetime.now(timezone.utc)
    # Case A: 40 hours remaining (In cooling off)
    eff_40h = (now_utc + timedelta(hours=40)).isoformat()
    eval_40h = svc.evaluate_cooling_off_reminder(eff_40h, current_time=now_utc)
    print("Case A (40h left):", eval_40h)
    assert eval_40h["action"] == "IN_COOLING_OFF"
    assert eval_40h["remaining_hours"] > 24

    # Case B: 18 hours remaining (Triggers 24H Reminder)
    eff_18h = (now_utc + timedelta(hours=18)).isoformat()
    eval_18h = svc.evaluate_cooling_off_reminder(eff_18h, current_time=now_utc)
    print("Case B (18h left):", eval_18h)
    assert eval_18h["action"] == "TRIGGER_24H_REMINDER"
    assert eval_18h["event_type"] == NotificationEvent.COOLING_OFF_REMINDER_24H

    # Case C: 0 hours remaining (Cooling-off completed / Activation)
    eff_past = (now_utc - timedelta(minutes=5)).isoformat()
    eval_past = svc.evaluate_cooling_off_reminder(
        eff_past, current_time=now_utc
    )
    print("Case C (Expired):", eval_past)
    assert eval_past["action"] == "TRIGGER_ACTIVATION_COMPLETE"
    assert eval_past["event_type"] == NotificationEvent.COOLING_OFF_COMPLETED
    print(
        "--> PROOF 6: VERIFIED (Timing derived strictly from authoritative effective_date)"
    )

    # Proof 7: Provider Abstraction & Dynamic Registration
    print("\n[PROOF 7: Provider Abstraction Layer]")
    print("Registered Channels in Notification Service:")
    for channel, adapter in svc.adapters.items():
        print(
            f" - Channel: {channel.value} --> Provider Adapter: {adapter.provider_name}"
        )
    assert NotificationChannel.EMAIL in svc.adapters
    assert NotificationChannel.SMS in svc.adapters
    assert NotificationChannel.WEBHOOK in svc.adapters
    print(
        "--> PROOF 7: VERIFIED (Pluggable provider-agnostic adapter architecture)"
    )

    # Proof 8: Non-Opt-Out Security Preference Enforcement
    print("\n[PROOF 8: Security Preferences & Non-Opt-Out Enforcement]")
    user_wants_opt_out = {event.value: False for event in NotificationEvent}
    for event in NON_OPT_OUT_EVENTS:
        allowed = svc.is_notification_allowed(
            event, user_preferences=user_wants_opt_out
        )
        assert allowed == True, f"{event.value} must NOT be opt-outable"
    print(
        f"Enforced non-opt-out status on all {len(NON_OPT_OUT_EVENTS)} security critical events."
    )
    print("--> PROOF 8: VERIFIED (Security-critical alerts cannot be disabled)")

    # Proof 9: All 7 Notification Event Templates
    print("\n[PROOF 9: All Notification Events Template Verification]")
    for event in NotificationEvent:
        p = NotificationPayload(
            company_id=comp_id,
            event_type=event,
            recipient="test@domain.com",
            vendor_name="Vendor " + event.value,
            effective_date="2026-09-04T12:00:00Z",
            cooling_off_hours=48,
        )
        r = svc.sanitize_and_render(p)
        assert len(r["subject"]) > 5
        assert len(r["body"]) > 15
        print(f" - Event [{event.value}]: Subject=\"{r['subject'][:50]}...\"")
    print("--> PROOF 9: VERIFIED (All event templates verified)")

    print("\n===============================================================")
    print(
        " ALL FINAL IMMUTABILITY & AUDIT PROOFS PASSED WITH 100% SUCCESS!"
    )
    print("===============================================================")


if __name__ == "__main__":
    run_all_tests()
