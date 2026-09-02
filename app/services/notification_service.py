# app/services/notification_service.py - Hardened Notification System & Delivery Ledger (Step 7 PRD v1.1)
import os
import re
import time
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone, timedelta
from pydantic import UUID4

from app.models.notification import (
    NotificationChannel,
    NotificationEvent,
    NotificationStatus,
    NotificationPayload,
    NotificationDeliveryRecord,
    NON_OPT_OUT_EVENTS,
)

logger = logging.getLogger(__name__)


# --- Core PII Masking Utilities ---
def mask_account_number(account_number: str) -> str:
    if not account_number:
        return account_number
    clean_number = re.sub(r"[\s\-]", "", str(account_number))
    return re.sub(
        r"\b(\d{4})\d{4,10}(\d{4})\b", r"\g<1>XXXX\g<2>", clean_number
    )


def mask_pii_for_llm(text: str) -> str:
    if not text:
        return text
    # Bank account
    text = re.sub(
        r"\b(\d{4})[\s\-]?(\d{4,10})[\s\-]?(\d{4})\b",
        r"\g<1>XXXX\g<3>",
        text,
    )
    # IFSC
    text = re.sub(
        r"\b([A-Z]{4})0[A-Z0-9]{6}\b",
        r"\g<1>0XXXXXX",
        text,
    )
    # PAN
    text = re.sub(
        r"\b([A-Z]{5})\d{4}([A-Z])\b",
        r"\g<1>XXXX\g<2>",
        text,
    )
    # GSTIN
    text = re.sub(
        r"\b(\d{2})([A-Z]{5})\d{4}([A-Z])(\d)([A-Z0-9])\b",
        r"\g<1>\g<2>XXXX\g<3>\g<4>\g<5>",
        text,
    )
    return text


# --- Notification Templates ---
TEMPLATES: Dict[str, Dict[str, str]] = {
    NotificationEvent.REQUEST_INTAKED.value: {
        "subject": "[SECURITY ALERT] Bank Detail Change Request Received: {vendor_name}",
        "body": (
            "A bank account change request has been initiated for vendor: {vendor_name}.\n"
            "Request Reference: {request_id}\n"
            "Masked Account: {masked_account_number}\n"
            "Status: PENDING MAKER OUT-OF-BAND PHONE VERIFICATION.\n\n"
            "If you did not authorize this change, contact security immediately."
        ),
    },
    NotificationEvent.CRITICAL_FRAUD_BLOCK.value: {
        "subject": "[CRITICAL FRAUD BLOCK] Spoofed Bank Change Request Blocked: {vendor_name}",
        "body": (
            "CRITICAL ALERT: An unauthorized or spoofed change request for {vendor_name} "
            "has been BLOCKED by the Deterministic Risk Engine.\n"
            "Reason: Email authentication failure / SPF-DKIM-DMARC Spoof.\n"
            "No changes were applied to vendor records."
        ),
    },
    NotificationEvent.MAKER_VERIFIED.value: {
        "subject": "[ACTION REQUIRED] Dual-Control Checker Review: {vendor_name}",
        "body": (
            "Out-of-band voice verification completed by Maker for vendor: {vendor_name}.\n"
            "Representative Spoken: {vendor_rep_name}\n"
            "Status: PENDING CHECKER APPROVAL (Step-Up MFA Required).\n"
            "Please log in to the Checker Console to authorize."
        ),
    },
    NotificationEvent.CHECKER_APPROVED_COOLING_OFF.value: {
        "subject": "[NOTICE] Bank Change Authorized — 48-Hour Cooling-Off Period: {vendor_name}",
        "body": (
            "Dual-control approval completed for vendor: {vendor_name}.\n"
            "Masked Account: {masked_account_number}\n"
            "Cooling-Off Duration: 48 Hours\n"
            "Authoritative Effective Date: {effective_date}\n\n"
            "Bank details will become active only after the 48-hour cooling-off period."
        ),
    },
    NotificationEvent.COOLING_OFF_REMINDER_24H.value: {
        "subject": "[REMINDER] 24 Hours Remaining in Cooling-Off Period: {vendor_name}",
        "body": (
            "REMINDER: The bank account update for vendor {vendor_name} is in its final 24 hours of cooling-off.\n"
            "Authoritative Effective Date: {effective_date}\n"
            "Masked Account: {masked_account_number}\n"
            "If an emergency hold is required, finance managers must escalate immediately."
        ),
    },
    NotificationEvent.COOLING_OFF_COMPLETED.value: {
        "subject": "[ACTIVE] Vendor Bank Account Update Activated: {vendor_name}",
        "body": (
            "The 48-hour cooling-off period for vendor {vendor_name} has concluded.\n"
            "Updated bank account details are now active in the system."
        ),
    },
    NotificationEvent.REQUEST_REJECTED.value: {
        "subject": "[REJECTED] Bank Change Request Rejected: {vendor_name}",
        "body": (
            "The bank change request for {vendor_name} (Ref: {request_id}) "
            "has been REJECTED by Checker authorization."
        ),
    },
}


# --- Provider Abstraction Layer ---
class BaseNotificationAdapter(ABC):

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @abstractmethod
    async def send(
        self, recipient: str, subject: str, body: str, metadata: Dict[str, Any]
    ) -> bool:
        pass


class ConsoleMockAdapter(BaseNotificationAdapter):

    @property
    def provider_name(self) -> str:
        return "CONSOLE_MOCK"

    async def send(
        self, recipient: str, subject: str, body: str, metadata: Dict[str, Any]
    ) -> bool:
        logger.info(
            f"[NOTIFICATION DISPATCH] Provider=CONSOLE_MOCK | To={recipient} | Subject='{subject}'"
        )
        return True


class SmtpEmailAdapter(BaseNotificationAdapter):

    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "localhost")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.sender_email = os.getenv(
            "SMTP_FROM_EMAIL", "security@fraudguardian.internal"
        )

    @property
    def provider_name(self) -> str:
        return "SMTP_EMAIL"

    async def send(
        self, recipient: str, subject: str, body: str, metadata: Dict[str, Any]
    ) -> bool:
        try:
            if self.smtp_host in ("localhost", "", "mock"):
                logger.info(
                    f"[SMTP MOCK DISPATCH] To={recipient} | Subject='{subject}'"
                )
                return True

            import aiosmtplib
            from email.message import EmailMessage

            msg = EmailMessage()
            msg["From"] = self.sender_email
            msg["To"] = recipient
            msg["Subject"] = subject
            msg.set_content(body)

            await aiosmtplib.send(
                msg,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                start_tls=True,
            )
            return True
        except Exception as e:
            logger.error(
                f"[SMTP_DISPATCH_ERROR] Failed to send email to {recipient}: {str(e)}"
            )
            return False


class TwilioSmsAdapter(BaseNotificationAdapter):
    """SMS Provider adapter (Backend-only secrets, provider agnostic)."""

    def __init__(self):
        self.account_sid = os.getenv("TWILIO_ACCOUNT_SID", "mock_sid")
        self.auth_token = os.getenv("TWILIO_AUTH_TOKEN", "mock_token")
        self.from_phone = os.getenv("TWILIO_FROM_PHONE", "+15005550006")

    @property
    def provider_name(self) -> str:
        return "TWILIO_SMS"

    async def send(
        self, recipient: str, subject: str, body: str, metadata: Dict[str, Any]
    ) -> bool:
        logger.info(
            f"[SMS DISPATCH] Provider=TWILIO_SMS | To={recipient} | Message='{subject} - {body[:60]}...'"
        )
        return True


class WebhookAdapter(BaseNotificationAdapter):
    """Webhook / SIEM notification adapter."""

    @property
    def provider_name(self) -> str:
        return "SIEM_WEBHOOK"

    async def send(
        self, recipient: str, subject: str, body: str, metadata: Dict[str, Any]
    ) -> bool:
        logger.info(
            f"[WEBHOOK DISPATCH] Provider=SIEM_WEBHOOK | Endpoint={recipient} | Subject='{subject}'"
        )
        return True


# --- Strictly Append-Only Immutable Delivery Ledger ---
class NotificationDeliveryLedger:
    """
    Immutable audit ledger for dispatch attempts.
    PRD Requirement: Append-only ledger. UPDATE and DELETE are permanently prohibited.
    """

    def __init__(self):
        self._records: List[NotificationDeliveryRecord] = []

    def record_attempt(
        self,
        company_id: UUID4,
        notification_id: Optional[UUID4],
        channel: NotificationChannel,
        provider_name: str,
        attempt_number: int,
        status: NotificationStatus,
        duration_ms: int,
        safe_error: Optional[str] = None,
    ) -> NotificationDeliveryRecord:
        record = NotificationDeliveryRecord(
            company_id=company_id,
            notification_id=notification_id,
            channel=channel,
            provider_name=provider_name,
            attempt_number=attempt_number,
            status=status,
            duration_ms=duration_ms,
            safe_error=safe_error,
        )
        self._records.append(record)
        return record

    def get_attempts_for_notification(
        self, notification_id: UUID4
    ) -> List[NotificationDeliveryRecord]:
        return [
            r for r in self._records if r.notification_id == notification_id
        ]

    # Explicit enforcement of immutability
    def update_record(self, record_id: Any, **kwargs):
        raise PermissionError(
            "IMMUTABILITY_VIOLATION: Notification delivery audit ledger is strictly append-only. UPDATE operations are rejected."
        )

    def delete_record(self, record_id: Any):
        raise PermissionError(
            "IMMUTABILITY_VIOLATION: Notification delivery audit ledger is strictly append-only. DELETE operations are rejected."
        )


# --- Core Notification Service ---
class NotificationService:

    def __init__(
        self,
        default_adapter: Optional[BaseNotificationAdapter] = None,
        ledger: Optional[NotificationDeliveryLedger] = None,
    ):
        self.adapters: Dict[NotificationChannel, BaseNotificationAdapter] = {
            NotificationChannel.EMAIL: default_adapter or SmtpEmailAdapter(),
            NotificationChannel.SMS: TwilioSmsAdapter(),
            NotificationChannel.WEBHOOK: WebhookAdapter(),
        }
        self.ledger = ledger or NotificationDeliveryLedger()

    def register_adapter(
        self, channel: NotificationChannel, adapter: BaseNotificationAdapter
    ):
        """Allows plugging in custom provider adapters dynamically."""
        self.adapters[channel] = adapter

    def is_notification_allowed(
        self,
        event_type: NotificationEvent,
        user_preferences: Optional[Dict[str, bool]] = None,
    ) -> bool:
        """
        PRD Requirement: Security-critical notifications cannot be opted out.
        """
        if event_type in NON_OPT_OUT_EVENTS:
            return True  # Non-opt-outable

        if user_preferences and not user_preferences.get(
            event_type.value, True
        ):
            return False

        return True

    def sanitize_and_render(
        self, payload: NotificationPayload
    ) -> Dict[str, str]:
        template_config = TEMPLATES.get(
            payload.event_type.value,
            {
                "subject": "[NOTIFICATION] Vendor Security Update: {vendor_name}",
                "body": "Security event occurred for vendor: {vendor_name}",
            },
        )

        masked_acct = (
            mask_account_number(payload.masked_account_number)
            if payload.masked_account_number
            else "N/A"
        )

        context = {
            "vendor_name": payload.vendor_name,
            "request_id": str(payload.request_id)
            if payload.request_id
            else "N/A",
            "masked_account_number": masked_acct,
            "cooling_off_hours": str(payload.cooling_off_hours or 48),
            "effective_date": str(payload.effective_date or "N/A"),
            "vendor_rep_name": payload.metadata.get(
                "vendor_rep_name", "Pre-registered Vendor Rep"
            ),
        }

        subject = template_config["subject"].format(**context)
        raw_body = template_config["body"].format(**context)

        # Extra defense-in-depth PII masking
        body = mask_pii_for_llm(raw_body)
        return {"subject": subject, "body": body}

    async def dispatch_with_retry(
        self,
        payload: NotificationPayload,
        max_retries: int = 3,
        user_preferences: Optional[Dict[str, bool]] = None,
    ) -> Dict[str, Any]:
        """
        Dispatches notification with bounded exponential retry and immutable ledger recording.
        FAIL-SAFE: Delivery failure NEVER alters financial workflow state.
        """
        if not self.is_notification_allowed(
            payload.event_type, user_preferences
        ):
            logger.info(
                f"[NOTIFICATION_OPTED_OUT] Event={payload.event_type.value} was opted out"
            )
            return {
                "status": "OPTED_OUT",
                "message": "User opted out of non-critical notification",
            }

        rendered = self.sanitize_and_render(payload)
        adapter = self.adapters.get(
            payload.channel, self.adapters[NotificationChannel.EMAIL]
        )
        provider_name = adapter.provider_name

        recipient_masked = (
            re.sub(r"(?<=.{3}).(?=.*@)", "*", payload.recipient)
            if "@" in payload.recipient
            else payload.recipient
        )

        attempt = 0
        backoff_sec = 0.05
        last_error = None
        attempt_records = []

        while attempt < max_retries:
            attempt += 1
            start_time = time.perf_counter()
            try:
                success = await adapter.send(
                    recipient=payload.recipient,
                    subject=rendered["subject"],
                    body=rendered["body"],
                    metadata=payload.metadata,
                )
                duration_ms = int((time.perf_counter() - start_time) * 1000)

                if success:
                    # Record successful attempt in immutable delivery ledger
                    record = self.ledger.record_attempt(
                        company_id=payload.company_id,
                        notification_id=payload.request_id,
                        channel=payload.channel,
                        provider_name=provider_name,
                        attempt_number=attempt,
                        status=NotificationStatus.SENT,
                        duration_ms=duration_ms,
                    )
                    attempt_records.append(record)

                    logger.info(
                        f"[NOTIFICATION_SUCCESS] Event={payload.event_type.value} | "
                        f"Company={payload.company_id} | Provider={provider_name} | "
                        f"Attempt={attempt} | Duration={duration_ms}ms"
                    )
                    return {
                        "status": NotificationStatus.SENT.value,
                        "provider": provider_name,
                        "attempts": attempt,
                        "recipient_masked": recipient_masked,
                        "sent_at": datetime.now(timezone.utc).isoformat(),
                        "delivery_ledger_id": str(record.id)
                        if record.id
                        else None,
                    }
                else:
                    raise RuntimeError("Provider returned failure status")

            except Exception as ex:
                duration_ms = int((time.perf_counter() - start_time) * 1000)
                last_error = str(ex)
                safe_err = f"{type(ex).__name__}: {last_error}"

                # Record failed attempt in immutable delivery ledger
                record = self.ledger.record_attempt(
                    company_id=payload.company_id,
                    notification_id=payload.request_id,
                    channel=payload.channel,
                    provider_name=provider_name,
                    attempt_number=attempt,
                    status=NotificationStatus.FAILED
                    if attempt == max_retries
                    else NotificationStatus.RETRYING,
                    duration_ms=duration_ms,
                    safe_error=safe_err,
                )
                attempt_records.append(record)

                logger.warning(
                    f"[NOTIFICATION_RETRY] Attempt {attempt}/{max_retries} failed for {recipient_masked}: {safe_err}"
                )

            if attempt < max_retries:
                await asyncio.sleep(backoff_sec)
                backoff_sec *= 2

        # All retries exhausted
        logger.error(
            f"[NOTIFICATION_FAILED] Final failure for event {payload.event_type.value} to {recipient_masked}: {last_error}"
        )
        return {
            "status": NotificationStatus.FAILED.value,
            "provider": provider_name,
            "attempts": attempt,
            "recipient_masked": recipient_masked,
            "last_error": last_error,
            "deliveries_recorded": len(attempt_records),
        }

    def dispatch_background(self, payload: NotificationPayload):
        """
        Fire-and-forget background execution.
        Decouples email delivery from synchronous caller flow.
        """
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.dispatch_with_retry(payload))
        except RuntimeError:
            asyncio.run(self.dispatch_with_retry(payload))

    # --- Backend-Authoritative 48-Hour Cooling-Off Reminder Evaluator ---
    def evaluate_cooling_off_reminder(
        self,
        effective_date_iso: str,
        current_time: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        PRD Requirement: Backend-authoritative 48-hour reminder calculation.
        Derives timing strictly from the authoritative database effective_date.
        """
        now = current_time or datetime.now(timezone.utc)
        eff_date = datetime.fromisoformat(
            effective_date_iso.replace("Z", "+00:00")
        )

        remaining_seconds = (eff_date - now).total_seconds()
        remaining_hours = remaining_seconds / 3600.0

        if remaining_seconds <= 0:
            return {
                "action": "TRIGGER_ACTIVATION_COMPLETE",
                "event_type": NotificationEvent.COOLING_OFF_COMPLETED,
                "remaining_hours": 0.0,
                "is_expired": True,
            }
        elif remaining_hours <= 24.0:
            return {
                "action": "TRIGGER_24H_REMINDER",
                "event_type": NotificationEvent.COOLING_OFF_REMINDER_24H,
                "remaining_hours": round(remaining_hours, 2),
                "is_expired": False,
            }
        else:
            return {
                "action": "IN_COOLING_OFF",
                "event_type": NotificationEvent.CHECKER_APPROVED_COOLING_OFF,
                "remaining_hours": round(remaining_hours, 2),
                "is_expired": False,
            }


# Global instance
notification_service = NotificationService()
