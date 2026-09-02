# app/services/alert_service.py - Alert & Deduplication Engine (Step 8 PRD v1.1)
import hashlib
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone, timedelta
from pydantic import UUID4

from app.models.monitoring import (
    AlertSeverity,
    AlertStatus,
    AlertEventInput,
    AlertRecord,
)
from app.models.notification import (
    NotificationEvent,
    NotificationPayload,
    NotificationChannel,
)
from app.services.notification_service import (
    notification_service,
    mask_pii_for_llm,
    mask_account_number,
)

logger = logging.getLogger(__name__)

# Anti-Alert-Storm Throttle Window (Seconds)
DEFAULT_SUPPRESSION_WINDOW_SEC = 300  # 5 minutes


def generate_canonical_fingerprint(
    company_id: UUID4,
    rule_id: str,
    rule_version: str = "v1.1",
    resource_identity: str = "GLOBAL",
    time_bucket: Optional[str] = None,
) -> str:
    """
    Deterministic, canonical, versioned, and collision-resistant fingerprint.
    PRD Requirement: sha256(rule_version:company_id:rule_id:resource_identity:time_bucket)
    """
    raw_components = [
        str(rule_version).strip().lower(),
        str(company_id).strip().lower(),
        str(rule_id).strip().upper(),
        str(resource_identity).strip().upper(),
        str(time_bucket or "NONE").strip().upper(),
    ]
    raw_string = ":".join(raw_components)
    return hashlib.sha256(raw_string.encode("utf-8")).hexdigest()


class AlertService:
    """
    Alert ingestion, atomic deduplication, and anti-storm notification throttling.
    """

    def __init__(
        self, suppression_window_sec: int = DEFAULT_SUPPRESSION_WINDOW_SEC
    ):
        self.suppression_window_sec = suppression_window_sec
        # In-memory store for active alerts (mirrors DB alerts table)
        self._alerts_store: Dict[str, AlertRecord] = {}
        self.total_events_processed: int = 0
        self.total_suppressed_events: int = 0

    def sanitize_alert_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Strictly masks all PII and sensitive data before storage or alerting."""
        sanitized = {}
        for k, v in payload.items():
            if isinstance(v, str):
                if any(
                    term in k.lower() for term in ["account", "bank", "iban"]
                ):
                    sanitized[k] = mask_account_number(v)
                else:
                    sanitized[k] = mask_pii_for_llm(v)
            elif isinstance(v, dict):
                sanitized[k] = self.sanitize_alert_payload(v)
            else:
                sanitized[k] = v
        return sanitized

    async def ingest_alert_event(
        self,
        event: AlertEventInput,
        rule_version: str = "v1.1",
        time_bucket: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Ingests monitoring alert with atomic deduplication.
        If duplicate within suppression window: increments count & updates timestamp.
        If new or outside window: creates alert & triggers Step 7 notification for CRITICAL.
        """
        self.total_events_processed += 1
        now = datetime.now(timezone.utc)

        resource_id = str(event.entity_id or event.entity_type or "GLOBAL")

        fingerprint = generate_canonical_fingerprint(
            company_id=event.company_id,
            rule_id=event.alert_type,
            rule_version=rule_version,
            resource_identity=resource_id,
            time_bucket=time_bucket,
        )

        sanitized_payload = self.sanitize_alert_payload(event.payload_sanitized)

        existing = self._alerts_store.get(fingerprint)

        if existing and existing.status == AlertStatus.FIRING:
            # Check suppression window
            time_diff = (now - existing.last_seen_at).total_seconds()
            if time_diff < self.suppression_window_sec:
                # Deduplicate: increment count, update last_seen_at, suppress notification
                existing.event_count += 1
                existing.last_seen_at = now
                self.total_suppressed_events += 1

                logger.info(
                    f"[ANTI_STORM_DEDUPLICATED] Fingerprint={fingerprint[:12]}... | "
                    f"Count={existing.event_count} | Type={event.alert_type}"
                )
                return {
                    "action": "DEDUPLICATED_AND_SUPPRESSED",
                    "alert": existing,
                    "event_count": existing.event_count,
                    "is_storm_suppressed": True,
                }

        # Create new or refreshed alert
        new_alert = AlertRecord(
            id=existing.id if existing else None,
            company_id=event.company_id,
            fingerprint=fingerprint,
            alert_type=event.alert_type,
            severity=event.severity,
            status=AlertStatus.FIRING,
            title=event.title,
            description=mask_pii_for_llm(event.description or ""),
            entity_type=event.entity_type,
            entity_id=event.entity_id,
            event_count=1,
            first_seen_at=now,
            last_seen_at=now,
            payload_sanitized=sanitized_payload,
        )
        self._alerts_store[fingerprint] = new_alert

        logger.info(
            f"[ALERT_FIRED] New Alert: Type={event.alert_type} | Severity={event.severity.value} | "
            f"Fingerprint={fingerprint[:12]}..."
        )

        # Step 7 Notification Integration for CRITICAL alerts
        if event.severity == AlertSeverity.CRITICAL:
            notification_payload = NotificationPayload(
                company_id=event.company_id,
                request_id=event.entity_id
                if event.entity_type == "REQUEST"
                else None,
                event_type=NotificationEvent.CRITICAL_FRAUD_BLOCK,
                channel=NotificationChannel.EMAIL,
                recipient="security-response@tenant.internal",
                vendor_name=sanitized_payload.get(
                    "vendor_name", "Monitored Vendor"
                ),
                masked_account_number=sanitized_payload.get(
                    "masked_account_number"
                ),
                metadata={
                    "alert_title": event.title,
                    "fingerprint": fingerprint,
                },
            )
            # Dispatch decoupled fire-and-forget notification via Step 7
            notification_service.dispatch_background(notification_payload)

        return {
            "action": "NEW_ALERT_CREATED",
            "alert": new_alert,
            "event_count": 1,
            "is_storm_suppressed": False,
        }

    def get_active_alerts(
        self, company_id: Optional[UUID4] = None
    ) -> List[AlertRecord]:
        alerts = list(self._alerts_store.values())
        if company_id:
            alerts = [a for a in alerts if a.company_id == company_id]
        return [a for a in alerts if a.status == AlertStatus.FIRING]

    def resolve_alert(
        self, fingerprint: str, company_id: UUID4
    ) -> Optional[AlertRecord]:
        alert = self._alerts_store.get(fingerprint)
        if alert and alert.company_id == company_id:
            alert.status = AlertStatus.RESOLVED
            alert.last_seen_at = datetime.now(timezone.utc)
            return alert
        return None


# Global instance
alert_service = AlertService()
