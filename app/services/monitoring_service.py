# app/services/monitoring_service.py - System Telemetry & Anomaly Monitoring (Step 8 PRD v1.1)
import logging
import asyncio
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone, timedelta
from pydantic import UUID4
import uuid

from app.models.monitoring import (
    AlertSeverity,
    AlertEventInput,
    SystemMetricsSummary,
)
from app.services.alert_service import alert_service
from app.services.incident_service import incident_service

logger = logging.getLogger(__name__)


class MonitoringService:
    """
    Continuous monitoring, velocity anomaly detection, and telemetry aggregation.
    """

    def __init__(self):
        # In-memory window for tracking entity velocities (entity_id -> list of timestamps)
        self._velocity_tracker: Dict[str, List[datetime]] = {}

    def record_request_velocity(
        self,
        company_id: UUID4,
        entity_key: str,
        threshold_count: int = 3,
        window_hours: int = 24,
    ) -> Optional[Dict[str, Any]]:
        """
        Monitors velocity of requests (IP, Vendor ID, Domain).
        If velocity exceeds threshold within window, automatically fires VELOCITY_ANOMALY alert.
        """
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=window_hours)

        if entity_key not in self._velocity_tracker:
            self._velocity_tracker[entity_key] = []

        # Prune old timestamps
        self._velocity_tracker[entity_key] = [
            ts for ts in self._velocity_tracker[entity_key] if ts > cutoff
        ]
        self._velocity_tracker[entity_key].append(now)

        current_count = len(self._velocity_tracker[entity_key])

        if current_count >= threshold_count:
            # Trigger Velocity Anomaly Alert
            alert_input = AlertEventInput(
                company_id=company_id,
                alert_type="VELOCITY_ANOMALY",
                severity=AlertSeverity.HIGH
                if current_count < 5
                else AlertSeverity.CRITICAL,
                title=f"Velocity Anomaly Detected: {entity_key}",
                description=f"Detected {current_count} requests for {entity_key} within {window_hours} hours. Possible time-bomb/brute force attempt.",
                entity_type="VELOCITY_TARGET",
                payload_sanitized={
                    "entity_key": entity_key,
                    "event_count": current_count,
                    "window_hours": window_hours,
                },
            )
            # Safe async task or sync fallback
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(alert_service.ingest_alert_event(alert_input))
            except RuntimeError:
                asyncio.run(alert_service.ingest_alert_event(alert_input))

            logger.warning(
                f"[VELOCITY_ANOMALY_TRIGGERED] Key={entity_key} | Count={current_count} in {window_hours}h"
            )
            return {
                "anomaly_detected": True,
                "current_count": current_count,
                "threshold": threshold_count,
                "window_hours": window_hours,
            }

        return {
            "anomaly_detected": False,
            "current_count": current_count,
            "threshold": threshold_count,
        }

    def get_system_metrics(
        self, company_id: Optional[UUID4] = None
    ) -> SystemMetricsSummary:
        """Computes live system telemetry and health metrics."""
        active_alerts = alert_service.get_active_alerts(company_id)
        incidents = incident_service.list_incidents(company_id)
        open_incidents = [
            i for i in incidents if i.status.value in ["OPEN", "INVESTIGATING"]
        ]

        total_proc = alert_service.total_events_processed
        suppressed = alert_service.total_suppressed_events
        suppression_rate = (
            (suppressed / total_proc * 100.0) if total_proc > 0 else 0.0
        )

        return SystemMetricsSummary(
            timestamp=datetime.now(timezone.utc),
            active_alerts_count=len(active_alerts),
            open_incidents_count=len(open_incidents),
            high_risk_requests_last_24h=len(
                [
                    a
                    for a in active_alerts
                    if a.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL)
                ]
            ),
            system_health_status="HEALTHY"
            if len(
                [a for a in active_alerts if a.severity == AlertSeverity.CRITICAL]
            )
            == 0
            else "DEGRADED",
            anti_storm_suppression_rate=round(suppression_rate, 2),
        )


# Global instance
monitoring_service = MonitoringService()
