"""
Alert management and notification for TrustGraph.

Supports in-memory alerting and optional Redis pub/sub
for distributed alert propagation.
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from typing import Callable, Optional

from agent_trust.config import TrustGraphConfig
from agent_trust.types import AlertSeverity, TrustAlert

logger = logging.getLogger(__name__)

AlertCallback = Callable[[TrustAlert], None]


class AlertManager:
    """
    Manages trust alerts with filtering, aggregation,
    and optional Redis pub/sub distribution.
    
    Usage:
        manager = AlertManager()
        manager.on_alert(AlertSeverity.CRITICAL, my_handler)
        manager.publish(alert)
    """

    def __init__(self, config: Optional[TrustGraphConfig] = None):
        self._config = config or TrustGraphConfig()
        self._alerts: list[TrustAlert] = []
        self._callbacks: dict[AlertSeverity, list[AlertCallback]] = (
            defaultdict(list)
        )
        self._global_callbacks: list[AlertCallback] = []
        self._redis_client = None
        self._suppressed_types: set[str] = set()
        self._rate_limits: dict[str, float] = {}  # alert_type -> last_fired

    def on_alert(
        self,
        severity: Optional[AlertSeverity] = None,
        callback: Optional[AlertCallback] = None,
    ) -> None:
        """
        Register a callback for alerts.
        
        If severity is None, callback fires for ALL severities.
        """
        if callback is None:
            return
        if severity is None:
            self._global_callbacks.append(callback)
        else:
            self._callbacks[severity].append(callback)

    def publish(self, alert: TrustAlert) -> None:
        """Publish an alert to all registered handlers."""
        # Check suppression
        if alert.alert_type in self._suppressed_types:
            logger.debug(f"Alert suppressed: {alert.alert_type}")
            return

        # Rate limiting (max 1 alert of same type per second)
        now = time.time()
        last_fired = self._rate_limits.get(alert.alert_type, 0)
        if now - last_fired < 1.0:
            return
        self._rate_limits[alert.alert_type] = now

        # Store
        self._alerts.append(alert)

        # Fire severity-specific callbacks
        for callback in self._callbacks.get(alert.severity, []):
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

        # Fire global callbacks
        for callback in self._global_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Global alert callback error: {e}")

        # Redis pub/sub (optional)
        if self._config.enable_redis_pubsub and self._redis_client:
            self._publish_to_redis(alert)

        logger.log(
            self._severity_to_log_level(alert.severity),
            f"[{alert.severity.value.upper()}] {alert.alert_type}: "
            f"{alert.message}",
        )

    def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        alert_type: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 100,
    ) -> list[TrustAlert]:
        """Query stored alerts with filtering."""
        results = self._alerts
        
        if severity:
            results = [a for a in results if a.severity == severity]
        if alert_type:
            results = [a for a in results if a.alert_type == alert_type]
        if since:
            results = [a for a in results if a.timestamp >= since]
        
        return results[-limit:]

    def suppress_type(self, alert_type: str) -> None:
        """Suppress a specific alert type."""
        self._suppressed_types.add(alert_type)

    def unsuppress_type(self, alert_type: str) -> None:
        """Unsuppress a specific alert type."""
        self._suppressed_types.discard(alert_type)

    def clear(self) -> None:
        """Clear all stored alerts."""
        self._alerts.clear()

    def get_summary(self) -> dict:
        """Get alert summary statistics."""
        summary: dict[str, int] = defaultdict(int)
        for alert in self._alerts:
            summary[alert.severity.value] += 1
        
        return {
            "total": len(self._alerts),
            "by_severity": dict(summary),
            "suppressed_types": list(self._suppressed_types),
        }

    def connect_redis(self, redis_url: Optional[str] = None) -> bool:
        """Connect to Redis for pub/sub alert distribution."""
        try:
            import redis
            url = redis_url or self._config.redis_url
            self._redis_client = redis.from_url(url)
            self._redis_client.ping()
            logger.info(f"Connected to Redis at {url}")
            return True
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self._redis_client = None
            return False

    def _publish_to_redis(self, alert: TrustAlert) -> None:
        """Publish alert to Redis pub/sub channel."""
        if self._redis_client is None:
            return
        try:
            payload = json.dumps({
                "alert_id": alert.alert_id,
                "severity": alert.severity.value,
                "alert_type": alert.alert_type,
                "message": alert.message,
                "source_agent_id": alert.source_agent_id,
                "target_agent_id": alert.target_agent_id,
                "chain": alert.chain,
                "timestamp": alert.timestamp,
                "auto_action_taken": alert.auto_action_taken,
            })
            self._redis_client.publish(
                self._config.redis_channel, payload
            )
        except Exception as e:
            logger.error(f"Redis publish failed: {e}")

    @staticmethod
    def _severity_to_log_level(severity: AlertSeverity) -> int:
        mapping = {
            AlertSeverity.INFO: logging.INFO,
            AlertSeverity.WARNING: logging.WARNING,
            AlertSeverity.CRITICAL: logging.CRITICAL,
            AlertSeverity.EMERGENCY: logging.CRITICAL,
        }
        return mapping.get(severity, logging.WARNING)
