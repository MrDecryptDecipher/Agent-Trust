"""
Traffic analyzer — detects anomalies in east-west
agent-to-agent traffic patterns.
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from agent_trust.config import EastWestMonitorConfig
from agent_trust.types import AlertSeverity, MonitorEvent, TrustAlert

logger = logging.getLogger(__name__)


@dataclass
class AgentTrafficProfile:
    """Traffic profile for a single agent."""
    agent_id: str
    total_requests_sent: int = 0
    total_requests_received: int = 0
    unique_targets: set = field(default_factory=set)
    unique_sources: set = field(default_factory=set)
    avg_latency_ms: float = 0.0
    error_rate: float = 0.0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    last_active: float = field(default_factory=time.time)
    anomaly_score: float = 0.0


class TrafficAnalyzer:
    """
    Analyzes east-west agent traffic for anomalies.
    
    Detection methods:
    1. Volume anomalies: sudden spikes in traffic
    2. Pattern anomalies: unusual communication partners
    3. Latency anomalies: degraded performance
    4. Error rate anomalies: elevated failure rates
    5. Fan-out detection: agent contacting too many others
    
    Usage:
        analyzer = TrafficAnalyzer()
        
        for event in events:
            alerts = analyzer.analyze_event(event)
            for alert in alerts:
                print(f"ALERT: {alert.message}")
    """

    def __init__(
        self,
        config: Optional[EastWestMonitorConfig] = None,
    ):
        self._config = config or EastWestMonitorConfig()
        self._profiles: dict[str, AgentTrafficProfile] = {}
        self._time_windows: dict[str, list[float]] = defaultdict(list)
        self._latency_history: dict[str, list[float]] = defaultdict(list)
        self._alerts: list[TrustAlert] = []

    def analyze_event(
        self, event: MonitorEvent
    ) -> list[TrustAlert]:
        """
        Analyze a single traffic event for anomalies.
        Returns any alerts generated.
        """
        alerts = []
        
        # Update profiles
        self._update_profile(event)
        
        # Run anomaly detection
        alerts.extend(self._check_volume_anomaly(event))
        alerts.extend(self._check_fan_out(event))
        alerts.extend(self._check_latency_anomaly(event))
        alerts.extend(self._check_error_rate(event))
        
        # Compute anomaly score
        source_profile = self._profiles.get(event.source_agent_id)
        if source_profile:
            event.anomaly_score = source_profile.anomaly_score
        
        self._alerts.extend(alerts)
        return alerts

    def get_profile(
        self, agent_id: str
    ) -> Optional[AgentTrafficProfile]:
        """Get the traffic profile for an agent."""
        return self._profiles.get(agent_id)

    def get_all_profiles(self) -> dict[str, AgentTrafficProfile]:
        """Get all agent traffic profiles."""
        return dict(self._profiles)

    def get_traffic_matrix(self) -> dict[str, dict[str, int]]:
        """
        Build a traffic matrix showing communication patterns.
        Returns {source: {target: count}}.
        """
        matrix: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        
        for profile in self._profiles.values():
            for target in profile.unique_targets:
                matrix[profile.agent_id][target] += 1
        
        return {k: dict(v) for k, v in matrix.items()}

    def get_dashboard_data(self) -> dict:
        """Get data for the monitoring dashboard."""
        profiles = list(self._profiles.values())
        
        return {
            "total_agents_monitored": len(profiles),
            "total_alerts": len(self._alerts),
            "agents": [
                {
                    "agent_id": p.agent_id,
                    "requests_sent": p.total_requests_sent,
                    "requests_received": p.total_requests_received,
                    "unique_targets": len(p.unique_targets),
                    "avg_latency_ms": round(p.avg_latency_ms, 2),
                    "error_rate": round(p.error_rate, 4),
                    "anomaly_score": round(p.anomaly_score, 4),
                    "last_active": p.last_active,
                }
                for p in profiles
            ],
            "recent_alerts": [
                {
                    "alert_id": a.alert_id,
                    "severity": a.severity.value,
                    "type": a.alert_type,
                    "message": a.message,
                    "timestamp": a.timestamp,
                }
                for a in self._alerts[-20:]
            ],
        }

    def _update_profile(self, event: MonitorEvent) -> None:
        """Update traffic profiles based on an event."""
        # Source profile
        source = self._profiles.setdefault(
            event.source_agent_id,
            AgentTrafficProfile(agent_id=event.source_agent_id),
        )
        source.total_requests_sent += 1
        source.unique_targets.add(event.target_agent_id)
        source.total_bytes_sent += event.request_size_bytes
        source.last_active = event.timestamp

        # Target profile
        target = self._profiles.setdefault(
            event.target_agent_id,
            AgentTrafficProfile(agent_id=event.target_agent_id),
        )
        target.total_requests_received += 1
        target.unique_sources.add(event.source_agent_id)
        target.total_bytes_received += event.response_size_bytes
        target.last_active = event.timestamp

        # Update latency tracking
        if event.latency_ms > 0:
            self._latency_history[event.source_agent_id].append(
                event.latency_ms
            )
            history = self._latency_history[event.source_agent_id]
            source.avg_latency_ms = sum(history) / len(history)

        # Track request times for volume analysis
        self._time_windows[event.source_agent_id].append(event.timestamp)

        # Error rate
        if event.status_code >= 400:
            total = source.total_requests_sent
            source.error_rate = (
                source.error_rate * (total - 1) + 1.0
            ) / total

    def _check_volume_anomaly(
        self, event: MonitorEvent
    ) -> list[TrustAlert]:
        """Detect sudden volume spikes."""
        alerts = []
        agent_id = event.source_agent_id
        timestamps = self._time_windows.get(agent_id, [])
        
        if len(timestamps) < 10:
            return alerts
        
        # Count events in last 60 seconds
        now = time.time()
        recent = [t for t in timestamps if now - t < 60]
        historical_rate = len(timestamps) / max(
            1, (now - timestamps[0]) / 60
        )
        
        if len(recent) > historical_rate * 3 and len(recent) > 20:
            profile = self._profiles[agent_id]
            profile.anomaly_score = min(
                1.0, profile.anomaly_score + 0.3
            )
            
            alerts.append(TrustAlert(
                severity=AlertSeverity.WARNING,
                alert_type="volume_spike",
                message=(
                    f"Agent {agent_id} traffic spike: "
                    f"{len(recent)} requests/min vs "
                    f"historical {historical_rate:.1f}/min"
                ),
                source_agent_id=agent_id,
            ))
        
        return alerts

    def _check_fan_out(
        self, event: MonitorEvent
    ) -> list[TrustAlert]:
        """Detect agents contacting an unusual number of targets."""
        alerts = []
        profile = self._profiles.get(event.source_agent_id)
        if profile is None:
            return alerts
        
        num_targets = len(profile.unique_targets)
        
        # Alert if an agent contacts more than 20 unique targets
        if num_targets > 20 and num_targets % 5 == 0:
            profile.anomaly_score = min(
                1.0, profile.anomaly_score + 0.2
            )
            
            alerts.append(TrustAlert(
                severity=AlertSeverity.WARNING,
                alert_type="high_fan_out",
                message=(
                    f"Agent {event.source_agent_id} has contacted "
                    f"{num_targets} unique targets"
                ),
                source_agent_id=event.source_agent_id,
            ))
        
        return alerts

    def _check_latency_anomaly(
        self, event: MonitorEvent
    ) -> list[TrustAlert]:
        """Detect latency anomalies."""
        alerts = []
        history = self._latency_history.get(event.source_agent_id, [])
        
        if len(history) < 10:
            return alerts
        
        avg = sum(history) / len(history)
        std_dev = math.sqrt(
            sum((x - avg) ** 2 for x in history) / len(history)
        )
        
        # Alert if current latency is > 3 standard deviations
        if std_dev > 0 and event.latency_ms > avg + 3 * std_dev:
            alerts.append(TrustAlert(
                severity=AlertSeverity.INFO,
                alert_type="latency_anomaly",
                message=(
                    f"Agent {event.source_agent_id}: latency "
                    f"{event.latency_ms:.1f}ms vs avg {avg:.1f}ms "
                    f"(3σ = {avg + 3 * std_dev:.1f}ms)"
                ),
                source_agent_id=event.source_agent_id,
            ))
        
        return alerts

    def _check_error_rate(
        self, event: MonitorEvent
    ) -> list[TrustAlert]:
        """Detect elevated error rates."""
        alerts = []
        profile = self._profiles.get(event.source_agent_id)
        
        if profile is None or profile.total_requests_sent < 10:
            return alerts
        
        if profile.error_rate > 0.3:
            profile.anomaly_score = min(
                1.0, profile.anomaly_score + 0.25
            )
            
            alerts.append(TrustAlert(
                severity=AlertSeverity.CRITICAL,
                alert_type="high_error_rate",
                message=(
                    f"Agent {event.source_agent_id}: error rate "
                    f"{profile.error_rate:.1%} exceeds threshold"
                ),
                source_agent_id=event.source_agent_id,
            ))
        
        return alerts
