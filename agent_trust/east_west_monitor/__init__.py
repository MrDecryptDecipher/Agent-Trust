"""
EastWestMonitor — Visibility Into Agent-to-Agent Traffic

Solves Gap 3: Nobody Is Watching.

A cloud-agnostic SDK shim that intercepts all A2A calls and
feeds them into a unified dashboard. Works without modifying
agent code.
"""

from agent_trust.east_west_monitor.interceptor import A2AInterceptor
from agent_trust.east_west_monitor.analyzer import TrafficAnalyzer
from agent_trust.east_west_monitor.store import EventStore

__all__ = ["A2AInterceptor", "TrafficAnalyzer", "EventStore"]
