"""
TrustGraph — Cascading Attack Detector

Solves Gap 1: The Cascading Trust Attack.

Builds a live directed graph of every agent-to-agent call.
Uses graph traversal to detect transitive trust inheritance
beyond the depth you set. Auto-revokes delegation chains
on violation.
"""

from agent_trust.trust_graph.graph import TrustGraph
from agent_trust.trust_graph.detector import CascadeDetector
from agent_trust.trust_graph.alerts import AlertManager

__all__ = ["TrustGraph", "CascadeDetector", "AlertManager"]
