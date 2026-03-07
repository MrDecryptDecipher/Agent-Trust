"""
Tests for TrustGraph module.
"""

import pytest
from agent_trust.trust_graph import TrustGraph, CascadeDetector
from agent_trust.config import TrustGraphConfig
from agent_trust.types import AgentIdentity, TrustLevel, TokenScope
from agent_trust.exceptions import AgentNotFoundError, CascadingTrustViolation


def _make_identity(agent_id: str, org: str = "test") -> AgentIdentity:
    """Helper to create a test identity."""
    return AgentIdentity(
        agent_id=agent_id,
        public_key=b"test-key",
        system_prompt_hash="abc",
        tool_list_hash="def",
        organization=org,
    )


class TestTrustGraph:
    """Test trust graph operations."""

    def test_add_agent(self):
        graph = TrustGraph()
        graph.add_agent(_make_identity("a"))
        assert graph.agent_count == 1

    def test_add_trust_edge(self):
        graph = TrustGraph()
        graph.add_agent(_make_identity("a"))
        graph.add_agent(_make_identity("b"))
        
        edge = graph.add_trust_edge("a", "b", TrustLevel.VERIFIED)
        assert edge.trust_level == TrustLevel.VERIFIED
        assert graph.edge_count == 1

    def test_trust_level_query(self):
        graph = TrustGraph()
        graph.add_agent(_make_identity("a"))
        graph.add_agent(_make_identity("b"))
        graph.add_trust_edge("a", "b", TrustLevel.TRUSTED)
        
        assert graph.get_trust_level("a", "b") == TrustLevel.TRUSTED
        assert graph.get_trust_level("b", "a") == TrustLevel.UNTRUSTED

    def test_remove_agent(self):
        graph = TrustGraph()
        graph.add_agent(_make_identity("a"))
        graph.add_agent(_make_identity("b"))
        graph.add_trust_edge("a", "b")
        
        graph.remove_agent("b")
        assert graph.agent_count == 1
        assert graph.edge_count == 0

    def test_find_trust_chains(self):
        graph = TrustGraph()
        for name in ["a", "b", "c", "d"]:
            graph.add_agent(_make_identity(name))
        
        graph.add_trust_edge("a", "b")
        graph.add_trust_edge("b", "c")
        graph.add_trust_edge("c", "d")
        
        chains = graph.find_trust_chains("a", "d")
        assert len(chains) == 1
        assert chains[0] == ["a", "b", "c", "d"]

    def test_delegation_depth(self):
        graph = TrustGraph()
        for name in ["a", "b", "c"]:
            graph.add_agent(_make_identity(name))
        
        graph.add_trust_edge("a", "b")
        graph.add_trust_edge("b", "c")
        
        assert graph.get_delegation_depth("a", "c") == 2

    def test_agent_not_found(self):
        graph = TrustGraph()
        with pytest.raises(AgentNotFoundError):
            graph.add_trust_edge("nonexistent", "also-nonexistent")


class TestCascadeDetector:
    """Test cascade attack detection."""

    def test_detect_deep_transitive_trust(self):
        config = TrustGraphConfig(max_delegation_depth=2, auto_revoke_on_violation=False)
        graph = TrustGraph(config)
        
        for name in ["a", "b", "c", "d"]:
            graph.add_agent(_make_identity(name))
        
        graph.add_trust_edge("a", "b")
        graph.add_trust_edge("b", "c")
        graph.add_trust_edge("c", "d")
        
        detector = CascadeDetector(
            graph._graph, graph._edges, config
        )
        alerts = detector.run_full_scan()
        
        # Should detect transitive amplification (depth 3 > max 2)
        transitive = [
            a for a in alerts
            if a.alert_type == "transitive_amplification"
        ]
        assert len(transitive) > 0

    def test_detect_circular_dependency(self):
        config = TrustGraphConfig(auto_revoke_on_violation=False)
        graph = TrustGraph(config)
        
        for name in ["a", "b", "c"]:
            graph.add_agent(_make_identity(name))
        
        graph.add_trust_edge("a", "b")
        graph.add_trust_edge("b", "c")
        graph.add_trust_edge("c", "a")
        
        detector = CascadeDetector(
            graph._graph, graph._edges, config
        )
        alerts = detector.run_full_scan()
        
        circular = [
            a for a in alerts
            if a.alert_type == "circular_trust_dependency"
        ]
        assert len(circular) > 0

    def test_detect_shadow_trust(self):
        config = TrustGraphConfig(auto_revoke_on_violation=False)
        graph = TrustGraph(config)
        
        for name in ["a", "b", "c"]:
            graph.add_agent(_make_identity(name))
        
        graph.add_trust_edge("a", "b")
        graph.add_trust_edge("b", "c")
        
        detector = CascadeDetector(
            graph._graph, graph._edges, config
        )
        alerts = detector.run_full_scan()
        
        shadow = [
            a for a in alerts if a.alert_type == "shadow_trust"
        ]
        assert len(shadow) > 0

    def test_graph_stats(self):
        graph = TrustGraph()
        for name in ["a", "b", "c"]:
            graph.add_agent(_make_identity(name))
        graph.add_trust_edge("a", "b")
        graph.add_trust_edge("b", "c")
        
        stats = graph.get_graph_stats()
        assert stats["total_agents"] == 3
        assert stats["total_edges"] == 2
        assert stats["is_dag"] is True
