"""
Tests for ReputationLedger module.
"""

import pytest
from agent_trust.reputation_ledger import ReputationLedger, MerkleTree, ReputationQuery
from agent_trust.types import InteractionRecord
from agent_trust.exceptions import InsufficientHistoryError


class TestMerkleTree:
    """Test Merkle tree implementation."""

    def test_add_leaf(self):
        tree = MerkleTree()
        idx = tree.add_leaf({"key": "value"})
        assert idx == 0
        assert tree.size == 1

    def test_root_hash_changes_on_add(self):
        tree = MerkleTree()
        tree.add_leaf({"data": 1})
        root1 = tree.root_hash
        
        tree.add_leaf({"data": 2})
        root2 = tree.root_hash
        
        assert root1 != root2

    def test_same_data_produces_same_hash(self):
        t1 = MerkleTree()
        t1.add_leaf({"a": 1})
        
        t2 = MerkleTree()
        t2.add_leaf({"a": 1})
        
        assert t1.root_hash == t2.root_hash

    def test_proof_generation_and_verification(self):
        tree = MerkleTree()
        for i in range(8):
            tree.add_leaf({"index": i})
        
        root = tree.root_hash
        leaf_hash = tree.leaves[3].hash
        proof = tree.get_proof(3)
        
        assert tree.verify_proof(proof, leaf_hash, root)

    def test_integrity_check(self):
        tree = MerkleTree()
        for i in range(5):
            tree.add_leaf({"val": i})
        
        assert tree.verify_integrity()


class TestReputationLedger:
    """Test reputation ledger."""

    def _add_interactions(self, ledger, agent_id, count=10, success=True):
        for i in range(count):
            ledger.record_interaction(InteractionRecord(
                source_agent_id="source",
                target_agent_id=agent_id,
                task_type="test",
                success=success,
                latency_ms=100 + i * 10,
                policy_violations=0 if success else 1,
            ))

    def test_record_interaction(self):
        ledger = ReputationLedger()
        idx = ledger.record_interaction(InteractionRecord(
            source_agent_id="a",
            target_agent_id="b",
            task_type="test",
            success=True,
        ))
        assert idx == 0
        assert ledger.total_records == 1

    def test_reputation_score(self):
        ledger = ReputationLedger()
        self._add_interactions(ledger, "agent-x", count=10, success=True)
        
        score = ledger.get_reputation("agent-x")
        assert score.overall_score > 0.8
        assert score.reliability > 0.9
        assert score.total_interactions == 10

    def test_insufficient_history(self):
        ledger = ReputationLedger()
        self._add_interactions(ledger, "agent-x", count=2)
        
        with pytest.raises(InsufficientHistoryError):
            ledger.get_reputation("agent-x")

    def test_low_reliability_score(self):
        ledger = ReputationLedger()
        self._add_interactions(ledger, "agent-x", count=10, success=False)
        
        score = ledger.get_reputation("agent-x")
        assert score.reliability < 0.2

    def test_merkle_integrity(self):
        ledger = ReputationLedger()
        self._add_interactions(ledger, "agent-x", count=5)
        
        assert ledger.verify_integrity()

    def test_leaderboard(self):
        ledger = ReputationLedger()
        self._add_interactions(ledger, "good-agent", count=10, success=True)
        self._add_interactions(ledger, "bad-agent", count=10, success=False)
        
        board = ledger.get_leaderboard(top_n=5)
        assert len(board) >= 1
        assert board[0].agent_id in ["good-agent", "source"]


class TestReputationQuery:
    """Test reputation query interface."""

    def test_risk_assessment(self):
        ledger = ReputationLedger()
        for i in range(10):
            ledger.record_interaction(InteractionRecord(
                source_agent_id="s",
                target_agent_id="test-agent",
                task_type="test",
                success=True,
                latency_ms=100,
            ))
        
        query = ReputationQuery(ledger)
        risk = query.get_risk_assessment("test-agent")
        
        assert risk["risk_level"] in ["low", "medium", "high", "critical"]

    def test_meets_threshold(self):
        ledger = ReputationLedger()
        for i in range(10):
            ledger.record_interaction(InteractionRecord(
                source_agent_id="s",
                target_agent_id="good-agent",
                task_type="test",
                success=True,
                latency_ms=50,
            ))
        
        query = ReputationQuery(ledger)
        assert query.meets_threshold("good-agent", min_score=0.5)
