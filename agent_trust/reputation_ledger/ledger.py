"""
Reputation ledger — stores and scores agent interaction records
with Merkle tree integrity guarantees.
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from agent_trust.config import ReputationConfig
from agent_trust.exceptions import InsufficientHistoryError, MerkleIntegrityError
from agent_trust.reputation_ledger.merkle import MerkleTree
from agent_trust.types import InteractionRecord

logger = logging.getLogger(__name__)


@dataclass
class ReputationScore:
    """Computed reputation score for an agent."""
    agent_id: str
    overall_score: float  # 0.0 to 1.0
    reliability: float  # Task success rate
    performance: float  # Latency/efficiency metric
    compliance: float  # Policy violation rate (inverse)
    total_interactions: int = 0
    last_updated: float = field(default_factory=time.time)
    confidence: float = 0.0  # Higher with more interactions

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "overall_score": round(self.overall_score, 4),
            "reliability": round(self.reliability, 4),
            "performance": round(self.performance, 4),
            "compliance": round(self.compliance, 4),
            "total_interactions": self.total_interactions,
            "confidence": round(self.confidence, 4),
            "last_updated_iso": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(self.last_updated),
            ),
        }


class ReputationLedger:
    """
    Append-only ledger of agent interaction records with
    Merkle tree integrity and reputation scoring.
    
    Usage:
        ledger = ReputationLedger()
        
        # Record an interaction
        ledger.record_interaction(InteractionRecord(
            source_agent_id="agent-a",
            target_agent_id="agent-b",
            task_type="data_retrieval",
            success=True,
            latency_ms=340,
            policy_violations=0,
        ))
        
        # Get reputation
        score = ledger.get_reputation("agent-b")
        print(f"Reputation: {score.overall_score}")
    """

    def __init__(self, config: Optional[ReputationConfig] = None):
        self._config = config or ReputationConfig()
        self._merkle = MerkleTree(self._config.merkle_hash_algorithm)
        self._records: list[InteractionRecord] = []
        self._by_agent: dict[str, list[InteractionRecord]] = defaultdict(list)
        self._scores_cache: dict[str, ReputationScore] = {}

    @property
    def merkle_root(self) -> str:
        """Current Merkle root hash."""
        return self._merkle.root_hash

    @property
    def total_records(self) -> int:
        return len(self._records)

    def record_interaction(
        self, record: InteractionRecord
    ) -> int:
        """
        Record a new agent interaction in the ledger.
        
        The record is added to the Merkle tree for tamper evidence
        and indexed for reputation queries.
        
        Returns the leaf index in the Merkle tree.
        """
        # Add to Merkle tree
        leaf_data = {
            "interaction_id": record.interaction_id,
            "source": record.source_agent_id,
            "target": record.target_agent_id,
            "task_type": record.task_type,
            "success": record.success,
            "latency_ms": record.latency_ms,
            "policy_violations": record.policy_violations,
            "timestamp": record.started_at,
        }
        index = self._merkle.add_leaf(leaf_data)
        
        # Store record
        self._records.append(record)
        
        # Index by both agents
        self._by_agent[record.source_agent_id].append(record)
        self._by_agent[record.target_agent_id].append(record)
        
        # Invalidate cached scores
        self._scores_cache.pop(record.source_agent_id, None)
        self._scores_cache.pop(record.target_agent_id, None)
        
        logger.debug(
            f"Recorded interaction {record.interaction_id[:8]}... "
            f"({record.source_agent_id} → {record.target_agent_id})"
        )
        
        return index

    def get_reputation(
        self,
        agent_id: str,
        force_recalc: bool = False,
    ) -> ReputationScore:
        """
        Get the reputation score for an agent.
        
        Computes from interaction history if not cached.
        """
        if not force_recalc and agent_id in self._scores_cache:
            return self._scores_cache[agent_id]

        records = self._by_agent.get(agent_id, [])
        
        if len(records) < self._config.min_interactions_for_score:
            raise InsufficientHistoryError(
                f"Agent {agent_id} has {len(records)} interactions, "
                f"minimum required: {self._config.min_interactions_for_score}"
            )

        score = self._compute_score(agent_id, records)
        self._scores_cache[agent_id] = score
        return score

    def get_reputation_safe(
        self, agent_id: str
    ) -> Optional[ReputationScore]:
        """Get reputation without raising on insufficient history."""
        try:
            return self.get_reputation(agent_id)
        except InsufficientHistoryError:
            return None

    def verify_integrity(self) -> bool:
        """Verify the integrity of the entire ledger."""
        return self._merkle.verify_integrity()

    def get_proof(self, record_index: int) -> list[tuple[str, str]]:
        """Get a Merkle proof for a specific record."""
        return self._merkle.get_proof(record_index)

    def verify_record(
        self,
        record_index: int,
        expected_root: Optional[str] = None,
    ) -> bool:
        """Verify that a record exists and hasn't been tampered with."""
        if record_index >= len(self._merkle.leaves):
            return False
        
        leaf_hash = self._merkle.leaves[record_index].hash
        proof = self._merkle.get_proof(record_index)
        root = expected_root or self._merkle.root_hash
        
        return self._merkle.verify_proof(proof, leaf_hash, root)

    def get_agent_history(
        self,
        agent_id: str,
        limit: int = 100,
    ) -> list[InteractionRecord]:
        """Get interaction history for an agent."""
        records = self._by_agent.get(agent_id, [])
        return records[-limit:]

    def get_leaderboard(
        self,
        top_n: int = 10,
        min_interactions: Optional[int] = None,
    ) -> list[ReputationScore]:
        """Get top-N agents by reputation score."""
        min_int = min_interactions or self._config.min_interactions_for_score
        
        scores = []
        for agent_id in self._by_agent:
            if len(self._by_agent[agent_id]) >= min_int:
                try:
                    score = self.get_reputation(agent_id)
                    scores.append(score)
                except InsufficientHistoryError:
                    continue
        
        scores.sort(key=lambda s: s.overall_score, reverse=True)
        return scores[:top_n]

    def export_records(
        self,
        agent_id: Optional[str] = None,
    ) -> list[dict]:
        """Export interaction records as dicts."""
        records = (
            self._by_agent.get(agent_id, [])
            if agent_id
            else self._records
        )
        
        return [
            {
                "interaction_id": r.interaction_id,
                "source": r.source_agent_id,
                "target": r.target_agent_id,
                "task_type": r.task_type,
                "success": r.success,
                "latency_ms": r.latency_ms,
                "policy_violations": r.policy_violations,
                "anomaly_score": r.anomaly_score,
                "timestamp": r.started_at,
            }
            for r in records
        ]

    def get_stats(self) -> dict:
        """Get ledger statistics."""
        return {
            "total_records": len(self._records),
            "unique_agents": len(self._by_agent),
            "merkle_root": self._merkle.root_hash,
            "merkle_leaves": self._merkle.size,
            "integrity_valid": self.verify_integrity(),
            "cached_scores": len(self._scores_cache),
        }

    def _compute_score(
        self,
        agent_id: str,
        records: list[InteractionRecord],
    ) -> ReputationScore:
        """Compute reputation score from interaction records."""
        now = time.time()
        decay_seconds = self._config.score_decay_days * 86400

        # Apply time decay weights
        weighted_records = []
        for record in records:
            age = now - record.started_at
            weight = math.exp(-age / decay_seconds) if decay_seconds > 0 else 1.0
            weighted_records.append((record, weight))

        total_weight = sum(w for _, w in weighted_records)
        if total_weight == 0:
            total_weight = 1.0

        # Reliability: weighted success rate
        reliability = sum(
            w * (1.0 if r.success else 0.0)
            for r, w in weighted_records
        ) / total_weight

        # Performance: normalized latency score (lower is better)
        latencies = [r.latency_ms for r, _ in weighted_records if r.latency_ms > 0]
        if latencies:
            median_latency = sorted(latencies)[len(latencies) // 2]
            # Score from 0-1 where 1 is best (fast)
            # Using sigmoid-like function: 1 / (1 + latency/1000)
            performance = 1.0 / (1.0 + median_latency / 1000.0)
        else:
            performance = 0.5

        # Compliance: inverse of violation rate
        total_violations = sum(r.policy_violations for r, _ in weighted_records)
        compliance = max(0, 1.0 - (total_violations / max(len(records), 1)))

        # Overall score: weighted combination
        overall = (
            0.50 * reliability
            + 0.25 * performance
            + 0.25 * compliance
        )

        # Confidence increases with more interactions (log scale)
        confidence = min(1.0, math.log(1 + len(records)) / math.log(100))

        return ReputationScore(
            agent_id=agent_id,
            overall_score=overall,
            reliability=reliability,
            performance=performance,
            compliance=compliance,
            total_interactions=len(records),
            confidence=confidence,
        )
