"""
Reputation query interface for cross-organization lookups.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from agent_trust.reputation_ledger.ledger import ReputationLedger, ReputationScore

logger = logging.getLogger(__name__)


@dataclass
class ReputationQueryResult:
    """Result of a reputation query."""
    agent_id: str
    found: bool
    score: Optional[ReputationScore] = None
    interaction_count: int = 0
    merkle_proof_valid: bool = False
    organization: str = ""
    query_metadata: dict[str, Any] = field(default_factory=dict)


class ReputationQuery:
    """
    Query interface for reputation lookups.
    
    Supports both local and cross-organization queries.
    
    Usage:
        query = ReputationQuery(ledger)
        
        result = query.lookup("agent-x")
        if result.found:
            print(f"Score: {result.score.overall_score}")
            print(f"Verified: {result.merkle_proof_valid}")
    """

    def __init__(self, ledger: ReputationLedger):
        self._ledger = ledger

    def lookup(
        self,
        agent_id: str,
        verify_integrity: bool = True,
    ) -> ReputationQueryResult:
        """Look up an agent's reputation."""
        score = self._ledger.get_reputation_safe(agent_id)
        history = self._ledger.get_agent_history(agent_id)
        
        result = ReputationQueryResult(
            agent_id=agent_id,
            found=score is not None,
            score=score,
            interaction_count=len(history),
        )
        
        if verify_integrity and score is not None:
            result.merkle_proof_valid = self._ledger.verify_integrity()
        
        return result

    def compare(
        self,
        agent_ids: list[str],
    ) -> list[ReputationQueryResult]:
        """Compare reputation scores of multiple agents."""
        results = [self.lookup(aid) for aid in agent_ids]
        # Sort by score (highest first), with unfound agents last
        results.sort(
            key=lambda r: (
                r.score.overall_score if r.score else -1
            ),
            reverse=True,
        )
        return results

    def meets_threshold(
        self,
        agent_id: str,
        min_score: float = 0.5,
        min_interactions: int = 5,
        min_confidence: float = 0.3,
    ) -> bool:
        """Check if an agent meets minimum reputation thresholds."""
        score = self._ledger.get_reputation_safe(agent_id)
        if score is None:
            return False
        
        return (
            score.overall_score >= min_score
            and score.total_interactions >= min_interactions
            and score.confidence >= min_confidence
        )

    def get_risk_assessment(
        self, agent_id: str
    ) -> dict[str, Any]:
        """Get a risk assessment for an agent."""
        score = self._ledger.get_reputation_safe(agent_id)
        history = self._ledger.get_agent_history(agent_id)
        
        if score is None:
            return {
                "agent_id": agent_id,
                "risk_level": "unknown",
                "reason": "Insufficient interaction history",
            }
        
        # Determine risk level
        if score.overall_score >= 0.8 and score.confidence >= 0.5:
            risk_level = "low"
        elif score.overall_score >= 0.5:
            risk_level = "medium"
        elif score.overall_score >= 0.3:
            risk_level = "high"
        else:
            risk_level = "critical"
        
        # Recent trend
        recent = history[-10:] if len(history) >= 10 else history
        recent_success_rate = (
            sum(1 for r in recent if r.success) / len(recent)
            if recent else 0
        )
        
        return {
            "agent_id": agent_id,
            "risk_level": risk_level,
            "overall_score": score.overall_score,
            "confidence": score.confidence,
            "total_interactions": score.total_interactions,
            "recent_success_rate": recent_success_rate,
            "reliability": score.reliability,
            "compliance": score.compliance,
            "recommendations": self._get_recommendations(
                risk_level, score
            ),
        }

    def _get_recommendations(
        self,
        risk_level: str,
        score: ReputationScore,
    ) -> list[str]:
        """Generate recommendations based on risk assessment."""
        recs = []
        
        if risk_level == "critical":
            recs.append("BLOCK: Do not allow this agent to execute tasks")
            recs.append("INVESTIGATE: Review recent interaction history")
        elif risk_level == "high":
            recs.append("RESTRICT: Limit to read-only operations")
            recs.append("MONITOR: Enable enhanced logging")
        elif risk_level == "medium":
            recs.append("CAUTIOUS: Allow with supervision")
        
        if score.compliance < 0.7:
            recs.append(
                "COMPLIANCE: Agent has elevated policy violation rate"
            )
        
        if score.confidence < 0.3:
            recs.append(
                "LOW CONFIDENCE: Too few interactions for reliable score"
            )
        
        return recs
