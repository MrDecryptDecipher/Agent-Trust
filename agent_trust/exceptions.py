"""
Custom exceptions for agent-trust.

Organized by module so callers can catch at the right granularity.
"""


class AgentTrustError(Exception):
    """Base exception for all agent-trust errors."""
    pass


# ─── TrustGraph Exceptions ────────────────────────────────────────────

class TrustGraphError(AgentTrustError):
    """Base exception for TrustGraph module."""
    pass


class CascadingTrustViolation(TrustGraphError):
    """
    Raised when a transitive trust chain exceeds the configured
    maximum delegation depth.
    """
    def __init__(self, chain: list[str], max_depth: int):
        self.chain = chain
        self.max_depth = max_depth
        path = " → ".join(chain)
        super().__init__(
            f"Cascading trust violation: chain depth {len(chain) - 1} "
            f"exceeds max {max_depth}. Path: {path}"
        )


class TrustRevocationError(TrustGraphError):
    """Raised when a trust edge revocation fails."""
    pass


class AgentNotFoundError(TrustGraphError):
    """Raised when a referenced agent does not exist in the graph."""
    pass


# ─── AgentID Exceptions ───────────────────────────────────────────────

class AgentIDError(AgentTrustError):
    """Base exception for AgentID module."""
    pass


class IdentityVerificationFailed(AgentIDError):
    """Raised when an agent's identity cannot be verified."""
    pass


class KeyRotationError(AgentIDError):
    """Raised when transport key rotation fails."""
    pass


class DuplicateIdentityError(AgentIDError):
    """Raised when an agent with the same fingerprint already exists."""
    pass


# ─── ReputationLedger Exceptions ──────────────────────────────────────

class ReputationError(AgentTrustError):
    """Base exception for ReputationLedger module."""
    pass


class MerkleIntegrityError(ReputationError):
    """Raised when Merkle tree integrity verification fails."""
    pass


class InsufficientHistoryError(ReputationError):
    """Raised when an agent has too few interactions for a score."""
    pass


# ─── ConsentAudit Exceptions ─────────────────────────────────────────

class ConsentError(AgentTrustError):
    """Base exception for ConsentAudit module."""
    pass


class ConsentExpiredError(ConsentError):
    """Raised when a consent record has expired."""
    pass


class ConsentScopeViolation(ConsentError):
    """Raised when an action exceeds the granted consent scope."""
    pass


class ConsentChainBrokenError(ConsentError):
    """Raised when a consent chain has a gap or invalid signature."""
    pass


class ComplianceViolation(ConsentError):
    """Raised when an action violates a compliance requirement."""
    def __init__(self, standard: str, requirement: str, detail: str = ""):
        self.standard = standard
        self.requirement = requirement
        super().__init__(
            f"Compliance violation [{standard}]: {requirement}. {detail}"
        )


# ─── EastWestMonitor Exceptions ──────────────────────────────────────

class MonitorError(AgentTrustError):
    """Base exception for EastWestMonitor module."""
    pass


class AnomalyDetected(MonitorError):
    """Raised when anomalous agent traffic is detected."""
    def __init__(self, agent_id: str, score: float, threshold: float):
        self.agent_id = agent_id
        self.score = score
        self.threshold = threshold
        super().__init__(
            f"Anomaly detected for agent {agent_id}: "
            f"score {score:.3f} exceeds threshold {threshold:.3f}"
        )


# ─── ScopedToken Exceptions ─────────────────────────────────────────

class ScopedTokenError(AgentTrustError):
    """Base exception for ScopedToken module."""
    pass


class TokenExpiredError(ScopedTokenError):
    """Raised when a scoped token has expired."""
    pass


class TokenAlreadyUsedError(ScopedTokenError):
    """Raised when a single-use token is presented again."""
    pass


class TokenScopeExceeded(ScopedTokenError):
    """Raised when an action exceeds the token's scoped permissions."""
    pass


class TokenAgentMismatch(ScopedTokenError):
    """Raised when a token is presented by the wrong agent pair."""
    pass
