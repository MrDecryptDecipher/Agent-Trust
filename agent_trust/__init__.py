"""
agent-trust: The Trust & Reputation Layer That A2A Forgot to Build

A middleware enforcement layer that sits between A2A agents and solves
every documented trust gap with working code.

Modules:
    - TrustGraph: Cascading attack detector
    - AgentID: Persistent cryptographic identity
    - ReputationLedger: Cross-organization trust scores
    - ConsentAudit: Legally compliant consent chains
    - EastWestMonitor: Agent-to-agent traffic visibility
    - ScopedToken: Short-lived, task-scoped credentials
"""

__version__ = "0.1.0"
__author__ = "agent-trust contributors"

from agent_trust.config import TrustConfig
from agent_trust.types import AgentIdentity, TrustLevel, InteractionRecord
from agent_trust.middleware import AgentTrustMiddleware

__all__ = [
    "AgentTrustMiddleware",
    "TrustConfig",
    "AgentIdentity",
    "TrustLevel",
    "InteractionRecord",
    "__version__",
]

