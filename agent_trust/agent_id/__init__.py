"""
AgentID — Persistent Cryptographic Identity Across Infrastructure Changes

Solves Gap 4: A2A has no persistent identity.

Creates a stable, hardware-independent identity for each agent using:
- A deterministic key derived from the agent's behavioral spec
  (system prompt hash + tool list hash)
- A short-lived rotating transport key for active communications

When your cloud provider changes or your domain rotates,
the agent's identity survives. Reputation accumulates over
time against a stable ID.
"""

from agent_trust.agent_id.identity import AgentIDManager
from agent_trust.agent_id.keys import KeyManager
from agent_trust.agent_id.resolver import IdentityResolver

__all__ = ["AgentIDManager", "KeyManager", "IdentityResolver"]
