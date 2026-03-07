"""
ScopedToken — Short-Lived, Task-Scoped Credential Manager

Solves Gap 5: Token Abuse.

Replaces long-lived OAuth tokens with tokens that are:
- Scoped to a single task type
- Valid for a maximum of 5 minutes
- Self-destructing after first use (for sensitive payloads)
- Cryptographically bound to the specific agent pair
"""

from agent_trust.scoped_token.manager import ScopedTokenManager
from agent_trust.scoped_token.policy import TokenPolicy
from agent_trust.scoped_token.validator import TokenValidator

__all__ = ["ScopedTokenManager", "TokenPolicy", "TokenValidator"]
