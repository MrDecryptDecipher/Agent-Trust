"""
Token policy engine for ScopedToken.

Defines and enforces policies for token creation:
- Maximum TTL enforcement
- Scope restriction rules
- Single-use enforcement
- Agent pair binding
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from agent_trust.config import ScopedTokenConfig
from agent_trust.types import TokenScope

logger = logging.getLogger(__name__)


@dataclass
class TokenConstraints:
    """Constraints applied to a specific token."""
    max_ttl_seconds: int = 300
    allowed_scopes: list[TokenScope] = field(
        default_factory=lambda: [TokenScope.READ]
    )
    single_use: bool = False
    require_agent_binding: bool = True
    task_type_restriction: Optional[str] = None
    
    def validate_requested_scopes(
        self, requested: list[TokenScope]
    ) -> tuple[bool, str]:
        """Check if requested scopes are within constraints."""
        for scope in requested:
            if scope not in self.allowed_scopes:
                return False, (
                    f"Scope '{scope.value}' not allowed. "
                    f"Allowed: {[s.value for s in self.allowed_scopes]}"
                )
        return True, "OK"


class TokenPolicy:
    """
    Policy engine that determines token constraints based on
    trust level, agent pair, and task type.
    
    Usage:
        policy = TokenPolicy()
        constraints = policy.get_constraints(
            issuer_id="agent-a",
            subject_id="agent-b",
            task_type="data_retrieval",
            trust_level=3,
        )
    """

    # Scope allowlists by trust level
    TRUST_LEVEL_SCOPES = {
        0: [],  # UNTRUSTED: no tokens
        1: [TokenScope.READ],  # PROVISIONAL: read only
        2: [TokenScope.READ, TokenScope.WRITE],  # BASIC
        3: [TokenScope.READ, TokenScope.WRITE, TokenScope.EXECUTE],  # VERIFIED
        4: [  # TRUSTED
            TokenScope.READ,
            TokenScope.WRITE,
            TokenScope.EXECUTE,
            TokenScope.DELEGATE,
        ],
        5: [  # FULLY_TRUSTED
            TokenScope.READ,
            TokenScope.WRITE,
            TokenScope.EXECUTE,
            TokenScope.DELEGATE,
            TokenScope.ADMIN,
        ],
    }

    # TTL limits by trust level (seconds)
    TRUST_LEVEL_TTL = {
        0: 0,
        1: 30,
        2: 60,
        3: 180,
        4: 300,
        5: 300,
    }

    def __init__(self, config: Optional[ScopedTokenConfig] = None):
        self._config = config or ScopedTokenConfig()
        self._custom_policies: dict[str, TokenConstraints] = {}

    def get_constraints(
        self,
        issuer_id: str,
        subject_id: str,
        task_type: str = "",
        trust_level: int = 0,
    ) -> TokenConstraints:
        """
        Determine token constraints for a given agent pair
        and task type.
        """
        # Check for custom policy first
        pair_key = f"{issuer_id}:{subject_id}"
        if pair_key in self._custom_policies:
            return self._custom_policies[pair_key]

        # Derive constraints from trust level
        allowed_scopes = self.TRUST_LEVEL_SCOPES.get(trust_level, [])
        max_ttl = min(
            self.TRUST_LEVEL_TTL.get(trust_level, 0),
            self._config.max_token_ttl_seconds,
        )

        # Sensitive task types get single-use tokens
        sensitive_tasks = {
            "payment", "delete", "admin", "credential",
            "transfer", "deploy", "execute_code",
        }
        single_use = (
            self._config.enable_single_use
            and any(s in task_type.lower() for s in sensitive_tasks)
        )

        return TokenConstraints(
            max_ttl_seconds=max_ttl,
            allowed_scopes=allowed_scopes,
            single_use=single_use,
            require_agent_binding=self._config.enforce_agent_pair_binding,
            task_type_restriction=task_type if task_type else None,
        )

    def set_custom_policy(
        self,
        issuer_id: str,
        subject_id: str,
        constraints: TokenConstraints,
    ) -> None:
        """Set a custom policy for a specific agent pair."""
        pair_key = f"{issuer_id}:{subject_id}"
        self._custom_policies[pair_key] = constraints
        logger.info(
            f"Custom token policy set for {issuer_id} → {subject_id}"
        )

    def remove_custom_policy(
        self, issuer_id: str, subject_id: str
    ) -> bool:
        """Remove a custom policy for a specific agent pair."""
        pair_key = f"{issuer_id}:{subject_id}"
        return self._custom_policies.pop(pair_key, None) is not None
