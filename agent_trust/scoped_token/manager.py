"""
Scoped token manager — creates and manages task-scoped,
short-lived, agent-pair-bound credentials.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from jose import jwt as jose_jwt
from jose import JWTError

from agent_trust.config import ScopedTokenConfig
from agent_trust.exceptions import (
    ScopedTokenError,
    TokenAgentMismatch,
    TokenAlreadyUsedError,
    TokenExpiredError,
    TokenScopeExceeded,
)
from agent_trust.scoped_token.policy import TokenPolicy, TokenConstraints
from agent_trust.types import TokenScope

logger = logging.getLogger(__name__)


@dataclass
class ScopedTokenRecord:
    """Internal record of an issued token."""
    token_id: str
    issuer_id: str
    subject_id: str
    scopes: list[TokenScope]
    task_type: str
    created_at: float
    expires_at: float
    single_use: bool
    used: bool = False
    used_at: Optional[float] = None
    revoked: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


class ScopedTokenManager:
    """
    Creates and manages task-scoped, short-lived credentials.
    
    Every token is:
    - Scoped to a specific task type
    - Valid for at most 5 minutes (configurable)
    - Optionally single-use (auto-destruct after first use)
    - Cryptographically bound to the issuer-subject agent pair
    
    Usage:
        manager = ScopedTokenManager()
        token = manager.issue_token(
            issuer_id="agent-a",
            subject_id="agent-b",
            scopes=[TokenScope.READ],
            task_type="data_retrieval",
            trust_level=3,
        )
        
        # Later, when agent-b presents the token:
        claims = manager.validate_token(
            token=token,
            presenter_id="agent-b",
            task_type="data_retrieval",
        )
    """

    def __init__(
        self,
        config: Optional[ScopedTokenConfig] = None,
        signing_key: Optional[str] = None,
    ):
        self._config = config or ScopedTokenConfig()
        self._policy = TokenPolicy(self._config)
        # Use a random signing key if none provided
        self._signing_key = signing_key or uuid.uuid4().hex
        self._tokens: dict[str, ScopedTokenRecord] = {}
        self._usage_log: list[dict] = []

    @property
    def policy(self) -> TokenPolicy:
        return self._policy

    def issue_token(
        self,
        issuer_id: str,
        subject_id: str,
        scopes: list[TokenScope],
        task_type: str = "",
        trust_level: int = 0,
        ttl_seconds: Optional[int] = None,
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Issue a new scoped token for a specific agent pair and task.
        
        Returns the JWT token string.
        """
        # Get policy constraints
        constraints = self._policy.get_constraints(
            issuer_id=issuer_id,
            subject_id=subject_id,
            task_type=task_type,
            trust_level=trust_level,
        )

        # Validate requested scopes against policy
        valid, msg = constraints.validate_requested_scopes(scopes)
        if not valid:
            raise TokenScopeExceeded(
                f"Token issuance denied: {msg}"
            )

        # Enforce TTL limits
        requested_ttl = ttl_seconds or self._config.default_token_ttl_seconds
        effective_ttl = min(requested_ttl, constraints.max_ttl_seconds)
        
        if effective_ttl <= 0:
            raise ScopedTokenError(
                f"Cannot issue token: trust level {trust_level} "
                f"does not allow token issuance"
            )

        now = time.time()
        token_id = str(uuid.uuid4())
        
        # Build agent pair binding hash
        pair_hash = hashlib.sha256(
            f"{issuer_id}:{subject_id}:{token_id}".encode()
        ).hexdigest()[:16]

        # Build JWT claims
        claims = {
            "jti": token_id,
            "iss": issuer_id,
            "sub": subject_id,
            "iat": int(now),
            "exp": int(now + effective_ttl),
            "scopes": [s.value for s in scopes],
            "task_type": task_type,
            "pair_hash": pair_hash,
            "single_use": constraints.single_use,
            "agent_trust_version": "0.1.0",
        }

        if metadata:
            claims["metadata"] = metadata

        # Sign the token
        token = jose_jwt.encode(
            claims,
            self._signing_key,
            algorithm="HS256",  # Use HMAC for simplicity; EdDSA in production
        )

        # Store the record
        record = ScopedTokenRecord(
            token_id=token_id,
            issuer_id=issuer_id,
            subject_id=subject_id,
            scopes=scopes,
            task_type=task_type,
            created_at=now,
            expires_at=now + effective_ttl,
            single_use=constraints.single_use,
            metadata=metadata or {},
        )
        self._tokens[token_id] = record

        logger.info(
            f"Issued token {token_id[:8]}... for {issuer_id} → {subject_id} "
            f"(scopes: {[s.value for s in scopes]}, "
            f"TTL: {effective_ttl}s, "
            f"single_use: {constraints.single_use})"
        )

        return token

    def validate_token(
        self,
        token: str,
        presenter_id: str,
        task_type: str = "",
        required_scope: Optional[TokenScope] = None,
    ) -> dict:
        """
        Validate a scoped token.
        
        Checks:
        1. Token signature is valid
        2. Token has not expired
        3. Token has not been used (if single-use)
        4. Presenter matches the subject
        5. Task type matches (if specified)
        6. Required scope is included
        
        Returns the decoded claims on success.
        """
        # Decode and verify signature
        try:
            claims = jose_jwt.decode(
                token,
                self._signing_key,
                algorithms=["HS256"],
            )
        except JWTError as e:
            raise ScopedTokenError(f"Invalid token: {e}")

        token_id = claims.get("jti", "")
        record = self._tokens.get(token_id)

        if record is None:
            raise ScopedTokenError(f"Unknown token: {token_id[:8]}...")

        # Check revocation
        if record.revoked:
            raise ScopedTokenError(f"Token {token_id[:8]}... has been revoked")

        # Check expiry
        if time.time() > record.expires_at:
            raise TokenExpiredError(
                f"Token {token_id[:8]}... expired at "
                f"{record.expires_at}"
            )

        # Check single-use
        if record.single_use and record.used:
            raise TokenAlreadyUsedError(
                f"Single-use token {token_id[:8]}... already used at "
                f"{record.used_at}"
            )

        # Check agent pair binding
        if self._config.enforce_agent_pair_binding:
            if presenter_id != record.subject_id:
                raise TokenAgentMismatch(
                    f"Token bound to {record.subject_id}, "
                    f"presented by {presenter_id}"
                )

        # Check task type
        if task_type and record.task_type and task_type != record.task_type:
            raise TokenScopeExceeded(
                f"Token scoped to task '{record.task_type}', "
                f"used for '{task_type}'"
            )

        # Check required scope
        if required_scope:
            token_scopes = {TokenScope(s) for s in claims.get("scopes", [])}
            if required_scope not in token_scopes:
                raise TokenScopeExceeded(
                    f"Token does not include required scope "
                    f"'{required_scope.value}'"
                )

        # Mark as used if single-use
        if record.single_use:
            record.used = True
            record.used_at = time.time()

        # Log usage
        self._usage_log.append({
            "token_id": token_id,
            "presenter_id": presenter_id,
            "task_type": task_type,
            "timestamp": time.time(),
            "single_use_consumed": record.single_use,
        })

        return claims

    def revoke_token(self, token_id: str) -> bool:
        """Revoke a specific token."""
        record = self._tokens.get(token_id)
        if record is None:
            return False
        record.revoked = True
        logger.info(f"Token {token_id[:8]}... revoked")
        return True

    def revoke_all_for_agent(self, agent_id: str) -> int:
        """Revoke all tokens issued by or for an agent."""
        count = 0
        for record in self._tokens.values():
            if (
                record.issuer_id == agent_id
                or record.subject_id == agent_id
            ) and not record.revoked:
                record.revoked = True
                count += 1
        logger.warning(f"Revoked {count} tokens for agent {agent_id}")
        return count

    def cleanup_expired(self) -> int:
        """Remove expired tokens from memory."""
        now = time.time()
        expired = [
            tid for tid, rec in self._tokens.items()
            if now > rec.expires_at
        ]
        for tid in expired:
            del self._tokens[tid]
        return len(expired)

    def get_active_tokens(
        self,
        agent_id: Optional[str] = None,
    ) -> list[dict]:
        """List active (non-expired, non-revoked) tokens."""
        now = time.time()
        results = []
        for record in self._tokens.values():
            if record.revoked or now > record.expires_at:
                continue
            if agent_id and (
                record.issuer_id != agent_id
                and record.subject_id != agent_id
            ):
                continue
            results.append({
                "token_id": record.token_id,
                "issuer_id": record.issuer_id,
                "subject_id": record.subject_id,
                "scopes": [s.value for s in record.scopes],
                "task_type": record.task_type,
                "expires_in_seconds": record.expires_at - now,
                "single_use": record.single_use,
                "used": record.used,
            })
        return results

    def get_stats(self) -> dict:
        """Get token manager statistics."""
        now = time.time()
        active = sum(
            1 for r in self._tokens.values()
            if not r.revoked and now <= r.expires_at
        )
        return {
            "total_issued": len(self._tokens),
            "active": active,
            "expired": sum(
                1 for r in self._tokens.values()
                if now > r.expires_at
            ),
            "revoked": sum(
                1 for r in self._tokens.values()
                if r.revoked
            ),
            "single_use_consumed": sum(
                1 for r in self._tokens.values()
                if r.single_use and r.used
            ),
            "total_validations": len(self._usage_log),
        }
