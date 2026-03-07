"""
Tests for ScopedToken module.
"""

import pytest
import time
from agent_trust.scoped_token import ScopedTokenManager
from agent_trust.scoped_token.policy import TokenPolicy, TokenConstraints
from agent_trust.scoped_token.validator import TokenValidator
from agent_trust.types import TokenScope
from agent_trust.exceptions import (
    TokenExpiredError,
    TokenAlreadyUsedError,
    TokenScopeExceeded,
    TokenAgentMismatch,
    ScopedTokenError,
)


class TestTokenPolicy:
    """Test token policy engine."""

    def test_trust_level_scopes(self):
        policy = TokenPolicy()
        
        # UNTRUSTED: no scopes
        c0 = policy.get_constraints("a", "b", trust_level=0)
        assert c0.allowed_scopes == []
        
        # BASIC: read + write
        c2 = policy.get_constraints("a", "b", trust_level=2)
        assert TokenScope.READ in c2.allowed_scopes
        assert TokenScope.WRITE in c2.allowed_scopes
        assert TokenScope.ADMIN not in c2.allowed_scopes

    def test_sensitive_tasks_get_single_use(self):
        policy = TokenPolicy()
        constraints = policy.get_constraints(
            "a", "b", task_type="payment_processing", trust_level=3
        )
        assert constraints.single_use is True

    def test_custom_policy(self):
        policy = TokenPolicy()
        custom = TokenConstraints(
            max_ttl_seconds=60,
            allowed_scopes=[TokenScope.READ],
            single_use=True,
        )
        policy.set_custom_policy("a", "b", custom)
        
        result = policy.get_constraints("a", "b", trust_level=5)
        assert result.max_ttl_seconds == 60
        assert result.single_use is True


class TestScopedTokenManager:
    """Test scoped token management."""

    def test_issue_and_validate(self):
        manager = ScopedTokenManager()
        
        token = manager.issue_token(
            issuer_id="agent-a",
            subject_id="agent-b",
            scopes=[TokenScope.READ],
            task_type="retrieval",
            trust_level=3,
        )
        
        claims = manager.validate_token(
            token=token,
            presenter_id="agent-b",
            task_type="retrieval",
        )
        
        assert claims["iss"] == "agent-a"
        assert claims["sub"] == "agent-b"
        assert "read" in claims["scopes"]

    def test_wrong_presenter_rejected(self):
        manager = ScopedTokenManager()
        
        token = manager.issue_token(
            issuer_id="agent-a",
            subject_id="agent-b",
            scopes=[TokenScope.READ],
            trust_level=2,
        )
        
        with pytest.raises(TokenAgentMismatch):
            manager.validate_token(
                token=token,
                presenter_id="agent-c",  # Wrong agent!
            )

    def test_single_use_token(self):
        manager = ScopedTokenManager()
        
        token = manager.issue_token(
            issuer_id="agent-a",
            subject_id="agent-b",
            scopes=[TokenScope.EXECUTE],
            task_type="payment",  # Sensitive → single use
            trust_level=3,
        )
        
        # First use: OK
        manager.validate_token(token=token, presenter_id="agent-b")
        
        # Second use: rejected
        with pytest.raises(TokenAlreadyUsedError):
            manager.validate_token(token=token, presenter_id="agent-b")

    def test_scope_exceeded_rejected(self):
        manager = ScopedTokenManager()
        
        # Trust level 1 only allows READ
        with pytest.raises(TokenScopeExceeded):
            manager.issue_token(
                issuer_id="agent-a",
                subject_id="agent-b",
                scopes=[TokenScope.ADMIN],  # Not allowed at level 1
                trust_level=1,
            )

    def test_revoke_token(self):
        manager = ScopedTokenManager()
        
        token = manager.issue_token(
            issuer_id="a",
            subject_id="b",
            scopes=[TokenScope.READ],
            trust_level=2,
        )
        
        claims = manager.validate_token(token=token, presenter_id="b")
        token_id = claims["jti"]
        
        # Note: can't validate twice since it was used, so revoke by id
        assert manager.revoke_token(token_id)

    def test_stats(self):
        manager = ScopedTokenManager()
        
        manager.issue_token("a", "b", [TokenScope.READ], trust_level=2)
        manager.issue_token("a", "c", [TokenScope.READ], trust_level=2)
        
        stats = manager.get_stats()
        assert stats["total_issued"] == 2
        assert stats["active"] == 2


class TestTokenValidator:
    """Test standalone token validator."""

    def test_validate_with_signing_key(self):
        key = "test-secret"
        manager = ScopedTokenManager(signing_key=key)
        validator = TokenValidator(signing_key=key)
        
        token = manager.issue_token(
            issuer_id="a",
            subject_id="b",
            scopes=[TokenScope.READ],
            trust_level=2,
        )
        
        claims = validator.validate(
            token=token,
            expected_subject="b",
            expected_issuer="a",
        )
        
        assert claims["sub"] == "b"

    def test_wrong_key_rejected(self):
        manager = ScopedTokenManager(signing_key="key1")
        validator = TokenValidator(signing_key="key2")
        
        token = manager.issue_token(
            issuer_id="a",
            subject_id="b",
            scopes=[TokenScope.READ],
            trust_level=2,
        )
        
        with pytest.raises(ScopedTokenError):
            validator.validate(token=token)
