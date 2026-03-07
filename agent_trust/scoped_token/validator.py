"""
Token validator — standalone validation that can be used
at the edge without the full manager context.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from jose import jwt as jose_jwt
from jose import JWTError

from agent_trust.exceptions import (
    ScopedTokenError,
    TokenExpiredError,
    TokenAgentMismatch,
    TokenScopeExceeded,
)
from agent_trust.types import TokenScope

logger = logging.getLogger(__name__)


class TokenValidator:
    """
    Lightweight token validator for edge deployment.
    
    Can validate tokens without access to the full token
    manager — only needs the signing key. Useful for
    distributed systems where validation happens at the
    receiving agent.
    
    Usage:
        validator = TokenValidator(signing_key="shared-secret")
        claims = validator.validate(
            token=token_string,
            expected_subject="agent-b",
        )
    """

    def __init__(self, signing_key: str, algorithms: Optional[list[str]] = None):
        self._signing_key = signing_key
        self._algorithms = algorithms or ["HS256"]

    def validate(
        self,
        token: str,
        expected_subject: Optional[str] = None,
        expected_issuer: Optional[str] = None,
        required_scope: Optional[TokenScope] = None,
        expected_task_type: Optional[str] = None,
    ) -> dict:
        """
        Validate a token and return its claims.
        
        This is a stateless validation — it cannot check
        single-use status (that requires the token manager).
        """
        try:
            claims = jose_jwt.decode(
                token,
                self._signing_key,
                algorithms=self._algorithms,
            )
        except JWTError as e:
            raise ScopedTokenError(f"Token validation failed: {e}")

        # Check expiry (even though jose should handle this)
        exp = claims.get("exp", 0)
        if time.time() > exp:
            raise TokenExpiredError("Token has expired")

        # Check subject
        if expected_subject:
            if claims.get("sub") != expected_subject:
                raise TokenAgentMismatch(
                    f"Expected subject '{expected_subject}', "
                    f"got '{claims.get('sub')}'"
                )

        # Check issuer
        if expected_issuer:
            if claims.get("iss") != expected_issuer:
                raise TokenAgentMismatch(
                    f"Expected issuer '{expected_issuer}', "
                    f"got '{claims.get('iss')}'"
                )

        # Check scope
        if required_scope:
            scopes = set(claims.get("scopes", []))
            if required_scope.value not in scopes:
                raise TokenScopeExceeded(
                    f"Token missing required scope: {required_scope.value}"
                )

        # Check task type
        if expected_task_type:
            token_task = claims.get("task_type", "")
            if token_task and token_task != expected_task_type:
                raise TokenScopeExceeded(
                    f"Token scoped to task '{token_task}', "
                    f"not '{expected_task_type}'"
                )

        return claims

    def extract_claims(self, token: str) -> Optional[dict]:
        """
        Extract claims without validation.
        Useful for inspection/debugging only.
        """
        try:
            return jose_jwt.decode(
                token,
                self._signing_key,
                algorithms=self._algorithms,
                options={"verify_exp": False},
            )
        except JWTError:
            return None
