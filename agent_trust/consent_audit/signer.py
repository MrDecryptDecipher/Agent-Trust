"""
Consent chain signer — creates cryptographically signed
consent records using JWT.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

import jwt

from agent_trust.config import ConsentAuditConfig
from agent_trust.types import ConsentRecord, TokenScope

logger = logging.getLogger(__name__)


class ConsentSigner:
    """
    Creates and verifies cryptographically signed consent records.
    
    Each consent record is signed as a JWT, creating an
    unforgeable chain of authorization decisions.
    
    Usage:
        signer = ConsentSigner(signing_key="secret")
        signed = signer.sign_consent(record)
        verified = signer.verify_consent(signed)
    """

    def __init__(
        self,
        signing_key: str,
        config: Optional[ConsentAuditConfig] = None,
    ):
        self._signing_key = signing_key
        self._config = config or ConsentAuditConfig()

    def sign_consent(self, record: ConsentRecord) -> str:
        """
        Sign a consent record and return a JWT string.
        Also populates the record's signature field.
        """
        payload = {
            "consent_id": record.consent_id,
            "chain_id": record.chain_id,
            "hop_index": record.hop_index,
            "grantor": record.grantor_agent_id,
            "grantee": record.grantee_agent_id,
            "scopes": [s.value for s in record.scopes],
            "task_type": record.task_type,
            "task_description": record.task_description,
            "iat": int(record.granted_at),
            "exp": int(record.expires_at),
            "parent_consent_id": record.parent_consent_id,
            "iss": self._config.jwt_issuer,
        }

        token = jwt.encode(
            payload,
            self._signing_key,
            algorithm="HS256",
        )
        
        record.signature = token
        return token

    def verify_consent(self, token: str) -> dict:
        """
        Verify a signed consent JWT and return its claims.
        Raises jwt.InvalidTokenError on failure.
        """
        return jwt.decode(
            token,
            self._signing_key,
            algorithms=["HS256"],
            issuer=self._config.jwt_issuer,
        )

    def verify_chain(self, tokens: list[str]) -> list[dict]:
        """
        Verify a chain of consent JWTs, checking:
        1. Each token is valid
        2. Chain ordering is correct (hop_index)
        3. Each hop's grantee is the next hop's grantor
        4. Parent consent IDs link correctly
        """
        claims_list = []
        
        for i, token in enumerate(tokens):
            claims = self.verify_consent(token)
            
            # Check hop ordering
            if claims.get("hop_index") != i:
                raise jwt.InvalidTokenError(
                    f"Expected hop_index {i}, got {claims.get('hop_index')}"
                )
            
            # Check chain continuity
            if i > 0:
                prev = claims_list[i - 1]
                if claims.get("grantor") != prev.get("grantee"):
                    raise jwt.InvalidTokenError(
                        f"Chain break at hop {i}: grantor "
                        f"'{claims.get('grantor')}' != previous grantee "
                        f"'{prev.get('grantee')}'"
                    )
                if claims.get("parent_consent_id") != prev.get("consent_id"):
                    raise jwt.InvalidTokenError(
                        f"Chain break at hop {i}: parent_consent_id mismatch"
                    )
            
            claims_list.append(claims)
        
        return claims_list
