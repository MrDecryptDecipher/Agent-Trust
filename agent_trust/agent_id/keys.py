"""
Cryptographic key management for AgentID.

Handles Ed25519 identity keys (deterministic from behavioral spec)
and short-lived transport keys (rotated periodically).
"""

from __future__ import annotations

import hashlib
import time
import logging
from dataclasses import dataclass, field
from typing import Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder
from nacl.exceptions import BadSignatureError

logger = logging.getLogger(__name__)


@dataclass
class KeyPair:
    """An Ed25519 key pair with metadata."""
    signing_key: SigningKey
    verify_key: VerifyKey
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    key_id: str = ""

    @property
    def public_bytes(self) -> bytes:
        return bytes(self.verify_key)

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at

    def sign(self, message: bytes) -> bytes:
        """Sign a message, returning the signature bytes."""
        signed = self.signing_key.sign(message, encoder=RawEncoder)
        return signed.signature

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature against this key pair."""
        try:
            self.verify_key.verify(message, signature, encoder=RawEncoder)
            return True
        except BadSignatureError:
            return False


class KeyManager:
    """
    Manages Ed25519 key pairs for agent identity and transport.
    
    Identity keys are deterministically derived from the agent's
    behavioral specification (system prompt + tool list). This means
    the same agent deployed on different infrastructure will produce
    the same identity key.
    
    Transport keys are ephemeral and rotated periodically.
    """

    def __init__(self, rotation_interval_seconds: int = 3600):
        self._rotation_interval = rotation_interval_seconds
        self._identity_keys: dict[str, KeyPair] = {}
        self._transport_keys: dict[str, KeyPair] = {}

    def derive_identity_key(
        self,
        system_prompt: str,
        tool_list: list[str],
        agent_id: str,
    ) -> KeyPair:
        """
        Derive a deterministic Ed25519 identity key from an agent's
        behavioral specification.
        
        The same inputs always produce the same key pair — this is
        what makes identity persistent across infrastructure changes.
        """
        # Create deterministic seed from behavioral spec
        prompt_hash = hashlib.sha256(system_prompt.encode("utf-8")).digest()
        tools_str = "|".join(sorted(tool_list))
        tools_hash = hashlib.sha256(tools_str.encode("utf-8")).digest()
        
        # Combine hashes to create a 32-byte seed for Ed25519
        combined = prompt_hash + tools_hash
        seed = hashlib.sha256(combined).digest()  # 32 bytes — exactly what Ed25519 needs
        
        signing_key = SigningKey(seed)
        verify_key = signing_key.verify_key
        
        key_id = hashlib.sha256(bytes(verify_key)).hexdigest()[:16]
        
        key_pair = KeyPair(
            signing_key=signing_key,
            verify_key=verify_key,
            key_id=key_id,
        )
        
        self._identity_keys[agent_id] = key_pair
        logger.info(
            f"Derived identity key for agent {agent_id} "
            f"(fingerprint: {key_id})"
        )
        
        return key_pair

    def generate_transport_key(self, agent_id: str) -> KeyPair:
        """
        Generate a new ephemeral transport key for an agent.
        
        Transport keys are short-lived and used for active
        communications. They are NOT derived deterministically —
        they are freshly generated and expire after the rotation
        interval.
        """
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        
        now = time.time()
        key_id = hashlib.sha256(
            bytes(verify_key) + str(now).encode()
        ).hexdigest()[:16]
        
        key_pair = KeyPair(
            signing_key=signing_key,
            verify_key=verify_key,
            created_at=now,
            expires_at=now + self._rotation_interval,
            key_id=key_id,
        )
        
        self._transport_keys[agent_id] = key_pair
        logger.info(
            f"Generated transport key for agent {agent_id} "
            f"(expires in {self._rotation_interval}s)"
        )
        
        return key_pair

    def get_identity_key(self, agent_id: str) -> Optional[KeyPair]:
        """Get the identity key for an agent, if it exists."""
        return self._identity_keys.get(agent_id)

    def get_transport_key(self, agent_id: str) -> Optional[KeyPair]:
        """Get the current transport key for an agent, rotating if expired."""
        key = self._transport_keys.get(agent_id)
        if key is None:
            return None
        if key.is_expired:
            logger.info(f"Transport key expired for agent {agent_id}, rotating")
            return self.generate_transport_key(agent_id)
        return key

    def verify_signature(
        self,
        agent_id: str,
        message: bytes,
        signature: bytes,
        use_transport_key: bool = False,
    ) -> bool:
        """
        Verify a signature from an agent using their identity or
        transport key.
        """
        if use_transport_key:
            key = self.get_transport_key(agent_id)
        else:
            key = self.get_identity_key(agent_id)
        
        if key is None:
            logger.warning(f"No key found for agent {agent_id}")
            return False
        
        return key.verify(message, signature)

    def rotate_transport_key(self, agent_id: str) -> Optional[KeyPair]:
        """Force rotation of an agent's transport key."""
        if agent_id not in self._identity_keys:
            logger.warning(
                f"Cannot rotate transport key: agent {agent_id} "
                f"has no identity key"
            )
            return None
        return self.generate_transport_key(agent_id)

    def revoke_all_keys(self, agent_id: str) -> None:
        """Revoke all keys for an agent (nuclear option)."""
        self._identity_keys.pop(agent_id, None)
        self._transport_keys.pop(agent_id, None)
        logger.warning(f"All keys revoked for agent {agent_id}")
