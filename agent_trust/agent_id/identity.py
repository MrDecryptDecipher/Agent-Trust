"""
AgentID identity management.

Creates, registers, and manages persistent agent identities
that survive infrastructure changes.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Optional

from agent_trust.agent_id.keys import KeyManager, KeyPair
from agent_trust.config import AgentIDConfig
from agent_trust.exceptions import (
    DuplicateIdentityError,
    IdentityVerificationFailed,
)
from agent_trust.types import AgentIdentity

logger = logging.getLogger(__name__)


class AgentIDManager:
    """
    High-level manager for agent identities.
    
    Handles registration, verification, and lifecycle management
    of persistent cryptographic identities.
    
    Usage:
        manager = AgentIDManager()
        identity = manager.register_agent(
            system_prompt="You are a helpful assistant...",
            tool_list=["search", "calculate", "translate"],
            organization="acme-corp",
        )
        
        # Later, even on different infrastructure:
        verified = manager.verify_agent(
            agent_id=identity.agent_id,
            message=b"hello",
            signature=sig_bytes,
        )
    """

    def __init__(self, config: Optional[AgentIDConfig] = None):
        self._config = config or AgentIDConfig()
        self._key_manager = KeyManager(
            rotation_interval_seconds=self._config.transport_key_rotation_seconds
        )
        self._identities: dict[str, AgentIdentity] = {}
        self._fingerprint_index: dict[str, str] = {}  # fingerprint -> agent_id

    @property
    def key_manager(self) -> KeyManager:
        return self._key_manager

    def register_agent(
        self,
        system_prompt: str,
        tool_list: list[str],
        organization: str,
        agent_id: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> AgentIdentity:
        """
        Register a new agent and create its persistent identity.
        
        The identity is derived deterministically from the agent's
        behavioral spec. If an agent with the same fingerprint already
        exists, raises DuplicateIdentityError.
        """
        # Compute behavioral fingerprint
        prompt_hash = hashlib.sha256(
            system_prompt.encode("utf-8")
        ).hexdigest()
        tools_str = "|".join(sorted(tool_list))
        tool_hash = hashlib.sha256(tools_str.encode("utf-8")).hexdigest()
        fingerprint = hashlib.sha256(
            f"{prompt_hash}:{tool_hash}".encode()
        ).hexdigest()[:16]

        # Check for duplicate fingerprint
        if fingerprint in self._fingerprint_index:
            existing_id = self._fingerprint_index[fingerprint]
            raise DuplicateIdentityError(
                f"Agent with fingerprint {fingerprint} already registered "
                f"as {existing_id}"
            )

        # Generate agent_id if not provided
        if agent_id is None:
            agent_id = f"agent-{fingerprint}-{int(time.time())}"

        # Derive identity key
        key_pair = self._key_manager.derive_identity_key(
            system_prompt=system_prompt,
            tool_list=tool_list,
            agent_id=agent_id,
        )

        # Also generate initial transport key
        self._key_manager.generate_transport_key(agent_id)

        identity = AgentIdentity(
            agent_id=agent_id,
            public_key=key_pair.public_bytes,
            system_prompt_hash=prompt_hash,
            tool_list_hash=tool_hash,
            organization=organization,
            created_at=time.time(),
            metadata=metadata or {},
        )

        self._identities[agent_id] = identity
        self._fingerprint_index[fingerprint] = agent_id

        logger.info(
            f"Registered agent {agent_id} "
            f"(org: {organization}, fingerprint: {fingerprint})"
        )

        return identity

    def get_identity(self, agent_id: str) -> Optional[AgentIdentity]:
        """Retrieve an agent's identity by ID."""
        return self._identities.get(agent_id)

    def get_identity_by_fingerprint(
        self, fingerprint: str
    ) -> Optional[AgentIdentity]:
        """Retrieve an agent's identity by behavioral fingerprint."""
        agent_id = self._fingerprint_index.get(fingerprint)
        if agent_id is None:
            return None
        return self._identities.get(agent_id)

    def verify_agent(
        self,
        agent_id: str,
        message: bytes,
        signature: bytes,
        use_transport_key: bool = False,
    ) -> bool:
        """
        Verify that a message was signed by the claimed agent.
        
        Can verify against either the identity key (default) or
        the current transport key.
        """
        identity = self._identities.get(agent_id)
        if identity is None:
            raise IdentityVerificationFailed(
                f"Unknown agent: {agent_id}"
            )

        return self._key_manager.verify_signature(
            agent_id=agent_id,
            message=message,
            signature=signature,
            use_transport_key=use_transport_key,
        )

    def sign_message(
        self,
        agent_id: str,
        message: bytes,
        use_transport_key: bool = False,
    ) -> bytes:
        """
        Sign a message on behalf of an agent.
        
        Returns the signature bytes.
        """
        if use_transport_key:
            key = self._key_manager.get_transport_key(agent_id)
        else:
            key = self._key_manager.get_identity_key(agent_id)

        if key is None:
            raise IdentityVerificationFailed(
                f"No key available for agent {agent_id}"
            )

        return key.sign(message)

    def rotate_transport_key(self, agent_id: str) -> KeyPair:
        """Force rotation of an agent's transport key."""
        key = self._key_manager.rotate_transport_key(agent_id)
        if key is None:
            raise IdentityVerificationFailed(
                f"Cannot rotate key for unknown agent {agent_id}"
            )
        return key

    def revoke_identity(self, agent_id: str) -> bool:
        """
        Permanently revoke an agent's identity.
        Removes all keys and identity records.
        """
        identity = self._identities.pop(agent_id, None)
        if identity is None:
            return False

        # Remove fingerprint index
        fingerprint = identity.fingerprint
        self._fingerprint_index.pop(fingerprint, None)

        # Revoke all cryptographic keys
        self._key_manager.revoke_all_keys(agent_id)

        logger.warning(f"Identity revoked for agent {agent_id}")
        return True

    def list_agents(self, organization: Optional[str] = None) -> list[AgentIdentity]:
        """List all registered agents, optionally filtered by organization."""
        agents = list(self._identities.values())
        if organization:
            agents = [a for a in agents if a.organization == organization]
        return agents

    @property
    def agent_count(self) -> int:
        return len(self._identities)
