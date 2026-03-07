"""
Tests for AgentID module.
"""

import pytest
from agent_trust.agent_id import AgentIDManager
from agent_trust.agent_id.keys import KeyManager
from agent_trust.exceptions import DuplicateIdentityError, IdentityVerificationFailed


class TestKeyManager:
    """Test Ed25519 key management."""

    def test_derive_identity_key_is_deterministic(self):
        """Same inputs always produce the same identity key."""
        km = KeyManager()
        key1 = km.derive_identity_key(
            "You are a helpful assistant",
            ["search", "calculate"],
            "agent-1",
        )
        
        km2 = KeyManager()
        key2 = km2.derive_identity_key(
            "You are a helpful assistant",
            ["search", "calculate"],
            "agent-1",
        )
        
        assert key1.public_bytes == key2.public_bytes

    def test_different_prompts_produce_different_keys(self):
        km = KeyManager()
        key1 = km.derive_identity_key("prompt A", ["tool1"], "agent-1")
        
        km2 = KeyManager()
        key2 = km2.derive_identity_key("prompt B", ["tool1"], "agent-2")
        
        assert key1.public_bytes != key2.public_bytes

    def test_sign_and_verify(self):
        km = KeyManager()
        key = km.derive_identity_key("test", ["t1"], "agent-1")
        
        message = b"hello world"
        signature = key.sign(message)
        
        assert key.verify(message, signature)

    def test_verify_fails_with_wrong_message(self):
        km = KeyManager()
        key = km.derive_identity_key("test", ["t1"], "agent-1")
        
        signature = key.sign(b"original")
        assert not key.verify(b"tampered", signature)

    def test_transport_key_is_random(self):
        km = KeyManager()
        km.derive_identity_key("test", ["t1"], "agent-1")
        t1 = km.generate_transport_key("agent-1")
        
        km2 = KeyManager()
        km2.derive_identity_key("test", ["t1"], "agent-1")
        t2 = km2.generate_transport_key("agent-1")
        
        # Transport keys should be different (random)
        assert t1.public_bytes != t2.public_bytes

    def test_transport_key_rotation(self):
        km = KeyManager(rotation_interval_seconds=1)
        km.derive_identity_key("test", ["t1"], "agent-1")
        t1 = km.generate_transport_key("agent-1")
        t2 = km.rotate_transport_key("agent-1")
        
        assert t1.public_bytes != t2.public_bytes


class TestAgentIDManager:
    """Test agent identity management."""

    def test_register_agent(self):
        manager = AgentIDManager()
        identity = manager.register_agent(
            system_prompt="You are a test agent",
            tool_list=["search"],
            organization="test-org",
        )
        
        assert identity.organization == "test-org"
        assert identity.public_key is not None
        assert len(identity.fingerprint) == 16

    def test_duplicate_fingerprint_rejected(self):
        manager = AgentIDManager()
        manager.register_agent(
            system_prompt="test",
            tool_list=["tool1"],
            organization="org1",
        )
        
        with pytest.raises(DuplicateIdentityError):
            manager.register_agent(
                system_prompt="test",
                tool_list=["tool1"],
                organization="org2",
            )

    def test_sign_and_verify_message(self):
        manager = AgentIDManager()
        identity = manager.register_agent(
            system_prompt="test",
            tool_list=["t1"],
            organization="org",
        )
        
        msg = b"important message"
        sig = manager.sign_message(identity.agent_id, msg)
        assert manager.verify_agent(identity.agent_id, msg, sig)

    def test_revoke_identity(self):
        manager = AgentIDManager()
        identity = manager.register_agent(
            system_prompt="test",
            tool_list=["t1"],
            organization="org",
        )
        
        assert manager.revoke_identity(identity.agent_id)
        assert manager.get_identity(identity.agent_id) is None

    def test_list_agents_by_org(self):
        manager = AgentIDManager()
        manager.register_agent("p1", ["t1"], "acme")
        manager.register_agent("p2", ["t2"], "acme")
        manager.register_agent("p3", ["t3"], "other")
        
        acme_agents = manager.list_agents("acme")
        assert len(acme_agents) == 2
