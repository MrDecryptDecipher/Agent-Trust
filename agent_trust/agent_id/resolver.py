"""
Identity resolver for cross-network agent lookup.

Resolves agent identities across organizations by fingerprint
or public key, enabling trust decisions about external agents.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from agent_trust.types import AgentIdentity

logger = logging.getLogger(__name__)


@dataclass
class ResolverEntry:
    """A cached identity resolver entry."""
    identity: AgentIdentity
    resolved_at: float = field(default_factory=time.time)
    source: str = "local"  # "local", "remote", "cached"
    ttl_seconds: float = 3600.0

    @property
    def is_stale(self) -> bool:
        return time.time() > (self.resolved_at + self.ttl_seconds)


class IdentityResolver:
    """
    Resolves agent identities across organizational boundaries.
    
    Maintains a local cache of known identities and supports
    remote resolution for cross-organization lookups.
    
    Usage:
        resolver = IdentityResolver()
        resolver.register_local(identity)
        
        # Later, when you need to verify an external agent:
        resolved = resolver.resolve_by_fingerprint("abc123...")
    """

    def __init__(self, cache_ttl_seconds: float = 3600.0):
        self._cache_ttl = cache_ttl_seconds
        self._by_id: dict[str, ResolverEntry] = {}
        self._by_fingerprint: dict[str, ResolverEntry] = {}
        self._by_public_key: dict[bytes, ResolverEntry] = {}

    def register_local(self, identity: AgentIdentity) -> None:
        """Register a local (owned) identity in the resolver."""
        entry = ResolverEntry(
            identity=identity,
            source="local",
            ttl_seconds=float("inf"),  # Local entries never expire
        )
        self._index_entry(entry)
        logger.debug(f"Registered local identity: {identity.agent_id}")

    def register_remote(
        self,
        identity: AgentIdentity,
        source: str = "remote",
    ) -> None:
        """Register a remote (external) identity in the resolver."""
        entry = ResolverEntry(
            identity=identity,
            source=source,
            ttl_seconds=self._cache_ttl,
        )
        self._index_entry(entry)
        logger.debug(
            f"Registered remote identity: {identity.agent_id} "
            f"from {source}"
        )

    def resolve_by_id(self, agent_id: str) -> Optional[AgentIdentity]:
        """Resolve an agent identity by agent ID."""
        entry = self._by_id.get(agent_id)
        if entry is None:
            return None
        if entry.is_stale:
            self._evict(entry)
            return None
        return entry.identity

    def resolve_by_fingerprint(
        self, fingerprint: str
    ) -> Optional[AgentIdentity]:
        """Resolve an agent identity by behavioral fingerprint."""
        entry = self._by_fingerprint.get(fingerprint)
        if entry is None:
            return None
        if entry.is_stale:
            self._evict(entry)
            return None
        return entry.identity

    def resolve_by_public_key(
        self, public_key: bytes
    ) -> Optional[AgentIdentity]:
        """Resolve an agent identity by public key."""
        entry = self._by_public_key.get(public_key)
        if entry is None:
            return None
        if entry.is_stale:
            self._evict(entry)
            return None
        return entry.identity

    def list_all(
        self,
        source: Optional[str] = None,
        organization: Optional[str] = None,
    ) -> list[AgentIdentity]:
        """List all known identities with optional filtering."""
        entries = self._by_id.values()
        result = []
        for entry in entries:
            if entry.is_stale:
                continue
            if source and entry.source != source:
                continue
            if organization and entry.identity.organization != organization:
                continue
            result.append(entry.identity)
        return result

    def evict_stale(self) -> int:
        """Remove all stale cache entries. Returns number evicted."""
        stale = [
            entry for entry in self._by_id.values()
            if entry.is_stale
        ]
        for entry in stale:
            self._evict(entry)
        return len(stale)

    def _index_entry(self, entry: ResolverEntry) -> None:
        """Index an entry by all lookup keys."""
        identity = entry.identity
        self._by_id[identity.agent_id] = entry
        self._by_fingerprint[identity.fingerprint] = entry
        self._by_public_key[identity.public_key] = entry

    def _evict(self, entry: ResolverEntry) -> None:
        """Remove an entry from all indices."""
        identity = entry.identity
        self._by_id.pop(identity.agent_id, None)
        self._by_fingerprint.pop(identity.fingerprint, None)
        self._by_public_key.pop(identity.public_key, None)

    @property
    def cache_size(self) -> int:
        return len(self._by_id)
