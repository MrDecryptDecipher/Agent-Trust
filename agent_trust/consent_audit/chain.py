"""
Consent chain manager — builds, stores, and queries
cryptographically signed consent chains.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Optional

from agent_trust.config import ConsentAuditConfig
from agent_trust.consent_audit.signer import ConsentSigner
from agent_trust.exceptions import (
    ConsentChainBrokenError,
    ConsentExpiredError,
    ConsentScopeViolation,
)
from agent_trust.types import ConsentRecord, TokenScope

logger = logging.getLogger(__name__)


class ConsentChainManager:
    """
    Manages consent chains — cryptographically linked sequences
    of authorization decisions.
    
    When Agent A delegates to Agent B, which delegates to Agent C:
    - A ConsentRecord is created for A→B
    - A ConsentRecord is created for B→C, linked to A→B
    - The resulting chain is: A→B→C
    
    Each hop records:
    - Who authorized (grantor)
    - Who received (grantee)
    - Under what scope
    - With what expiry
    - For what specific task
    
    Usage:
        manager = ConsentChainManager(signing_key="secret")
        
        # Start a new chain
        chain_id, record = manager.create_chain(
            grantor_id="agent-a",
            grantee_id="agent-b",
            scopes=[TokenScope.READ, TokenScope.EXECUTE],
            task_type="data_analysis",
        )
        
        # Extend the chain
        record2 = manager.extend_chain(
            chain_id=chain_id,
            grantor_id="agent-b",
            grantee_id="agent-c",
            scopes=[TokenScope.READ],
            task_type="data_retrieval",
        )
        
        # Verify the entire chain
        is_valid = manager.verify_chain(chain_id)
    """

    def __init__(
        self,
        signing_key: str,
        config: Optional[ConsentAuditConfig] = None,
    ):
        self._config = config or ConsentAuditConfig()
        self._signer = ConsentSigner(signing_key, self._config)
        self._chains: dict[str, list[ConsentRecord]] = {}
        self._records_by_id: dict[str, ConsentRecord] = {}

    def create_chain(
        self,
        grantor_id: str,
        grantee_id: str,
        scopes: list[TokenScope],
        task_type: str,
        task_description: str = "",
        ttl_seconds: Optional[int] = None,
        metadata: Optional[dict] = None,
    ) -> tuple[str, ConsentRecord]:
        """
        Create a new consent chain with the first hop.
        
        Returns (chain_id, first_record).
        """
        chain_id = str(uuid.uuid4())
        ttl = ttl_seconds or self._config.default_consent_ttl_seconds
        now = time.time()

        record = ConsentRecord(
            chain_id=chain_id,
            hop_index=0,
            grantor_agent_id=grantor_id,
            grantee_agent_id=grantee_id,
            scopes=scopes,
            task_type=task_type,
            task_description=task_description,
            granted_at=now,
            expires_at=now + ttl,
            parent_consent_id=None,
            metadata=metadata or {},
        )

        # Sign the record
        self._signer.sign_consent(record)

        # Store
        self._chains[chain_id] = [record]
        self._records_by_id[record.consent_id] = record

        logger.info(
            f"Created consent chain {chain_id[:8]}...: "
            f"{grantor_id} → {grantee_id} "
            f"(scopes: {[s.value for s in scopes]}, TTL: {ttl}s)"
        )

        return chain_id, record

    def extend_chain(
        self,
        chain_id: str,
        grantor_id: str,
        grantee_id: str,
        scopes: list[TokenScope],
        task_type: str,
        task_description: str = "",
        ttl_seconds: Optional[int] = None,
        metadata: Optional[dict] = None,
    ) -> ConsentRecord:
        """
        Extend an existing consent chain with a new hop.
        
        Validates:
        1. The chain exists and hasn't expired
        2. The grantor is the grantee of the last hop
        3. Requested scopes don't exceed parent scopes
        4. Chain depth doesn't exceed maximum
        """
        chain = self._chains.get(chain_id)
        if chain is None:
            raise ConsentChainBrokenError(
                f"Chain {chain_id[:8]}... not found"
            )

        # Check depth limit
        if len(chain) >= self._config.max_chain_depth:
            raise ConsentChainBrokenError(
                f"Chain depth {len(chain)} exceeds maximum "
                f"{self._config.max_chain_depth}"
            )

        # Get the last hop
        last_hop = chain[-1]

        # Check expiry
        if last_hop.is_expired:
            raise ConsentExpiredError(
                f"Last hop in chain {chain_id[:8]}... has expired"
            )

        # Check that grantor matches last hop's grantee
        if grantor_id != last_hop.grantee_agent_id:
            raise ConsentChainBrokenError(
                f"Grantor {grantor_id} is not the grantee of "
                f"the previous hop ({last_hop.grantee_agent_id})"
            )

        # Check scope restriction (new scopes must be subset of parent)
        if self._config.require_explicit_scope:
            parent_scopes = set(last_hop.scopes)
            new_scopes = set(scopes)
            if not new_scopes.issubset(parent_scopes):
                escalated = new_scopes - parent_scopes
                raise ConsentScopeViolation(
                    f"Scope escalation in chain {chain_id[:8]}...: "
                    f"{[s.value for s in escalated]} not in parent scopes "
                    f"{[s.value for s in last_hop.scopes]}"
                )

        # Create the new hop
        ttl = ttl_seconds or self._config.default_consent_ttl_seconds
        # New hop can't outlive parent
        max_expiry = last_hop.expires_at
        now = time.time()
        effective_expiry = min(now + ttl, max_expiry)

        record = ConsentRecord(
            chain_id=chain_id,
            hop_index=len(chain),
            grantor_agent_id=grantor_id,
            grantee_agent_id=grantee_id,
            scopes=scopes,
            task_type=task_type,
            task_description=task_description,
            granted_at=now,
            expires_at=effective_expiry,
            parent_consent_id=last_hop.consent_id,
            metadata=metadata or {},
        )

        # Sign
        self._signer.sign_consent(record)

        # Store
        chain.append(record)
        self._records_by_id[record.consent_id] = record

        logger.info(
            f"Extended chain {chain_id[:8]}... (hop {record.hop_index}): "
            f"{grantor_id} → {grantee_id}"
        )

        return record

    def verify_chain(self, chain_id: str) -> bool:
        """
        Verify the cryptographic integrity of an entire chain.
        
        Checks all signatures and chain linkage.
        """
        chain = self._chains.get(chain_id)
        if chain is None:
            return False

        tokens = [record.signature for record in chain]
        
        try:
            self._signer.verify_chain(tokens)
            return True
        except Exception as e:
            logger.error(
                f"Chain {chain_id[:8]}... verification failed: {e}"
            )
            return False

    def get_chain(self, chain_id: str) -> list[ConsentRecord]:
        """Get all records in a consent chain."""
        return list(self._chains.get(chain_id, []))

    def get_chain_summary(self, chain_id: str) -> dict:
        """Get a human-readable summary of a consent chain."""
        chain = self._chains.get(chain_id, [])
        if not chain:
            return {"error": "Chain not found"}

        hops = []
        for record in chain:
            hops.append({
                "hop": record.hop_index,
                "from": record.grantor_agent_id,
                "to": record.grantee_agent_id,
                "scopes": [s.value for s in record.scopes],
                "task": record.task_type,
                "expired": record.is_expired,
            })

        return {
            "chain_id": chain_id,
            "total_hops": len(chain),
            "origin": chain[0].grantor_agent_id,
            "terminal": chain[-1].grantee_agent_id,
            "path": " → ".join(
                [chain[0].grantor_agent_id]
                + [r.grantee_agent_id for r in chain]
            ),
            "hops": hops,
            "all_valid": self.verify_chain(chain_id),
        }

    def revoke_chain(self, chain_id: str) -> bool:
        """Revoke an entire consent chain."""
        chain = self._chains.get(chain_id)
        if chain is None:
            return False
        
        # Set all records to expired
        for record in chain:
            record.expires_at = 0
        
        logger.warning(f"Revoked consent chain {chain_id[:8]}...")
        return True

    def find_chains_for_agent(
        self, agent_id: str
    ) -> list[str]:
        """Find all chain IDs that involve a specific agent."""
        result = []
        for chain_id, chain in self._chains.items():
            for record in chain:
                if (
                    record.grantor_agent_id == agent_id
                    or record.grantee_agent_id == agent_id
                ):
                    result.append(chain_id)
                    break
        return result

    def export_audit_trail(
        self, chain_id: str
    ) -> list[dict[str, Any]]:
        """
        Export a chain as a compliance-ready audit trail.
        
        Returns data suitable for GDPR, PSD2, SOC2, HIPAA auditors.
        """
        chain = self._chains.get(chain_id, [])
        trail = []
        
        for record in chain:
            trail.append({
                "consent_id": record.consent_id,
                "chain_id": record.chain_id,
                "hop_index": record.hop_index,
                "grantor_agent_id": record.grantor_agent_id,
                "grantee_agent_id": record.grantee_agent_id,
                "scopes": [s.value for s in record.scopes],
                "task_type": record.task_type,
                "task_description": record.task_description,
                "granted_at_iso": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ",
                    time.gmtime(record.granted_at)
                ),
                "expires_at_iso": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ",
                    time.gmtime(record.expires_at)
                ),
                "parent_consent_id": record.parent_consent_id,
                "signature_present": bool(record.signature),
                "is_expired": record.is_expired,
                "metadata": record.metadata,
            })
        
        return trail

    def get_stats(self) -> dict:
        """Get consent chain statistics."""
        total_records = sum(len(c) for c in self._chains.values())
        expired_chains = sum(
            1 for c in self._chains.values()
            if any(r.is_expired for r in c)
        )
        
        return {
            "total_chains": len(self._chains),
            "total_records": total_records,
            "expired_chains": expired_chains,
            "active_chains": len(self._chains) - expired_chains,
            "avg_chain_depth": (
                total_records / len(self._chains)
                if self._chains else 0
            ),
        }
