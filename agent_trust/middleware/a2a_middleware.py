"""
AgentTrustMiddleware — The unified entry point that ties
all 6 modules together into a drop-in middleware layer.

This is what you actually integrate into your A2A system.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Optional

from agent_trust.config import TrustConfig
from agent_trust.agent_id import AgentIDManager
from agent_trust.trust_graph import TrustGraph, CascadeDetector, AlertManager
from agent_trust.reputation_ledger import ReputationLedger, ReputationQuery
from agent_trust.consent_audit import ConsentChainManager, ComplianceChecker
from agent_trust.east_west_monitor import A2AInterceptor, TrafficAnalyzer, EventStore
from agent_trust.scoped_token import ScopedTokenManager
from agent_trust.utils.storage import SQLiteStorage
from agent_trust.types import (
    AgentIdentity,
    ComplianceStandard,
    InteractionRecord,
    TokenScope,
    TrustLevel,
    TrustAlert,
    AlertSeverity,
)

logger = logging.getLogger(__name__)


class AgentTrustMiddleware:
    """
    The unified middleware layer that sits between A2A agents.
    
    Integrates all 6 modules:
    1. AgentID — Persistent cryptographic identity
    2. TrustGraph — Cascading attack detection
    3. ScopedToken — Task-scoped credentials
    4. ConsentAudit — Consent chain management
    5. ReputationLedger — Cross-org trust scores
    6. EastWestMonitor — Traffic visibility
    
    Usage:
        # Initialize
        middleware = AgentTrustMiddleware()
        
        # Register agents
        agent_a = middleware.register_agent(
            system_prompt="You are an analyst...",
            tool_list=["search", "calculate"],
            organization="acme-corp",
        )
        agent_b = middleware.register_agent(
            system_prompt="You are a data retriever...",
            tool_list=["fetch", "parse"],
            organization="acme-corp",
        )
        
        # Establish trust
        middleware.establish_trust(
            source_id=agent_a.agent_id,
            target_id=agent_b.agent_id,
            trust_level=TrustLevel.VERIFIED,
            scopes=[TokenScope.READ, TokenScope.EXECUTE],
        )
        
        # Authorize a task (creates token + consent chain)
        auth = middleware.authorize_task(
            source_id=agent_a.agent_id,
            target_id=agent_b.agent_id,
            task_type="data_retrieval",
            scopes=[TokenScope.READ],
        )
        
        # Validate before execution
        middleware.validate_authorization(
            token=auth["token"],
            presenter_id=agent_b.agent_id,
            task_type="data_retrieval",
        )
        
        # Record outcome
        middleware.record_interaction(
            source_id=agent_a.agent_id,
            target_id=agent_b.agent_id,
            task_type="data_retrieval",
            success=True,
            latency_ms=340,
        )
    """

    def __init__(self, config: Optional[TrustConfig] = None):
        self._config = config or TrustConfig()
        self._signing_key = uuid.uuid4().hex
        
        # Initialize Storage
        self.storage = SQLiteStorage(self._config.sqlite_db_path)
        
        # Initialize all modules
        self.agent_id = AgentIDManager(self._config.agent_id)
        self.trust_graph = TrustGraph(self._config.trust_graph, storage=self.storage)
        self.alert_manager = AlertManager(self._config.trust_graph)
        self.scoped_token = ScopedTokenManager(
            self._config.scoped_token, self._signing_key
        )
        self.consent_audit = ConsentChainManager(
            self._signing_key, self._config.consent_audit
        )
        self.reputation = ReputationLedger(self._config.reputation, storage=self.storage)
        self.reputation_query = ReputationQuery(self.reputation)
        self.interceptor = A2AInterceptor(
            self._config.east_west_monitor,
            event_callback=self._on_traffic_event,
        )
        self.traffic_analyzer = TrafficAnalyzer(
            self._config.east_west_monitor
        )
        self.event_store = EventStore(
            self._config.east_west_monitor.db_path
        )
        self.compliance = ComplianceChecker()
        
        # Wire up cascade detector
        self._cascade_detector = CascadeDetector(
            self.trust_graph._graph,
            self.trust_graph._edges,
            self._config.trust_graph,
        )
        
        logger.info("AgentTrustMiddleware initialized with all 6 modules")

    def register_agent(
        self,
        system_prompt: str,
        tool_list: list[str],
        organization: str,
        agent_id: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> AgentIdentity:
        """
        Register an agent — creates identity and adds to trust graph.
        """
        identity = self.agent_id.register_agent(
            system_prompt=system_prompt,
            tool_list=tool_list,
            organization=organization,
            agent_id=agent_id,
            metadata=metadata,
        )
        
        self.trust_graph.add_agent(identity, TrustLevel.PROVISIONAL)
        
        logger.info(f"Agent registered: {identity}")
        return identity

    def establish_trust(
        self,
        source_id: str,
        target_id: str,
        trust_level: TrustLevel = TrustLevel.BASIC,
        scopes: Optional[list[TokenScope]] = None,
        max_depth: int = 1,
        ttl_seconds: Optional[float] = None,
    ) -> dict:
        """
        Establish a trust relationship between two agents.
        Records in the trust graph and creates initial consent.
        """
        edge = self.trust_graph.add_trust_edge(
            source_id=source_id,
            target_id=target_id,
            trust_level=trust_level,
            scopes=scopes,
            max_depth=max_depth,
            ttl_seconds=ttl_seconds,
        )
        
        return {
            "source_id": source_id,
            "target_id": target_id,
            "trust_level": trust_level.name,
            "scopes": [s.value for s in (scopes or [])],
            "max_depth": max_depth,
            "alerts": [
                {"type": a.alert_type, "message": a.message}
                for a in self.trust_graph.alerts[-5:]
            ],
        }

    def authorize_task(
        self,
        source_id: str,
        target_id: str,
        task_type: str,
        task_description: str = "",
        scopes: Optional[list[TokenScope]] = None,
        ttl_seconds: Optional[int] = None,
    ) -> dict:
        """
        Authorize a task delegation.
        Creates both a scoped token and a consent chain record.
        """
        effective_scopes = scopes or [TokenScope.READ]
        
        # Get trust level for token policy
        trust_level = self.trust_graph.get_trust_level(
            source_id, target_id
        )
        
        # Issue scoped token
        token = self.scoped_token.issue_token(
            issuer_id=source_id,
            subject_id=target_id,
            scopes=effective_scopes,
            task_type=task_type,
            trust_level=trust_level.value,
            ttl_seconds=ttl_seconds,
        )
        
        # Create consent chain
        chain_id, consent = self.consent_audit.create_chain(
            grantor_id=source_id,
            grantee_id=target_id,
            scopes=effective_scopes,
            task_type=task_type,
            task_description=task_description,
            ttl_seconds=ttl_seconds,
        )
        
        # Record the traffic event
        self.interceptor.record_event(
            source=source_id,
            target=target_id,
            method="AUTHORIZE",
            endpoint=f"/tasks/{task_type}",
        )
        
        return {
            "token": token,
            "chain_id": chain_id,
            "consent_id": consent.consent_id,
            "trust_level": trust_level.name,
            "scopes": [s.value for s in effective_scopes],
            "task_type": task_type,
        }

    def validate_authorization(
        self,
        token: str,
        presenter_id: str,
        task_type: str = "",
        required_scope: Optional[TokenScope] = None,
    ) -> dict:
        """Validate that an agent is authorized to perform a task."""
        claims = self.scoped_token.validate_token(
            token=token,
            presenter_id=presenter_id,
            task_type=task_type,
            required_scope=required_scope,
        )
        
        return claims

    def delegate_task(
        self,
        chain_id: str,
        from_agent_id: str,
        to_agent_id: str,
        scopes: list[TokenScope],
        task_type: str,
        task_description: str = "",
    ) -> dict:
        """
        Delegate a task further down the chain.
        Extends the consent chain and issues a new scoped token.
        """
        # Extend consent chain
        consent = self.consent_audit.extend_chain(
            chain_id=chain_id,
            grantor_id=from_agent_id,
            grantee_id=to_agent_id,
            scopes=scopes,
            task_type=task_type,
            task_description=task_description,
        )
        
        # Get trust level
        trust_level = self.trust_graph.get_trust_level(
            from_agent_id, to_agent_id
        )
        
        # Issue new token for this hop
        token = self.scoped_token.issue_token(
            issuer_id=from_agent_id,
            subject_id=to_agent_id,
            scopes=scopes,
            task_type=task_type,
            trust_level=trust_level.value,
        )
        
        # Record traffic
        self.interceptor.record_event(
            source=from_agent_id,
            target=to_agent_id,
            method="DELEGATE",
            endpoint=f"/tasks/{task_type}",
        )
        
        return {
            "token": token,
            "chain_id": chain_id,
            "consent_id": consent.consent_id,
            "hop_index": consent.hop_index,
        }

    def record_interaction(
        self,
        source_id: str,
        target_id: str,
        task_type: str,
        success: bool = True,
        latency_ms: float = 0.0,
        policy_violations: int = 0,
        metadata: Optional[dict] = None,
    ) -> dict:
        """Record the outcome of an agent interaction."""
        record = InteractionRecord(
            source_agent_id=source_id,
            target_agent_id=target_id,
            task_type=task_type,
            success=success,
            latency_ms=latency_ms,
            policy_violations=policy_violations,
            completed_at=time.time(),
            metadata=metadata or {},
        )
        
        # Trigger immediate alert if policy violations are present
        if policy_violations > 0:
            alert = TrustAlert(
                severity=AlertSeverity.CRITICAL,
                alert_type="policy_violation",
                message=f"Security violation detected: {task_type} (Source: {source_id})",
                source_agent_id=source_id,
                target_agent_id=target_id,
                metadata={"interaction_id": record.interaction_id}
            )
            self.trust_graph.add_alert(alert)
        
        # Add to reputation ledger
        index = self.reputation.record_interaction(record)
        
        # Record traffic
        self.interceptor.record_event(
            source=source_id,
            target=target_id,
            method="COMPLETED",
            latency_ms=latency_ms,
            status_code=200 if success else 500,
        )
        
        return {
            "interaction_id": record.interaction_id,
            "merkle_index": index,
            "merkle_root": self.reputation.merkle_root,
        }

    def run_security_scan(self) -> dict:
        """
        Run a full security scan across all modules.
        """
        # Cascade detection
        cascade_alerts = self._cascade_detector.run_full_scan()
        
        # Reputation integrity
        reputation_valid = self.reputation.verify_integrity()
        
        # Token cleanup
        expired_tokens = self.scoped_token.cleanup_expired()
        
        # Graph stats
        graph_stats = self.trust_graph.get_graph_stats()
        
        return {
            "timestamp": time.time(),
            "cascade_alerts": len(cascade_alerts),
            "cascade_alert_details": [
                {
                    "type": a.alert_type,
                    "severity": a.severity.value,
                    "message": a.message,
                    "chain": a.chain,
                }
                for a in cascade_alerts
            ],
            "reputation_integrity": reputation_valid,
            "expired_tokens_cleaned": expired_tokens,
            "graph_stats": graph_stats,
            "token_stats": self.scoped_token.get_stats(),
            "consent_stats": self.consent_audit.get_stats(),
            "reputation_stats": self.reputation.get_stats(),
        }

    def get_compliance_report(
        self,
        chain_id: str,
        standards: Optional[list[ComplianceStandard]] = None,
    ) -> dict:
        """Generate a compliance report for a consent chain."""
        records = self.consent_audit.get_chain(chain_id)
        reports = self.compliance.check_all(records, standards)
        
        return {
            "chain_id": chain_id,
            "chain_summary": (
                self.consent_audit.get_chain_summary(chain_id)
            ),
            "compliance": {
                std.value: {
                    "passed": report.passed,
                    "checks": f"{report.checks_passed}/{report.checks_performed}",
                    "violations": report.violations,
                    "recommendations": report.recommendations,
                }
                for std, report in reports.items()
            },
        }

    def get_dashboard_data(self) -> dict:
        """Get all data needed for the dashboard UI."""
        return {
            "trust_graph": self.trust_graph.export_graph_data(),
            "graph_stats": self.trust_graph.get_graph_stats(),
            "traffic": self.traffic_analyzer.get_dashboard_data(),
            "reputation": {
                "stats": self.reputation.get_stats(),
                "leaderboard": [
                    s.to_dict()
                    for s in self.reputation.get_leaderboard()
                ],
            },
            "tokens": self.scoped_token.get_stats(),
            "consent": self.consent_audit.get_stats(),
            "alerts": [
                {
                    "id": a.alert_id,
                    "severity": a.severity.value,
                    "message": a.message,
                    "timestamp": a.timestamp,
                    "acknowledged": a.metadata.get("acknowledged", False),
                }
                for a in self.trust_graph.alerts[-50:]
            ],
        }

    def _on_traffic_event(self, event: Any) -> None:
        """Callback for intercepted traffic events."""
        from agent_trust.types import MonitorEvent
        if isinstance(event, MonitorEvent):
            self.traffic_analyzer.analyze_event(event)
