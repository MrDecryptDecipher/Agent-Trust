"""
Configuration management for agent-trust.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TrustGraphConfig:
    """Configuration for TrustGraph module."""
    max_delegation_depth: int = 3
    auto_revoke_on_violation: bool = True
    alert_on_transitive_trust: bool = True
    graph_update_interval_seconds: float = 1.0
    max_agents: int = 10_000
    enable_redis_pubsub: bool = False
    redis_url: str = "redis://localhost:6379/0"
    redis_channel: str = "agent-trust:alerts"


@dataclass
class AgentIDConfig:
    """Configuration for AgentID module."""
    transport_key_rotation_seconds: int = 3600  # 1 hour
    identity_key_algorithm: str = "ed25519"
    key_storage_path: str = ".agent-trust/keys"
    enable_key_escrow: bool = False


@dataclass
class ReputationConfig:
    """Configuration for ReputationLedger module."""
    db_path: str = ".agent-trust/reputation.db"
    merkle_hash_algorithm: str = "sha256"
    min_interactions_for_score: int = 5
    score_decay_days: int = 90
    enable_cross_org_queries: bool = True
    max_records_per_query: int = 1000


@dataclass
class ConsentAuditConfig:
    """Configuration for ConsentAudit module."""
    db_path: str = ".agent-trust/consent.db"
    max_chain_depth: int = 10
    default_consent_ttl_seconds: int = 300  # 5 minutes
    require_explicit_scope: bool = True
    compliance_standards: list[str] = field(
        default_factory=lambda: ["gdpr", "soc2"]
    )
    jwt_algorithm: str = "EdDSA"
    jwt_issuer: str = "agent-trust"


@dataclass
class EastWestMonitorConfig:
    """Configuration for EastWestMonitor module."""
    db_path: str = ".agent-trust/monitor.db"
    anomaly_threshold: float = 0.75
    retention_days: int = 30
    sample_rate: float = 1.0  # 1.0 = capture everything
    max_events_per_second: int = 10_000
    enable_real_time_dashboard: bool = True


@dataclass
class ScopedTokenConfig:
    """Configuration for ScopedToken module."""
    max_token_ttl_seconds: int = 300  # 5 minutes
    default_token_ttl_seconds: int = 60  # 1 minute
    enable_single_use: bool = True
    enforce_agent_pair_binding: bool = True
    token_algorithm: str = "EdDSA"
    max_scopes_per_token: int = 3


@dataclass
class APIConfig:
    """Configuration for the API server."""
    host: str = "0.0.0.0"
    port: int = 8730
    enable_cors: bool = True
    cors_origins: list[str] = field(default_factory=lambda: ["*"])
    api_key: Optional[str] = None
    enable_dashboard: bool = True


@dataclass
class TrustConfig:
    """
    Root configuration object for the entire agent-trust system.
    
    Usage:
        config = TrustConfig()
        config.trust_graph.max_delegation_depth = 5
        config.scoped_token.max_token_ttl_seconds = 120
    """
    trust_graph: TrustGraphConfig = field(default_factory=TrustGraphConfig)
    agent_id: AgentIDConfig = field(default_factory=AgentIDConfig)
    reputation: ReputationConfig = field(default_factory=ReputationConfig)
    consent_audit: ConsentAuditConfig = field(default_factory=ConsentAuditConfig)
    east_west_monitor: EastWestMonitorConfig = field(
        default_factory=EastWestMonitorConfig
    )
    scoped_token: ScopedTokenConfig = field(default_factory=ScopedTokenConfig)
    api: APIConfig = field(default_factory=APIConfig)
    
    # Global settings
    log_level: str = "INFO"
    data_dir: str = ".agent-trust"
    enable_all_modules: bool = True
