"""
Live directed graph of agent-to-agent trust relationships.

Uses NetworkX for graph operations and provides real-time
trust chain analysis.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import networkx as nx

from agent_trust.config import TrustGraphConfig
from agent_trust.exceptions import (
    AgentNotFoundError,
    CascadingTrustViolation,
    TrustRevocationError,
)
from agent_trust.types import (
    AgentIdentity,
    AlertSeverity,
    TokenScope,
    TrustAlert,
    TrustEdge,
    TrustLevel,
)
from agent_trust.utils.storage import SQLiteStorage
import json

logger = logging.getLogger(__name__)


class TrustGraph:
    """
    A live directed graph of trust relationships between agents.
    
    Every edge carries:
    - Trust level (0-5)
    - Granted scopes (read, write, execute, delegate, admin)
    - Maximum delegation depth
    - Expiry timestamp
    - Consent chain reference
    
    Usage:
        graph = TrustGraph()
        graph.add_agent(agent_a_identity)
        graph.add_agent(agent_b_identity)
        graph.add_trust_edge(
            source_id="agent-a",
            target_id="agent-b",
            trust_level=TrustLevel.VERIFIED,
            scopes=[TokenScope.READ, TokenScope.EXECUTE],
            max_depth=2,
        )
        
        # Check if a delegation chain is safe:
        chains = graph.find_trust_chains("agent-a", "agent-d")
        for chain in chains:
            print(f"Chain: {' → '.join(chain)}")
    """

    def __init__(self, config: Optional[TrustGraphConfig] = None, storage: Optional[SQLiteStorage] = None):
        self._config = config or TrustGraphConfig()
        self._storage = storage
        self._graph = nx.DiGraph()
        self._edges: dict[tuple[str, str], TrustEdge] = {}
        self._alerts: list[TrustAlert] = []
        self._revoked_edges: list[TrustEdge] = []
        
        # Load from storage if available
        if self._storage is not None:
            self._load_from_storage()

    @property
    def agent_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    @property
    def alerts(self) -> list[TrustAlert]:
        return list(self._alerts)

    def add_alert(self, alert: TrustAlert) -> None:
        """Add a security alert to the graph and storage."""
        self._alerts.append(alert)
        if self._storage is not None:
            self._storage.save_alert(alert)
        logger.warning(f"Alert added: {alert.alert_type} - {alert.message}")

    def get_graph_stats(self) -> dict:
        """Get summary statistics for the trust graph."""
        return {
            "total_agents": self.agent_count,
            "total_trust_edges": self.edge_count,
            "total_alerts": len(self._alerts),
            "revoked_edges": len(self._revoked_edges),
        }

    def add_agent(
        self,
        identity: AgentIdentity,
        initial_trust: TrustLevel = TrustLevel.UNTRUSTED,
    ) -> None:
        """Add an agent node to the trust graph."""
        self._graph.add_node(
            identity.agent_id,
            identity=identity,
            trust_level=initial_trust,
            added_at=time.time(),
        )
        storage = self._storage
        if storage is not None:
            storage.save_agent(identity)
            
        logger.info(
            f"Added agent {identity.agent_id} to trust graph "
            f"(trust level: {initial_trust.name})"
        )

    def remove_agent(self, agent_id: str) -> None:
        """
        Remove an agent and all its trust edges from the graph.
        This is the nuclear option.
        """
        if agent_id not in self._graph:
            raise AgentNotFoundError(f"Agent {agent_id} not in graph")
        
        # Collect and store revoked edges
        for pred in list(self._graph.predecessors(agent_id)):
            edge_key = (pred, agent_id)
            if edge_key in self._edges:
                self._revoked_edges.append(self._edges.pop(edge_key))
        
        for succ in list(self._graph.successors(agent_id)):
            edge_key = (agent_id, succ)
            if edge_key in self._edges:
                self._revoked_edges.append(self._edges.pop(edge_key))
        
        self._graph.remove_node(agent_id)
        logger.warning(f"Removed agent {agent_id} from trust graph")

    def add_trust_edge(
        self,
        source_id: str,
        target_id: str,
        trust_level: TrustLevel = TrustLevel.BASIC,
        scopes: Optional[list[TokenScope]] = None,
        max_depth: int = 1,
        ttl_seconds: Optional[float] = None,
        consent_chain_id: Optional[str] = None,
    ) -> TrustEdge:
        """
        Add a directed trust edge from source to target.
        
        Automatically checks if this creates a dangerous transitive
        chain and fires alerts if so.
        """
        if source_id not in self._graph:
            raise AgentNotFoundError(f"Source agent {source_id} not in graph")
        if target_id not in self._graph:
            raise AgentNotFoundError(f"Target agent {target_id} not in graph")

        now = time.time()
        expires_at = (now + ttl_seconds) if ttl_seconds else None

        edge = TrustEdge(
            source_id=source_id,
            target_id=target_id,
            trust_level=trust_level,
            granted_scopes=scopes or [],
            max_delegation_depth=max_depth,
            created_at=now,
            expires_at=expires_at,
            consent_chain_id=consent_chain_id,
        )

        self._graph.add_edge(
            source_id,
            target_id,
            trust_level=trust_level.value,
            scopes=[s.value for s in (scopes or [])],
            max_depth=max_depth,
            edge=edge,
        )
        self._edges[(source_id, target_id)] = edge

        storage = self._storage
        if storage is not None:
            storage.save_trust_edge(edge)

        logger.info(
            f"Trust edge: {source_id} → {target_id} "
            f"(level: {trust_level.name}, depth: {max_depth})"
        )

        # Check for cascading trust violations
        self._check_cascading_trust(source_id, target_id)

        return edge

    def remove_trust_edge(self, source_id: str, target_id: str) -> None:
        """Remove a trust edge between two agents."""
        edge_key = (source_id, target_id)
        if edge_key not in self._edges:
            raise TrustRevocationError(
                f"No trust edge from {source_id} to {target_id}"
            )
        
        self._revoked_edges.append(self._edges.pop(edge_key))
        self._graph.remove_edge(source_id, target_id)
        logger.info(f"Removed trust edge: {source_id} → {target_id}")

    def get_trust_edge(
        self, source_id: str, target_id: str
    ) -> Optional[TrustEdge]:
        """Get the trust edge between two agents."""
        edge = self._edges.get((source_id, target_id))
        if edge and edge.is_expired:
            # Auto-cleanup expired edges
            self.remove_trust_edge(source_id, target_id)
            return None
        return edge

    def get_trust_level(
        self, source_id: str, target_id: str
    ) -> TrustLevel:
        """Get the direct trust level from source to target."""
        edge = self.get_trust_edge(source_id, target_id)
        if edge is None:
            return TrustLevel.UNTRUSTED
        return edge.trust_level

    def find_trust_chains(
        self,
        source_id: str,
        target_id: str,
        max_depth: Optional[int] = None,
    ) -> list[list[str]]:
        """
        Find all trust chains from source to target.
        
        Returns a list of paths, where each path is a list of agent IDs.
        Paths longer than max_depth are flagged as violations.
        """
        if source_id not in self._graph or target_id not in self._graph:
            return []

        depth_limit = max_depth or self._config.max_delegation_depth
        
        try:
            paths = list(
                nx.all_simple_paths(
                    self._graph,
                    source_id,
                    target_id,
                    cutoff=depth_limit + 2,  # Look slightly beyond to detect violations
                )
            )
        except nx.NetworkXError:
            return []
        
        return paths

    def find_transitive_trust_violations(
        self,
    ) -> list[tuple[list[str], int]]:
        """
        Scan the entire graph for transitive trust chains that
        exceed the configured maximum delegation depth.
        
        Returns list of (path, max_allowed_depth) tuples.
        """
        violations = []
        max_depth = self._config.max_delegation_depth

        for node in self._graph.nodes():
            # Find all reachable nodes
            reachable = nx.single_source_shortest_path(
                self._graph, node, cutoff=max_depth + 3
            )
            
            for target, path in reachable.items():
                if len(path) - 1 > max_depth:
                    violations.append((path, max_depth))

        return violations

    def get_delegation_depth(
        self, source_id: str, target_id: str
    ) -> int:
        """Get the shortest delegation depth from source to target."""
        try:
            return nx.shortest_path_length(
                self._graph, source_id, target_id
            )
        except (nx.NetworkXError, nx.NodeNotFound):
            return -1

    def get_agents_trusting(self, agent_id: str) -> list[str]:
        """Get all agents that trust the given agent (predecessors)."""
        if agent_id not in self._graph:
            return []
        return list(self._graph.predecessors(agent_id))

    def get_agents_trusted_by(self, agent_id: str) -> list[str]:
        """Get all agents trusted by the given agent (successors)."""
        if agent_id not in self._graph:
            return []
        return list(self._graph.successors(agent_id))

    def revoke_chain(self, chain: list[str]) -> int:
        """
        Revoke all trust edges along a specific chain.
        Returns the number of edges revoked.
        """
        revoked = 0
        for i in range(len(chain) - 1):
            source, target = chain[i], chain[i + 1]
            try:
                self.remove_trust_edge(source, target)
                revoked = int(revoked) + 1
            except TrustRevocationError:
                pass
        
        logger.warning(
            f"Revoked {revoked} edges in chain: "
            f"{' → '.join(chain)}"
        )
        return revoked

    def get_graph_stats(self) -> dict:
        """Get statistics about the trust graph."""
        g = self._graph
        stats = {
            "total_agents": g.number_of_nodes(),
            "total_edges": g.number_of_edges(),
            "total_alerts": len(self._alerts),
            "total_revoked_edges": len(self._revoked_edges),
            "density": nx.density(g) if g.number_of_nodes() > 1 else 0,
            "is_dag": nx.is_directed_acyclic_graph(g),
            "strongly_connected_components": (
                nx.number_strongly_connected_components(g)
            ),
        }
        
        if g.number_of_nodes() > 0:
            in_degrees = [d for _, d in g.in_degree()]
            out_degrees = [d for _, d in g.out_degree()]
            stats["max_in_degree"] = max(in_degrees) if in_degrees else 0
            stats["max_out_degree"] = max(out_degrees) if out_degrees else 0
            stats["avg_in_degree"] = (
                sum(in_degrees) / len(in_degrees) if in_degrees else 0
            )
        
        return stats

    def export_graph_data(self) -> dict:
        """Export graph data for visualization."""
        nodes = []
        for node_id, data in self._graph.nodes(data=True):
            identity = data.get("identity")
            nodes.append({
                "id": node_id,
                "organization": identity.organization if identity else "unknown",
                "trust_level": data.get("trust_level", 0),
                "fingerprint": identity.fingerprint if identity else "",
            })

        edges = []
        for source, target, data in self._graph.edges(data=True):
            edge_obj = self._edges.get((source, target))
            edges.append({
                "source": source,
                "target": target,
                "trust_level": data.get("trust_level", 0),
                "scopes": data.get("scopes", []),
                "max_depth": data.get("max_depth", 1),
                "is_expired": edge_obj.is_expired if edge_obj else False,
            })

        return {"nodes": nodes, "edges": edges}

    def _check_cascading_trust(
        self, source_id: str, target_id: str
    ) -> None:
        """Check if adding this edge creates a cascading trust violation."""
        max_depth = self._config.max_delegation_depth

        # Check all paths that go THROUGH the target
        for predecessor in nx.ancestors(self._graph, source_id):
            try:
                path_len = nx.shortest_path_length(
                    self._graph, predecessor, target_id
                )
                if path_len > max_depth:
                    path = nx.shortest_path(
                        self._graph, predecessor, target_id
                    )
                    alert = TrustAlert(
                        severity=AlertSeverity.CRITICAL,
                        alert_type="cascading_trust_violation",
                        message=(
                            f"Transitive trust chain depth {path_len} "
                            f"exceeds maximum {max_depth}"
                        ),
                        source_agent_id=predecessor,
                        target_agent_id=target_id,
                        chain=path,
                    )
                    self._alerts.append(alert)
                    if self._storage is not None:
                        self._storage.save_alert(alert)
                    logger.critical(
                        f"CASCADING TRUST VIOLATION: "
                        f"{' → '.join(path)} "
                        f"(depth {path_len} > max {max_depth})"
                    )

                    if self._config.auto_revoke_on_violation:
                        self.revoke_chain(path)
                        alert.auto_action_taken = "chain_revoked"
                        logger.warning(
                            f"Auto-revoked chain: {' → '.join(path)}"
                        )

            except (nx.NetworkXError, nx.NodeNotFound):
                continue

    def _load_from_storage(self) -> None:
        """Load agents, edges, and alerts from persistent storage on startup."""
        storage = self._storage
        if storage is None:
            return
            
        # 1. Load Agents
        agent_rows = storage.get_agents()
        for row in agent_rows:
            identity = AgentIdentity(
                agent_id=row['agent_id'],
                organization=row['organization'],
                public_key=b"", # Rehydrated later or not needed for graph ops
                system_prompt_hash=row['system_prompt_hash'],
                tool_list_hash=row['tool_list_hash'],
                created_at=row['created_at'],
                metadata=json.loads(row['metadata']) if row['metadata'] else {}
            )
            # Add to graph without re-saving
            self._graph.add_node(
                identity.agent_id,
                identity=identity,
                trust_level=TrustLevel.BASIC, # Default for re-load
                added_at=identity.created_at,
            )
            
        # 2. Load Trust Edges
        edge_rows = storage.get_trust_edges()
        for row in edge_rows:
            sid, tid = str(row['source_id']), str(row['target_id'])
            if sid in self._graph and tid in self._graph:
                edge = TrustEdge(
                    source_id=sid,
                    target_id=tid,
                    trust_level=TrustLevel(int(row['trust_level'])),
                    granted_scopes=[TokenScope(s) for s in json.loads(row['scopes'])],
                    max_delegation_depth=int(row['max_depth']),
                    created_at=float(row['created_at']),
                    expires_at=float(row['expires_at']) if row['expires_at'] else None,
                )
                self._graph.add_edge(
                    sid, tid,
                    trust_level=edge.trust_level.value,
                    scopes=[s.value for s in edge.granted_scopes],
                    max_depth=edge.max_delegation_depth,
                    edge=edge
                )
                self._edges[(sid, tid)] = edge
                
        # 3. Load Recent Alerts
        alert_rows = storage.get_alerts(limit=100)
        for row in alert_rows:
            alert = TrustAlert(
                alert_id=row['alert_id'],
                severity=AlertSeverity(row['severity']),
                alert_type=row['alert_type'],
                message=row['message'],
                source_agent_id=row['source_id'],
                target_agent_id=row['target_id'],
                timestamp=row['timestamp'],
                metadata=json.loads(row['metadata']) if row['metadata'] else {}
            )
            self._alerts.append(alert)
            
        logger.info(
            f"Loaded {len(agent_rows)} agents, {len(edge_rows)} edges, "
            f"and {len(alert_rows)} alerts from persistent storage."
        )
