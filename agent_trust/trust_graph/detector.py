"""
Cascade attack detector for the trust graph.

Implements detection algorithms for:
- Transitive trust amplification
- Circular trust dependencies
- Scope escalation through delegation chains
- Anomalous trust pattern detection
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import networkx as nx

from agent_trust.config import TrustGraphConfig
from agent_trust.types import (
    AlertSeverity,
    TokenScope,
    TrustAlert,
    TrustLevel,
)

logger = logging.getLogger(__name__)


class CascadeDetector:
    """
    Detects cascading trust attacks in the trust graph.
    
    Attack types detected:
    1. Transitive Trust Amplification — Agent C gains Agent A's
       trust level through an indirect chain A→B→C without A's
       knowledge or consent.
    2. Circular Trust Dependencies — Agents forming a trust
       cycle that can be exploited for privilege escalation.
    3. Scope Escalation — A delegation chain where each hop
       gains broader permissions than the previous.
    4. Shadow Trust — Trust inherited through agents that the
       original grantor has never directly interacted with.
    
    Usage:
        detector = CascadeDetector(graph, config)
        alerts = detector.run_full_scan()
    """

    def __init__(
        self,
        graph: nx.DiGraph,
        edges: dict,
        config: Optional[TrustGraphConfig] = None,
    ):
        self._graph = graph
        self._edges = edges
        self._config = config or TrustGraphConfig()
        self._alerts: list[TrustAlert] = []

    @property
    def alerts(self) -> list[TrustAlert]:
        return list(self._alerts)

    def run_full_scan(self) -> list[TrustAlert]:
        """
        Run all detection algorithms and return aggregated alerts.
        """
        self._alerts.clear()
        
        self._detect_transitive_amplification()
        self._detect_circular_dependencies()
        self._detect_scope_escalation()
        self._detect_shadow_trust()
        
        logger.info(
            f"Full scan complete: {len(self._alerts)} alerts generated"
        )
        return list(self._alerts)

    def _detect_transitive_amplification(self) -> None:
        """
        Detect transitive trust amplification attacks.
        
        If Agent A trusts Agent B at level 3, and Agent B trusts
        Agent C at level 4, Agent C should NOT inherit level 3
        trust from Agent A — but in naive systems, it does.
        """
        max_depth = self._config.max_delegation_depth
        
        for node in self._graph.nodes():
            # Find all nodes reachable from this node
            reachable = nx.single_source_shortest_path(
                self._graph, node, cutoff=max_depth + 5
            )
            
            for target, path in reachable.items():
                depth = len(path) - 1
                if depth <= 1:
                    continue  # Direct trust is fine
                
                if depth > max_depth:
                    alert = TrustAlert(
                        severity=AlertSeverity.CRITICAL,
                        alert_type="transitive_amplification",
                        message=(
                            f"Agent {target} inherits trust from {node} "
                            f"through a chain of depth {depth} "
                            f"(max allowed: {max_depth})"
                        ),
                        source_agent_id=node,
                        target_agent_id=target,
                        chain=path,
                    )
                    self._alerts.append(alert)

    def _detect_circular_dependencies(self) -> None:
        """
        Detect circular trust dependencies.
        
        If A→B→C→A forms a cycle, any compromised agent in the
        cycle can amplify its privileges indefinitely.
        """
        try:
            cycles = list(nx.simple_cycles(self._graph))
        except nx.NetworkXError:
            return

        for cycle in cycles:
            if len(cycle) < 2:
                continue
            
            # Close the cycle for display
            display_chain = cycle + [cycle[0]]
            
            alert = TrustAlert(
                severity=AlertSeverity.EMERGENCY,
                alert_type="circular_trust_dependency",
                message=(
                    f"Circular trust dependency detected involving "
                    f"{len(cycle)} agents: {' → '.join(display_chain)}"
                ),
                source_agent_id=cycle[0],
                chain=display_chain,
            )
            self._alerts.append(alert)
            logger.critical(
                f"CIRCULAR TRUST: {' → '.join(display_chain)}"
            )

    def _detect_scope_escalation(self) -> None:
        """
        Detect scope escalation through delegation chains.
        
        If A grants B [read] scope, and B grants C [read, write]
        scope, C has escalated beyond what A authorized.
        """
        scope_hierarchy = {
            TokenScope.READ: 1,
            TokenScope.WRITE: 2,
            TokenScope.EXECUTE: 3,
            TokenScope.DELEGATE: 4,
            TokenScope.ADMIN: 5,
        }
        
        for node in self._graph.nodes():
            for target in nx.descendants(self._graph, node):
                paths = list(
                    nx.all_simple_paths(
                        self._graph, node, target,
                        cutoff=self._config.max_delegation_depth + 2
                    )
                )
                
                for path in paths:
                    if len(path) < 3:
                        continue
                    
                    # Check if scopes escalate along the chain
                    prev_max_scope = 0
                    escalation_detected = False
                    
                    for i in range(len(path) - 1):
                        edge_key = (path[i], path[i + 1])
                        edge = self._edges.get(edge_key)
                        if edge is None:
                            break
                        
                        current_max_scope = max(
                            (scope_hierarchy.get(s, 0) for s in edge.granted_scopes),
                            default=0,
                        )
                        
                        if i > 0 and current_max_scope > prev_max_scope:
                            escalation_detected = True
                            break
                        
                        prev_max_scope = current_max_scope
                    
                    if escalation_detected:
                        alert = TrustAlert(
                            severity=AlertSeverity.WARNING,
                            alert_type="scope_escalation",
                            message=(
                                f"Scope escalation detected in chain: "
                                f"{' → '.join(path)}"
                            ),
                            source_agent_id=node,
                            target_agent_id=target,
                            chain=path,
                        )
                        self._alerts.append(alert)

    def _detect_shadow_trust(self) -> None:
        """
        Detect shadow trust — agents that inherit trust from
        a grantor without any direct interaction history.
        
        This is the most insidious attack: Agent A has never seen
        Agent D, yet Agent D can act with Agent A's authority
        through the chain A→B→C→D.
        """
        for node in self._graph.nodes():
            direct_trustees = set(self._graph.successors(node))
            all_reachable = set(nx.descendants(self._graph, node))
            
            shadow_agents = all_reachable - direct_trustees - {node}
            
            for shadow in shadow_agents:
                # Find the shortest path to understand the chain
                try:
                    path = nx.shortest_path(self._graph, node, shadow)
                except nx.NetworkXError:
                    continue
                
                if len(path) > 2:
                    alert = TrustAlert(
                        severity=AlertSeverity.WARNING,
                        alert_type="shadow_trust",
                        message=(
                            f"Agent {shadow} has shadow trust from {node} "
                            f"through {len(path) - 2} intermediaries"
                        ),
                        source_agent_id=node,
                        target_agent_id=shadow,
                        chain=path,
                    )
                    self._alerts.append(alert)
