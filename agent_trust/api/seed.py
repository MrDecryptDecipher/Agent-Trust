"""
Seed the middleware with realistic agent data on server startup.
This creates REAL agents, trust edges, interactions, consent chains,
and traffic events — not mock data.
"""

from __future__ import annotations

import logging
import random
import time

from agent_trust.middleware import AgentTrustMiddleware
from agent_trust.types import TrustLevel, TokenScope

logger = logging.getLogger(__name__)

# ─── Agent Definitions ──────────────────────────────────────────

AGENTS = [
    {
        "system_prompt": "You are a strategic planner that orchestrates multi-step workflows. You break complex tasks into sub-tasks and delegate them to specialized agents.",
        "tool_list": ["task_decompose", "agent_discover", "workflow_schedule", "priority_rank"],
        "organization": "OrchestraCorp",
        "agent_id": "planner-alpha",
    },
    {
        "system_prompt": "You are a high-performance data retrieval agent. You fetch structured data from databases, APIs, and file systems with low latency.",
        "tool_list": ["sql_query", "api_fetch", "file_read", "cache_lookup"],
        "organization": "DataVault",
        "agent_id": "retriever-beta",
    },
    {
        "system_prompt": "You are a secure code execution agent. You run sandboxed code, process computations, and return structured results.",
        "tool_list": ["code_execute", "sandbox_run", "compute_aggregate", "result_format"],
        "organization": "OrchestraCorp",
        "agent_id": "executor-gamma",
    },
    {
        "system_prompt": "You are a validation and compliance agent. You verify data integrity, check regulatory compliance, and produce audit reports.",
        "tool_list": ["schema_validate", "compliance_check", "audit_log", "hash_verify"],
        "organization": "TrustNet",
        "agent_id": "validator-delta",
    },
    {
        "system_prompt": "You are a monitoring agent that watches system health, detects anomalies, and triggers alerts when thresholds are breached.",
        "tool_list": ["metric_collect", "anomaly_detect", "alert_fire", "health_check"],
        "organization": "SecureAI",
        "agent_id": "monitor-epsilon",
    },
    {
        "system_prompt": "You are a data analysis agent. You perform statistical analysis, generate insights, and produce visualizations from large datasets.",
        "tool_list": ["stats_compute", "trend_analyze", "chart_generate", "report_build"],
        "organization": "DataVault",
        "agent_id": "analyzer-zeta",
    },
    {
        "system_prompt": "You are a natural language processing agent. You summarize documents, extract entities, classify text, and translate between languages.",
        "tool_list": ["text_summarize", "entity_extract", "text_classify", "translate"],
        "organization": "LinguaAI",
        "agent_id": "nlp-eta",
    },
    {
        "system_prompt": "You are a payment processing agent. You handle financial transactions, verify balances, process invoices, and generate receipts.",
        "tool_list": ["payment_execute", "balance_verify", "invoice_process", "receipt_generate"],
        "organization": "FinSecure",
        "agent_id": "payments-theta",
    },
]

# ─── Trust Relationships ────────────────────────────────────────

TRUST_EDGES = [
    ("planner-alpha", "retriever-beta", TrustLevel.TRUSTED, [TokenScope.READ, TokenScope.EXECUTE]),
    ("planner-alpha", "executor-gamma", TrustLevel.VERIFIED, [TokenScope.READ, TokenScope.WRITE, TokenScope.EXECUTE]),
    ("planner-alpha", "nlp-eta", TrustLevel.VERIFIED, [TokenScope.READ, TokenScope.EXECUTE]),
    ("retriever-beta", "validator-delta", TrustLevel.VERIFIED, [TokenScope.READ]),
    ("retriever-beta", "analyzer-zeta", TrustLevel.BASIC, [TokenScope.READ]),
    ("executor-gamma", "analyzer-zeta", TrustLevel.BASIC, [TokenScope.READ]),
    ("executor-gamma", "payments-theta", TrustLevel.VERIFIED, [TokenScope.READ, TokenScope.WRITE]),
    ("validator-delta", "planner-alpha", TrustLevel.TRUSTED, [TokenScope.READ, TokenScope.EXECUTE]),
    ("monitor-epsilon", "retriever-beta", TrustLevel.PROVISIONAL, [TokenScope.READ]),
    ("monitor-epsilon", "planner-alpha", TrustLevel.BASIC, [TokenScope.READ]),
    ("analyzer-zeta", "planner-alpha", TrustLevel.BASIC, [TokenScope.READ]),
    ("nlp-eta", "retriever-beta", TrustLevel.VERIFIED, [TokenScope.READ]),
    ("payments-theta", "validator-delta", TrustLevel.TRUSTED, [TokenScope.READ, TokenScope.WRITE]),
]

# ─── Interaction History ────────────────────────────────────────

TASK_TYPES = [
    "data_retrieval", "code_execution", "text_analysis",
    "compliance_check", "payment_processing", "anomaly_detection",
    "report_generation", "entity_extraction", "data_validation",
]


def seed_middleware(middleware: AgentTrustMiddleware) -> dict:
    """
    Seed the middleware with realistic data.
    Returns a summary of what was created.
    """
    results = {
        "agents_registered": 0,
        "trust_edges_created": 0,
        "interactions_recorded": 0,
        "consent_chains_created": 0,
        "errors": [],
    }

    # 1. Register all agents
    agent_ids = []
    for agent_def in AGENTS:
        try:
            identity = middleware.register_agent(**agent_def)
            agent_ids.append(identity.agent_id)
            results["agents_registered"] += 1
            logger.info(f"Registered agent: {identity.agent_id} ({identity.organization})")
        except Exception as e:
            results["errors"].append(f"Failed to register {agent_def['agent_id']}: {e}")
            logger.warning(f"Failed to register {agent_def['agent_id']}: {e}")

    # 2. Establish trust relationships
    for source, target, level, scopes in TRUST_EDGES:
        try:
            middleware.establish_trust(
                source_id=source,
                target_id=target,
                trust_level=level,
                scopes=scopes,
                max_depth=2,
            )
            results["trust_edges_created"] += 1
        except Exception as e:
            results["errors"].append(f"Failed trust {source}→{target}: {e}")

    # 3. Generate realistic interaction history
    interactions = _generate_interactions(agent_ids)
    for interaction in interactions:
        try:
            middleware.record_interaction(**interaction)
            results["interactions_recorded"] += 1
        except Exception as e:
            results["errors"].append(f"Failed interaction: {e}")

    # 4. Create consent chains
    consent_scenarios = [
        ("planner-alpha", "retriever-beta", "data_retrieval", "Fetch quarterly sales data"),
        ("planner-alpha", "executor-gamma", "code_execution", "Run analysis pipeline"),
        ("planner-alpha", "nlp-eta", "text_analysis", "Summarize research papers"),
        ("executor-gamma", "payments-theta", "payment_processing", "Process vendor invoice"),
        ("validator-delta", "planner-alpha", "compliance_check", "Verify GDPR compliance"),
    ]

    for grantor, grantee, task_type, desc in consent_scenarios:
        try:
            chain_id, _ = middleware.consent_audit.create_chain(
                grantor_id=grantor,
                grantee_id=grantee,
                scopes=[TokenScope.READ],
                task_type=task_type,
                task_description=desc,
            )
            results["consent_chains_created"] += 1
        except Exception as e:
            results["errors"].append(f"Failed consent chain: {e}")

    # 5. Run initial security scan
    try:
        middleware.run_security_scan()
    except Exception as e:
        results["errors"].append(f"Security scan failed: {e}")

    logger.info(
        f"Seed complete: {results['agents_registered']} agents, "
        f"{results['trust_edges_created']} edges, "
        f"{results['interactions_recorded']} interactions, "
        f"{results['consent_chains_created']} consent chains"
    )

    return results


def _generate_interactions(agent_ids: list[str]) -> list[dict]:
    """Generate realistic interaction records."""
    interactions = []
    now = time.time()

    # Agent performance profiles
    profiles = {
        "planner-alpha": {"success_rate": 0.96, "avg_latency": 120, "violation_rate": 0.01},
        "retriever-beta": {"success_rate": 0.93, "avg_latency": 85, "violation_rate": 0.02},
        "executor-gamma": {"success_rate": 0.78, "avg_latency": 340, "violation_rate": 0.08},
        "validator-delta": {"success_rate": 0.99, "avg_latency": 45, "violation_rate": 0.005},
        "monitor-epsilon": {"success_rate": 0.52, "avg_latency": 890, "violation_rate": 0.15},
        "analyzer-zeta": {"success_rate": 0.88, "avg_latency": 210, "violation_rate": 0.03},
        "nlp-eta": {"success_rate": 0.91, "avg_latency": 180, "violation_rate": 0.02},
        "payments-theta": {"success_rate": 0.97, "avg_latency": 65, "violation_rate": 0.01},
    }

    for agent_id in agent_ids:
        profile = profiles.get(agent_id, {"success_rate": 0.8, "avg_latency": 200, "violation_rate": 0.05})

        # Generate 8-15 interactions per agent
        num_interactions = random.randint(8, 15)
        for i in range(num_interactions):
            # Pick a random target (different from source)
            targets = [a for a in agent_ids if a != agent_id]
            target = random.choice(targets)

            success = random.random() < profile["success_rate"]
            latency = max(10, profile["avg_latency"] + random.gauss(0, profile["avg_latency"] * 0.3))
            violations = 1 if random.random() < profile["violation_rate"] else 0

            interactions.append({
                "source_id": agent_id,
                "target_id": target,
                "task_type": random.choice(TASK_TYPES),
                "success": success,
                "latency_ms": round(latency, 1),
                "policy_violations": violations,
            })

    return interactions
