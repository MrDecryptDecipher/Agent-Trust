"""
Seed the middleware with deterministic scenario-driven data.
Eliminates mock data in favor of verifiable security story-boards.
"""

import logging
import time
from typing import List

from agent_trust.middleware import AgentTrustMiddleware
from agent_trust.types import TrustLevel, TokenScope

logger = logging.getLogger(__name__)

# ─── Agent Definitions ──────────────────────────────────────────

AGENTS = [
    {
        "agent_id": "planner-alpha",
        "organization": "OrchestraCorp",
        "system_prompt": "You are a strategic planner that orchestrates multi-step workflows.",
        "tool_list": ["task_decompose", "agent_discover", "workflow_schedule"],
    },
    {
        "agent_id": "retriever-beta",
        "organization": "DataVault",
        "system_prompt": "You are a high-performance data retrieval agent.",
        "tool_list": ["sql_query", "api_fetch", "file_read"],
    },
    {
        "agent_id": "validator-delta",
        "organization": "TrustNet",
        "system_prompt": "You are a validation and compliance agent.",
        "tool_list": ["schema_validate", "compliance_check", "audit_log"],
    },
    {
        "agent_id": "executor-gamma",
        "organization": "OrchestraCorp",
        "system_prompt": "You are a secure code execution agent.",
        "tool_list": ["code_execute", "sandbox_run"],
    },
    {
        "agent_id": "payments-theta",
        "organization": "FinSecure",
        "system_prompt": "You are a payment processing agent.",
        "tool_list": ["payment_execute", "balance_verify"],
    },
    {
        "agent_id": "monitor-epsilon",
        "organization": "SecureAI",
        "system_prompt": "You are a monitoring agent that detects anomalies.",
        "tool_list": ["metric_collect", "anomaly_detect"],
    },
]

def seed_middleware(middleware: AgentTrustMiddleware) -> dict:
    """
    Seed the middleware with deterministic story-driven data.
    """
    # 1. Registration
    for agent_def in AGENTS:
        middleware.register_agent(**agent_def)
    
    # 2. Scenarios
    _run_scenario_supply_chain(middleware)
    _run_scenario_lateral_movement(middleware)
    _run_scenario_authorized_payments(middleware)
    
    # 3. Security Scan
    middleware.run_security_scan()
    
    return {"status": "seeded", "scenarios": ["supply_chain", "lateral_movement", "payments"]}

def _run_scenario_supply_chain(mw: AgentTrustMiddleware):
    """Scenario 1: Verified Supply Chain Orchestration."""
    # Establish Trust
    mw.establish_trust("planner-alpha", "retriever-beta", TrustLevel.VERIFIED, [TokenScope.READ, TokenScope.EXECUTE])
    mw.establish_trust("retriever-beta", "validator-delta", TrustLevel.TRUSTED, [TokenScope.READ])
    
    # Record Interactions
    for _ in range(5):
        mw.record_interaction("planner-alpha", "retriever-beta", "data_retrieval", success=True, latency_ms=120)
        mw.record_interaction("retriever-beta", "validator-delta", "compliance_check", success=True, latency_ms=45)

def _run_scenario_lateral_movement(mw: AgentTrustMiddleware):
    """Scenario 2: Lateral Movement Attempt (Detected Anomaly)."""
    # monitor-epsilon has BASIC trust to planner-alpha
    mw.establish_trust("monitor-epsilon", "planner-alpha", TrustLevel.BASIC, [TokenScope.READ])
    
    # Record normal behavior
    mw.record_interaction("monitor-epsilon", "planner-alpha", "metric_report", success=True, latency_ms=80)
    
    # Attempt unauthorized lateral movement (monitor-epsilon -> payments-theta)
    # This will fail and trigger a high-severity alert
    try:
        # We simulate the interaction record directly as a violation
        mw.record_interaction(
            source_id="monitor-epsilon",
            target_id="payments-theta",
            task_type="unauthorized_access",
            success=False,
            latency_ms=10,
            policy_violations=1
        )
    except Exception:
        pass

def _run_scenario_authorized_payments(mw: AgentTrustMiddleware):
    """Scenario 3: Cross-Org High-Value Transaction."""
    mw.establish_trust("executor-gamma", "payments-theta", TrustLevel.VERIFIED, [TokenScope.READ, TokenScope.WRITE])
    
    # Record success
    for _ in range(3):
        mw.record_interaction("executor-gamma", "payments-theta", "payment_processing", success=True, latency_ms=340)
    
    # Record one failure (network issue, not violation)
    mw.record_interaction("executor-gamma", "payments-theta", "payment_processing", success=False, latency_ms=2100, policy_violations=0)
