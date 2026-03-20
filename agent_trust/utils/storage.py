"""
SQLite storage manager for persistent agent-trust state.
"""

import sqlite3
import json
import logging
import os
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)

class SQLiteStorage:
    """ handles persistent storage for agent-trust using SQLite. """

    def __init__(self, db_path: str):
        self.db_path = db_path
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """Initialize the database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Agents table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    organization TEXT,
                    fingerprint TEXT,
                    tool_list_hash TEXT,
                    system_prompt_hash TEXT,
                    created_at REAL,
                    metadata TEXT
                )
            ''')
            
            # Trust Edges table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS trust_edges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT,
                    target_id TEXT,
                    trust_level INTEGER,
                    scopes TEXT,
                    max_depth INTEGER,
                    created_at REAL,
                    expires_at REAL,
                    UNIQUE(source_id, target_id)
                )
            ''')
            
            # Interaction Records table (Ledger)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS interactions (
                    interaction_id TEXT PRIMARY KEY,
                    source_id TEXT,
                    target_id TEXT,
                    task_type TEXT,
                    success INTEGER,
                    latency_ms REAL,
                    policy_violations INTEGER,
                    timestamp REAL,
                    metadata TEXT
                )
            ''')
            
            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    severity TEXT,
                    alert_type TEXT,
                    message TEXT,
                    source_id TEXT,
                    target_id TEXT,
                    timestamp REAL,
                    acknowledged INTEGER DEFAULT 0,
                    metadata TEXT
                )
            ''')
            
            conn.commit()

    # --- Agent Operations ---
    def save_agent(self, agent: Any):
        with self._get_connection() as conn:
            conn.execute('''
                INSERT OR REPLACE INTO agents 
                (agent_id, organization, fingerprint, tool_list_hash, system_prompt_hash, created_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                agent.agent_id, agent.organization, agent.fingerprint,
                agent.tool_list_hash, agent.system_prompt_hash,
                agent.created_at, json.dumps(agent.metadata)
            ))

    def get_agents(self) -> list[dict]:
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('SELECT * FROM agents')
            return [dict(row) for row in cursor.fetchall()]

    # --- Trust Edge Operations ---
    def save_trust_edge(self, edge: Any):
        with self._get_connection() as conn:
            conn.execute('''
                INSERT OR REPLACE INTO trust_edges 
                (source_id, target_id, trust_level, scopes, max_depth, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                edge.source_id, edge.target_id, int(edge.trust_level),
                json.dumps([s.value if hasattr(s, 'value') else s for s in edge.granted_scopes]),
                edge.max_delegation_depth, edge.created_at, edge.expires_at
            ))

    def get_trust_edges(self) -> list[dict]:
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('SELECT * FROM trust_edges')
            return [dict(row) for row in cursor.fetchall()]

    # --- Interaction Operations ---
    def save_interaction(self, record: Any):
        with self._get_connection() as conn:
            conn.execute('''
                INSERT OR REPLACE INTO interactions 
                (interaction_id, source_id, target_id, task_type, success, latency_ms, policy_violations, timestamp, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                record.interaction_id, record.source_agent_id, record.target_agent_id,
                record.task_type, 1 if record.success else 0, record.latency_ms,
                record.policy_violations, record.started_at, json.dumps(record.metadata)
            ))

    def get_interactions(self, agent_id: Optional[str] = None, limit: int = 1000) -> list[dict]:
        query = 'SELECT * FROM interactions'
        params: list[Any] = []
        if agent_id:
            query += ' WHERE source_id = ? OR target_id = ?'
            params = [agent_id, agent_id]
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    # --- Alert Operations ---
    def save_alert(self, alert: Any):
        with self._get_connection() as conn:
            severity_val = getattr(alert.severity, 'value', str(alert.severity))
            conn.execute('''
                INSERT OR REPLACE INTO alerts 
                (alert_id, severity, alert_type, message, source_id, target_id, timestamp, acknowledged, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.alert_id, 
                severity_val,
                alert.alert_type, alert.message, alert.source_agent_id, alert.target_agent_id,
                alert.timestamp, 1 if alert.metadata.get("acknowledged") else 0,
                json.dumps(alert.metadata)
            ))

    def get_alerts(self, limit: int = 200) -> list[dict]:
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?', (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def acknowledge_alert(self, alert_id: str):
        with self._get_connection() as conn:
            conn.execute('UPDATE alerts SET acknowledged = 1 WHERE alert_id = ?', (alert_id,))
