"""
Event store — persistent storage for east-west traffic events.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from typing import Any, Optional

from agent_trust.config import EastWestMonitorConfig
from agent_trust.types import MonitorEvent

logger = logging.getLogger(__name__)


class EventStore:
    """
    SQLite-backed persistent event store for traffic monitoring.
    
    Supports:
    - High-throughput event ingestion
    - Time-range queries
    - Agent-based filtering
    - Automatic retention cleanup
    
    Usage:
        store = EventStore("events.db")
        store.initialize()
        store.store_event(event)
        
        events = store.query(
            since=time.time() - 3600,
            source="agent-a",
        )
    """

    def __init__(
        self,
        db_path: str = ":memory:",
        config: Optional[EastWestMonitorConfig] = None,
    ):
        self._db_path = db_path
        self._config = config or EastWestMonitorConfig()
        self._conn: Optional[sqlite3.Connection] = None

    def initialize(self) -> None:
        """Initialize the database schema."""
        self._conn = sqlite3.connect(self._db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                source_agent_id TEXT NOT NULL,
                target_agent_id TEXT NOT NULL,
                method TEXT,
                endpoint TEXT,
                request_size_bytes INTEGER DEFAULT 0,
                response_size_bytes INTEGER DEFAULT 0,
                status_code INTEGER DEFAULT 0,
                latency_ms REAL DEFAULT 0,
                anomaly_score REAL DEFAULT 0,
                timestamp REAL NOT NULL,
                tags TEXT DEFAULT '[]',
                metadata TEXT DEFAULT '{}'
            );
            
            CREATE INDEX IF NOT EXISTS idx_events_source
                ON events(source_agent_id);
            CREATE INDEX IF NOT EXISTS idx_events_target
                ON events(target_agent_id);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp
                ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_anomaly
                ON events(anomaly_score);
        """)
        self._conn.commit()
        logger.info(f"Event store initialized at {self._db_path}")

    def store_event(self, event: MonitorEvent) -> None:
        """Store a single event."""
        if self._conn is None:
            self.initialize()
        
        self._conn.execute(  # type: ignore
            """INSERT OR REPLACE INTO events 
            (event_id, source_agent_id, target_agent_id, method,
             endpoint, request_size_bytes, response_size_bytes,
             status_code, latency_ms, anomaly_score, timestamp,
             tags, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.event_id,
                event.source_agent_id,
                event.target_agent_id,
                event.method,
                event.endpoint,
                event.request_size_bytes,
                event.response_size_bytes,
                event.status_code,
                event.latency_ms,
                event.anomaly_score,
                event.timestamp,
                json.dumps(event.tags),
                json.dumps(event.metadata),
            ),
        )
        self._conn.commit()  # type: ignore

    def store_events_batch(self, events: list[MonitorEvent]) -> int:
        """Store multiple events in a single transaction."""
        if self._conn is None:
            self.initialize()
        
        rows = [
            (
                e.event_id, e.source_agent_id, e.target_agent_id,
                e.method, e.endpoint, e.request_size_bytes,
                e.response_size_bytes, e.status_code, e.latency_ms,
                e.anomaly_score, e.timestamp,
                json.dumps(e.tags), json.dumps(e.metadata),
            )
            for e in events
        ]
        
        self._conn.executemany(  # type: ignore
            """INSERT OR REPLACE INTO events 
            (event_id, source_agent_id, target_agent_id, method,
             endpoint, request_size_bytes, response_size_bytes,
             status_code, latency_ms, anomaly_score, timestamp,
             tags, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        self._conn.commit()  # type: ignore
        return len(rows)

    def query(
        self,
        source: Optional[str] = None,
        target: Optional[str] = None,
        since: Optional[float] = None,
        until: Optional[float] = None,
        min_anomaly_score: Optional[float] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query stored events with filtering."""
        if self._conn is None:
            self.initialize()
        
        conditions = []
        params: list[Any] = []
        
        if source:
            conditions.append("source_agent_id = ?")
            params.append(source)
        if target:
            conditions.append("target_agent_id = ?")
            params.append(target)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since)
        if until:
            conditions.append("timestamp <= ?")
            params.append(until)
        if min_anomaly_score is not None:
            conditions.append("anomaly_score >= ?")
            params.append(min_anomaly_score)
        
        where = " AND ".join(conditions) if conditions else "1=1"
        
        cursor = self._conn.execute(  # type: ignore
            f"""SELECT * FROM events
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT ?""",
            params + [limit],
        )
        
        return [dict(row) for row in cursor.fetchall()]

    def get_agent_summary(self, agent_id: str) -> dict:
        """Get traffic summary for a specific agent."""
        if self._conn is None:
            self.initialize()
        
        cursor = self._conn.execute(  # type: ignore
            """SELECT 
                COUNT(*) as total_events,
                AVG(latency_ms) as avg_latency,
                MAX(latency_ms) as max_latency,
                AVG(anomaly_score) as avg_anomaly,
                SUM(request_size_bytes) as total_bytes_sent,
                SUM(response_size_bytes) as total_bytes_received,
                COUNT(DISTINCT target_agent_id) as unique_targets,
                SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors
            FROM events
            WHERE source_agent_id = ?""",
            (agent_id,),
        )
        
        row = cursor.fetchone()
        if row is None:
            return {"agent_id": agent_id, "found": False}
        
        return {
            "agent_id": agent_id,
            "found": True,
            **(dict(row) if row else {}),
        }

    def cleanup_old_events(self) -> int:
        """Remove events older than retention period."""
        if self._conn is None:
            return 0
        
        cutoff = time.time() - (self._config.retention_days * 86400)
        cursor = self._conn.execute(
            "DELETE FROM events WHERE timestamp < ?",
            (cutoff,),
        )
        self._conn.commit()
        deleted = cursor.rowcount
        
        if deleted > 0:
            logger.info(f"Cleaned up {deleted} old events")
        
        return deleted

    def get_stats(self) -> dict:
        """Get event store statistics."""
        if self._conn is None:
            return {"initialized": False}
        
        cursor = self._conn.execute(
            """SELECT 
                COUNT(*) as total_events,
                COUNT(DISTINCT source_agent_id) as unique_sources,
                COUNT(DISTINCT target_agent_id) as unique_targets,
                MIN(timestamp) as earliest,
                MAX(timestamp) as latest
            FROM events"""
        )
        
        row = cursor.fetchone()
        return {
            "initialized": True,
            "db_path": self._db_path,
            **(dict(row) if row else {}),
        }

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
