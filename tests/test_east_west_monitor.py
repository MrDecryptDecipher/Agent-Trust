"""
Tests for EastWestMonitor module.
"""

import pytest
from agent_trust.east_west_monitor import A2AInterceptor, TrafficAnalyzer, EventStore
from agent_trust.types import MonitorEvent


class TestA2AInterceptor:
    """Test traffic interception."""

    def test_record_event(self):
        interceptor = A2AInterceptor()
        event = interceptor.record_event(
            source="agent-a",
            target="agent-b",
            method="POST",
            latency_ms=45.2,
            status_code=200,
        )
        
        assert event.source_agent_id == "agent-a"
        assert interceptor.event_count == 1

    def test_capture_context_manager(self):
        interceptor = A2AInterceptor()
        
        with interceptor.capture("a", "b") as ctx:
            ctx.set_response(status_code=200, response_size=1024)
        
        assert interceptor.event_count == 1

    def test_filter_events(self):
        interceptor = A2AInterceptor()
        interceptor.record_event(source="a", target="b")
        interceptor.record_event(source="a", target="c")
        interceptor.record_event(source="b", target="c")
        
        events = interceptor.get_events(source="a")
        assert len(events) == 2

    def test_pause_resume(self):
        interceptor = A2AInterceptor()
        interceptor.record_event(source="a", target="b")
        assert interceptor.event_count == 1
        
        interceptor.pause()
        interceptor.record_event(source="a", target="b")
        assert interceptor.event_count == 1  # Not recorded
        
        interceptor.resume()
        interceptor.record_event(source="a", target="b")
        assert interceptor.event_count == 2


class TestTrafficAnalyzer:
    """Test traffic analysis."""

    def test_update_profile(self):
        analyzer = TrafficAnalyzer()
        event = MonitorEvent(
            source_agent_id="a",
            target_agent_id="b",
            latency_ms=100,
        )
        
        analyzer.analyze_event(event)
        
        profile = analyzer.get_profile("a")
        assert profile is not None
        assert profile.total_requests_sent == 1

    def test_error_rate_detection(self):
        analyzer = TrafficAnalyzer()
        
        # Send many failed events
        for i in range(15):
            event = MonitorEvent(
                source_agent_id="bad-agent",
                target_agent_id=f"target-{i % 3}",
                status_code=500,
                latency_ms=100,
            )
            alerts = analyzer.analyze_event(event)
        
        profile = analyzer.get_profile("bad-agent")
        assert profile is not None
        assert profile.error_rate > 0.5

    def test_dashboard_data(self):
        analyzer = TrafficAnalyzer()
        
        for i in range(5):
            analyzer.analyze_event(MonitorEvent(
                source_agent_id=f"agent-{i}",
                target_agent_id=f"agent-{(i+1) % 5}",
                latency_ms=50 + i * 10,
            ))
        
        data = analyzer.get_dashboard_data()
        assert data["total_agents_monitored"] > 0


class TestEventStore:
    """Test event persistence."""

    def test_store_and_query(self):
        store = EventStore(":memory:")
        store.initialize()
        
        event = MonitorEvent(
            source_agent_id="a",
            target_agent_id="b",
            method="POST",
            latency_ms=100,
        )
        store.store_event(event)
        
        results = store.query(source="a")
        assert len(results) == 1
        assert results[0]["source_agent_id"] == "a"

    def test_batch_store(self):
        store = EventStore(":memory:")
        store.initialize()
        
        events = [
            MonitorEvent(
                source_agent_id=f"agent-{i}",
                target_agent_id="target",
                latency_ms=float(i * 10),
            )
            for i in range(100)
        ]
        
        count = store.store_events_batch(events)
        assert count == 100

    def test_agent_summary(self):
        store = EventStore(":memory:")
        store.initialize()
        
        for i in range(10):
            store.store_event(MonitorEvent(
                source_agent_id="agent-x",
                target_agent_id=f"target-{i % 3}",
                latency_ms=50.0 + i,
            ))
        
        summary = store.get_agent_summary("agent-x")
        assert summary["found"]
        assert summary["total_events"] == 10

    def test_stats(self):
        store = EventStore(":memory:")
        store.initialize()
        
        stats = store.get_stats()
        assert stats["initialized"]
