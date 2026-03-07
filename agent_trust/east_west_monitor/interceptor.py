"""
A2A call interceptor — wraps HTTP clients to capture
all agent-to-agent communications transparently.
"""

from __future__ import annotations

import logging
import time
import uuid
import functools
from typing import Any, Callable, Optional

from agent_trust.config import EastWestMonitorConfig
from agent_trust.types import MonitorEvent

logger = logging.getLogger(__name__)


class A2AInterceptor:
    """
    Transparently intercepts A2A HTTP calls to capture
    traffic metadata without modifying agent code.
    
    Usage — as a decorator:
        interceptor = A2AInterceptor()
        
        @interceptor.wrap
        async def call_agent(url, payload):
            return await httpx.post(url, json=payload)
    
    Usage — as a context manager:
        interceptor = A2AInterceptor()
        
        with interceptor.capture("agent-a", "agent-b") as ctx:
            response = await httpx.post(url, json=payload)
            ctx.set_response(response)
    
    Usage — manual recording:
        interceptor = A2AInterceptor()
        event = interceptor.record_event(
            source="agent-a",
            target="agent-b",
            method="POST",
            endpoint="/tasks",
            request_size=1024,
            response_size=2048,
            status_code=200,
            latency_ms=45.2,
        )
    """

    def __init__(
        self,
        config: Optional[EastWestMonitorConfig] = None,
        event_callback: Optional[Callable[[MonitorEvent], None]] = None,
    ):
        self._config = config or EastWestMonitorConfig()
        self._events: list[MonitorEvent] = []
        self._callback = event_callback
        self._sample_counter = 0
        self._active = True

    @property
    def events(self) -> list[MonitorEvent]:
        return list(self._events)

    @property
    def event_count(self) -> int:
        return len(self._events)

    def record_event(
        self,
        source: str,
        target: str,
        method: str = "POST",
        endpoint: str = "",
        request_size: int = 0,
        response_size: int = 0,
        status_code: int = 200,
        latency_ms: float = 0.0,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict] = None,
    ) -> MonitorEvent:
        """Record a single A2A traffic event."""
        if not self._active:
            return MonitorEvent()

        # Sampling
        self._sample_counter += 1
        if self._config.sample_rate < 1.0:
            import random
            if random.random() > self._config.sample_rate:
                return MonitorEvent()

        event = MonitorEvent(
            source_agent_id=source,
            target_agent_id=target,
            method=method,
            endpoint=endpoint,
            request_size_bytes=request_size,
            response_size_bytes=response_size,
            status_code=status_code,
            latency_ms=latency_ms,
            tags=tags or [],
            metadata=metadata or {},
        )
        
        self._events.append(event)
        
        if self._callback:
            try:
                self._callback(event)
            except Exception as e:
                logger.error(f"Event callback error: {e}")
        
        return event

    def wrap(self, func: Callable) -> Callable:
        """
        Decorator that wraps an async function to capture
        A2A call metadata.
        
        The decorated function should accept keyword arguments:
        - source_agent_id: str
        - target_agent_id: str
        """
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            source = kwargs.pop("source_agent_id", "unknown")
            target = kwargs.pop("target_agent_id", "unknown")
            
            start = time.time()
            try:
                result = await func(*args, **kwargs)
                latency = (time.time() - start) * 1000
                
                self.record_event(
                    source=source,
                    target=target,
                    method="CALL",
                    latency_ms=latency,
                    status_code=200,
                    tags=["wrapped"],
                )
                
                return result
            except Exception as e:
                latency = (time.time() - start) * 1000
                self.record_event(
                    source=source,
                    target=target,
                    method="CALL",
                    latency_ms=latency,
                    status_code=500,
                    tags=["wrapped", "error"],
                    metadata={"error": str(e)},
                )
                raise
        
        return wrapper

    def capture(
        self, source: str, target: str
    ) -> "CaptureContext":
        """
        Context manager for capturing a single A2A interaction.
        """
        return CaptureContext(self, source, target)

    def pause(self) -> None:
        """Pause event capture."""
        self._active = False

    def resume(self) -> None:
        """Resume event capture."""
        self._active = True

    def clear(self) -> None:
        """Clear all stored events."""
        self._events.clear()

    def get_events(
        self,
        source: Optional[str] = None,
        target: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 100,
    ) -> list[MonitorEvent]:
        """Query stored events with filtering."""
        results = self._events
        
        if source:
            results = [e for e in results if e.source_agent_id == source]
        if target:
            results = [e for e in results if e.target_agent_id == target]
        if since:
            results = [e for e in results if e.timestamp >= since]
        
        return results[-limit:]


class CaptureContext:
    """Context manager for capturing a single A2A interaction."""

    def __init__(
        self,
        interceptor: A2AInterceptor,
        source: str,
        target: str,
    ):
        self._interceptor = interceptor
        self._source = source
        self._target = target
        self._start_time = 0.0
        self._response_size = 0
        self._request_size = 0
        self._status_code = 200
        self._method = "POST"
        self._endpoint = ""

    def set_request_size(self, size: int) -> None:
        self._request_size = size

    def set_response(
        self,
        status_code: int = 200,
        response_size: int = 0,
    ) -> None:
        self._status_code = status_code
        self._response_size = response_size

    def __enter__(self) -> "CaptureContext":
        self._start_time = time.time()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        latency = (time.time() - self._start_time) * 1000
        tags = []
        metadata: dict[str, Any] = {}
        
        if exc_type is not None:
            self._status_code = 500
            tags.append("error")
            metadata["error"] = str(exc_val)
        
        self._interceptor.record_event(
            source=self._source,
            target=self._target,
            method=self._method,
            endpoint=self._endpoint,
            request_size=self._request_size,
            response_size=self._response_size,
            status_code=self._status_code,
            latency_ms=latency,
            tags=tags,
            metadata=metadata,
        )
