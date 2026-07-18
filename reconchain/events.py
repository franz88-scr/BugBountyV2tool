"""
reconchain.events — lightweight in-process event bus for real-time data streaming.

The dashboard server, companion bot, AI triage, and attack surface modules
subscribe to events emitted by the pipeline to receive live updates without
polling or file watching.

Usage:
    from reconchain.events import bus, Event

    # Emitting (from pipeline.py)
    bus.emit("phase.start", {"phase": "11-INJECT", "ts": time.time()})
    bus.emit("finding.new", {"url": "...", "vuln": "xss", "severity": "high"})

    # Subscribing (from dashboard_server.py)
    bus.subscribe("phase.complete", my_handler)
"""
from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class Event:
    """An event emitted on the :class:`EventBus`.

    Attributes:
        type: Event type identifier (e.g. ``"phase.start"``).
        data: Arbitrary payload dictionary.
        timestamp: Unix timestamp when the event was created.
    """
    type: str
    data: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)

    def to_json(self) -> str:
        return json.dumps({"type": self.type, "data": self.data, "ts": self.timestamp})

    def to_sse(self) -> str:
        payload = json.dumps(self.data)
        return f"event: {self.type}\ndata: {payload}\n\n"


Callback = Callable[[Event], None]


class EventBus:
    """Thread-safe publish/subscribe event bus.

    Components subscribe to named event types and receive callbacks when
    matching events are emitted.  A ``"*"`` wildcard subscription receives
    every event regardless of type.

    The bus keeps an in-memory ring buffer of the last 500 events that
    can be queried via :meth:`get_history`.
    """

    def __init__(self) -> None:
        self._subscribers: Dict[str, List[Callback]] = defaultdict(list)
        self._wildcard_subscribers: List[Callback] = []
        self._lock = threading.Lock()
        self._history: List[Event] = []
        self._max_history = 500
        self._event_count = 0

    def subscribe(self, event_type: str, callback: Callback) -> None:
        with self._lock:
            if event_type == "*":
                self._wildcard_subscribers.append(callback)
            else:
                self._subscribers[event_type].append(callback)

    def unsubscribe(self, event_type: str, callback: Callback) -> None:
        with self._lock:
            if event_type == "*":
                self._wildcard_subscribers = [
                    cb for cb in self._wildcard_subscribers if cb is not callback
                ]
            else:
                self._subscribers[event_type] = [
                    cb for cb in self._subscribers.get(event_type, []) if cb is not callback
                ]

    def emit(self, event_type: str, data: Optional[Dict[str, Any]] = None) -> Event:
        """Emit an event and notify all matching subscribers.

        Subscribers are called outside the lock to prevent deadlocks.
        Exceptions raised by subscribers are silently swallowed.
        """
        event = Event(type=event_type, data=data or {})
        with self._lock:
            self._event_count += 1
            self._history.append(event)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]

            targets = list(self._subscribers.get(event_type, []))
            wildcards = list(self._wildcard_subscribers)

        for cb in targets + wildcards:
            try:
                cb(event)
            except Exception as exc:
                import logging
                logging.getLogger("reconchain.events").debug(f"subscriber error for {event_type}: {exc}")
        return event

    def get_history(
        self, event_type: Optional[str] = None, since: Optional[float] = None
    ) -> List[Event]:
        with self._lock:
            events = list(self._history)
        if event_type:
            events = [e for e in events if e.type == event_type]
        if since is not None:
            events = [e for e in events if e.timestamp >= since]
        return events

    @property
    def event_count(self) -> int:
        with self._lock:
            return self._event_count

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()


bus = EventBus()
