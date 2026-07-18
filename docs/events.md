# Event Bus Reference

ReconChain uses an in-process event bus (`EventBus`) for real-time communication between the pipeline and subscriber components (dashboard, bot, AI triage, notifications).

## Quick Usage

```python
from reconchain.events import bus, Event

# Subscribe to events
bus.subscribe("phase.start", lambda e: print(f"Phase started: {e.data['phase']}"))
bus.subscribe("finding.new", lambda e: print(f"New finding: {e.data}"))
bus.subscribe("*", lambda e: print(f"Any event: {e.type}"))  # wildcard

# Emit events
bus.emit("phase.start", {"phase": "11-INJECT"})
bus.emit("finding.new", {"url": "https://...", "vuln": "xss", "severity": "high"})
```

## API Reference

### `Event` (dataclass)

| Field | Type | Description |
|-------|------|-------------|
| `type` | `str` | Event type identifier (e.g. `"phase.start"`) |
| `data` | `Dict[str, Any]` | Event payload |
| `timestamp` | `float` | Unix timestamp (auto-set) |

**Methods:**
- `to_json() -> str` — JSON serialization for logging/storage
- `to_sse() -> str` — Server-Sent Events format for browser streaming

### `EventBus`

| Method | Description |
|--------|-------------|
| `subscribe(event_type, callback)` | Register a callback for an event type. Use `"*"` for wildcard. |
| `unsubscribe(event_type, callback)` | Remove a previously registered callback. |
| `emit(event_type, data=None) -> Event` | Emit an event. All matching subscribers are called synchronously. |
| `get_history(event_type=None, since=None)` | Retrieve past events from the in-memory ring buffer (max 500). |
| `clear_history()` | Clear the event history buffer. |

**Properties:**
- `event_count -> int` — Total events emitted since creation.

### `bus` (module-level singleton)

The default `EventBus` instance shared across all ReconChain components.

## Event Types

The pipeline emits these events during a scan:

| Event Type | Data Fields | Description |
|------------|-------------|-------------|
| `phase.start` | `phase`, `ts` | A phase is about to execute |
| `phase.complete` | `phase`, `ts`, `artifacts` | A phase completed successfully |
| `phase.error` | `phase`, `ts`, `error` | A phase failed |
| `finding.new` | `url`, `vuln`, `severity`, `host` | A new vulnerability finding |
| `scan.start` | `domain`, `ts` | Pipeline scan started |
| `scan.complete` | `domain`, `ts`, `total_findings` | Pipeline scan completed |

## SSE (Server-Sent Events)

The dashboard server streams events to browsers using SSE. Each `Event` can be serialized:

```python
event = bus.emit("finding.new", {"url": "https://...", "vuln": "xss"})
print(event.to_sse())
# event: finding.new
# data: {"url": "https://...", "vuln": "xss"}
```

## Thread Safety

`EventBus` is fully thread-safe. All operations use an internal `threading.Lock`. Subscribers are called outside the lock to prevent deadlocks.

## History Buffer

The bus keeps the last 500 events in memory. You can query historical events:

```python
# Get all phase.complete events
events = bus.get_history(event_type="phase.complete")

# Get events since a specific timestamp
import time
recent = bus.get_history(since=time.time() - 300)  # last 5 minutes
```

## Integration with Plugins

Plugins can emit events to notify subscribers:

```python
class MyPlugin(PhasePlugin):
    name = "MY-PLUGIN"
    # ...

    async def run(self, outdir, t, only, skip, prev, force=False, **kwargs):
        from reconchain.events import bus

        bus.emit("phase.start", {"phase": self.name})

        # ... scan logic ...

        bus.emit("finding.new", {
            "url": "https://example.com/vuln",
            "vuln": "xss",
            "severity": "high",
        })

        return {"MY-PLUGIN": str(outpath)}
```
