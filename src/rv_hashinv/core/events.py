"""The event stream: the only way the engine talks to a front-end.

Events are plain dicts with an "event" key; their JSON form is identical to the Rust profile
(`rv-hashinv scan --progress jsonl`).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

Event = dict[str, Any]
Sink = Callable[[Event], None]


def eta_ms(elapsed_ms: int, bytes_done: int, bytes_total: int) -> int | None:
    if bytes_done == 0 or elapsed_ms < 500 or bytes_total < bytes_done:
        return None
    return (bytes_total - bytes_done) * elapsed_ms // bytes_done


def event(kind: str, /, **fields: Any) -> Event:
    return {"event": kind, **fields}
