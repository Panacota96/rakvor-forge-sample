"""UTC timestamps and durations in one place, so every output uses the same format."""

from datetime import UTC, datetime


def utc_now() -> str:
    """'2026-10-19T20:15:03.123Z'"""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def utc_from_timestamp(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def utc_compact() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def human_duration(ms: int) -> str:
    """'12.3 s', '4 min 05 s', '1 h 02 min 03 s' (identical to the Rust profile)."""
    s = ms // 1000
    if s < 60:
        return f"{ms / 1000:.1f} s"
    if s < 3600:
        return f"{s // 60} min {s % 60:02d} s"
    return f"{s // 3600} h {(s % 3600) // 60:02d} min {s % 60:02d} s"
