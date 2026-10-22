"""Append-only, hash-chained audit log (audit.jsonl) plus a human-readable twin (audit.log).

Chain rule (identical in every Rakvor tool, any language):
  entry_hash = SHA-256(canonical JSON of the entry without "entry_hash")
  canonical  = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
  the first entry's prev_entry_hash is 64 zeros.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .timeutil import utc_now

GENESIS = "0" * 64


def canonical(entry: dict[str, Any]) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def entry_hash(entry: dict[str, Any]) -> str:
    return hashlib.sha256(canonical({k: v for k, v in entry.items() if k != "entry_hash"})).hexdigest()


def _summarize(details: Any) -> str:
    if not isinstance(details, dict):
        return json.dumps(details, ensure_ascii=False)
    parts = []
    for k in sorted(details):
        v = details[k]
        if isinstance(v, dict):
            continue
        if isinstance(v, list):
            v = "+".join(x if isinstance(x, str) else json.dumps(x, ensure_ascii=False) for x in v)
        elif v is None:
            v = "null"
        elif isinstance(v, bool):
            v = "true" if v else "false"
        parts.append(f"{k}={v}")
    return " ".join(parts)


def build_entry(seq: int, run_id: str, actor: str, action: str, item: str | None, details: Any, prev: str) -> dict[str, Any]:
    """One chained entry (shared by audit.jsonl and the case log case-log.jsonl), with its entry_hash set."""
    entry: dict[str, Any] = {"seq": seq, "ts_utc": utc_now(), "run_id": run_id, "actor": actor, "action": action}
    if item is not None:
        entry["item"] = item
    entry["details"] = details if details is not None else {}
    entry["prev_entry_hash"] = prev
    entry["entry_hash"] = entry_hash(entry)
    return entry


class AuditLog:
    def __init__(self, directory: Path, run_id: str, actor: str):
        directory.mkdir(parents=True, exist_ok=True)
        self.dir = directory
        # "x": the log must not exist yet — an existing log is never appended to or overwritten.
        self._jsonl = open(directory / "audit.jsonl", "x", encoding="utf-8", newline="\n")  # noqa: SIM115
        self._text = open(directory / "audit.log", "x", encoding="utf-8", newline="\n")  # noqa: SIM115
        self.seq = 0
        self.head = GENESIS
        self.run_id = run_id
        self.actor = actor

    @classmethod
    def resume(cls, directory: Path, actor: str) -> AuditLog:
        """Re-opens an existing, intact log to append later actions (e.g. a delayed timestamp)."""
        n, problems = verify(directory / "audit.jsonl")
        if problems:
            raise ValueError(f"refusing to append to a broken audit log: {problems[0]}")
        last = json.loads((directory / "audit.jsonl").read_text(encoding="utf-8").splitlines()[-1])
        self = cls.__new__(cls)
        self.dir = directory
        self._jsonl = open(directory / "audit.jsonl", "a", encoding="utf-8", newline="\n")  # noqa: SIM115
        self._text = open(directory / "audit.log", "a", encoding="utf-8", newline="\n")  # noqa: SIM115
        self.seq, self.head, self.run_id, self.actor = n, last["entry_hash"], last["run_id"], actor
        return self

    def record(self, action: str, item: str | None = None, details: Any = None) -> int:
        self.seq += 1
        entry = build_entry(self.seq, self.run_id, self.actor, action, item, details, self.head)
        ts = entry["ts_utc"]
        self._jsonl.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
        self._text.write(f"{ts}  #{self.seq:05d}  {action:<20} {item + '  ' if item else ''}{_summarize(entry['details'])}\n")
        self._jsonl.flush()
        self._text.flush()
        self.head = entry["entry_hash"]
        return self.seq

    def close(self) -> None:
        self._jsonl.close()
        self._text.close()


def heads(path: Path) -> dict[int, str]:
    """seq -> entry_hash, for checking what a timestamp covers."""
    out = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if line.strip():
            e = json.loads(line)
            out[e.get("seq")] = e.get("entry_hash")
    return out


def verify(path: Path) -> tuple[int, list[str]]:
    """(entries, problems). An empty problem list means the chain is intact."""
    problems: list[str] = []
    prev, expected, n = GENESIS, 1, 0
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                problems.append(f"line {lineno}: not valid JSON ({e})")
                continue
            seq = entry.get("seq")
            if seq != expected:
                problems.append(f"line {lineno}: sequence {seq} where {expected} was expected (deleted or re-ordered entry)")
            if entry.get("prev_entry_hash") != prev:
                problems.append(f"line {lineno}: prev_entry_hash does not link to the previous entry")
            stored = entry.get("entry_hash", "")
            if entry_hash(entry) != stored:
                problems.append(f"line {lineno}: entry_hash does not match its content (edited entry)")
            prev = stored
            expected = (seq if isinstance(seq, int) else expected) + 1
            n += 1
    return n, problems
