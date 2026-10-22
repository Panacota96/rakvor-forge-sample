"""verify-log: the audit chain, its RFC 3161 timestamps and, because a hash chain alone cannot show that
entries were removed from its end, a truncation check against the records kept outside the log:

* the timestamp: timestamp-<seq>.json names the entry it covers (covers_seq) and the token signs that entry's
  hash, so the log must still contain that entry with that hash;
* the case log: for a run inside a case folder (<CASE>/runs/<tool>/<RUN-ID>/logs), run_finished in
  case-log.jsonl records the run's final audit head and entry count (audit_head, audit_entries).

Entries after the last anchored one cannot be proven complete; the report says how many there are. Without a
timestamp or a case record, truncation is not detectable and the report says so.
Same rules and wording as the Rust profile (src/core/src/verify.rs).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .audit import heads
from .audit import verify as verify_chain
from .inputs import normalize_path
from .trust import verify_timestamps

NO_ANCHOR = "truncation not detectable without a timestamp or case record"
CASE_FILE, CASE_LOG = "case.json", "case-log.jsonl"


@dataclass
class LogVerification:
    path: Path
    entries: int = 0
    problems: list[str] = field(default_factory=list)  # anything here means exit 3
    timestamps: list[str] = field(default_factory=list)
    truncation: str = ""
    warnings: list[str] = field(default_factory=list)


def _entries(path: Path) -> list[dict]:
    out = []
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for line in lines:
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def case_of_log_dir(log_dir: Path) -> Path | None:
    """<CASE> when log_dir is <CASE>/runs/<tool>/<RUN-ID>/logs."""
    p = Path(normalize_path(log_dir))
    if p.name != "logs" or len(p.parents) < 4 or p.parents[2].name != "runs":
        return None
    root = p.parents[3]
    return root if (root / CASE_FILE).is_file() else None


def _entries_count(n: int) -> str:
    return "1 entry" if n == 1 else f"{n} entries"


def verify_log(path: Path) -> LogVerification:
    """Verifies path (an audit.jsonl). Raises OSError only when the log cannot be opened."""
    path = Path(path)
    directory = path.parent
    v = LogVerification(path)
    n, problems = verify_chain(path)
    if problems:
        v.problems = problems
        return v
    v.entries = n
    entries = _entries(path)
    v.problems += verify_timestamps(directory, heads(path))

    # Every timestamp the log says it obtained must still be next to it (deleting the token files is how a
    # truncation below the last timestamp would be hidden).
    for e in (e for e in entries if e.get("action") == "timestamp_obtained"):
        d = e.get("details") or {}
        file, want = d.get("file") or "", d.get("token_sha256") or ""
        got = hashlib.sha256((directory / file).read_bytes()).hexdigest() if file and (directory / file).is_file() else ""
        if not file or got != want:
            v.problems.append(f"entry #{e.get('seq')} records timestamp token {file or '?'}, which is missing or altered")

    anchors: list[tuple[int, str]] = []
    for meta_path in sorted(directory.glob("timestamp-*.json")):
        try:
            m = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        seq = m.get("covers_seq") if isinstance(m.get("covers_seq"), int) else 0
        v.timestamps.append(f"timestamp {m.get('gen_time', '?')} by {m.get('tsa', '?')} covers entry #{m.get('covers_seq')}")
        # seq > n is reported by verify_timestamps ("truncated: ... which is not in the log").
        if 0 < seq <= n:
            anchors.append((seq, f"the RFC 3161 timestamp ({meta_path.name})"))

    case = case_of_log_dir(directory)
    if case is not None:
        _case_anchor(case, entries, n, v, anchors)

    if not anchors:
        v.truncation = NO_ANCHOR
    else:
        s, by = max(anchors, key=lambda a: a[0])
        if s == n:
            v.truncation = f"truncation: the final entry #{n} is anchored by {by}"
        else:
            later = [str(e.get("action", "?")) for e in entries if (e.get("seq") or 0) > s]
            v.truncation = (
                f"truncation: entries up to #{s} are anchored by {by}; {_entries_count(n - s)} after it ({', '.join(later)}) "
                "cannot be proven complete"
            )
    return v


def _case_anchor(case: Path, entries: list[dict], n: int, v: LogVerification, anchors: list[tuple[int, str]]) -> None:
    """Compares the end of the run's log with run_finished in the case log."""
    case_log = case / CASE_LOG
    try:
        _, broken = verify_chain(case_log)
    except OSError as e:
        broken = [str(e)]
    if broken:
        v.problems.append(f"{case_log} is broken (run verify-case): it cannot vouch for this log's length")
        return
    run_id = (entries[0] if entries else {}).get("run_id", "")
    case_entries = _entries(case_log)

    def mine(action: str) -> dict | None:
        return next((e for e in case_entries if e.get("action") == action and e.get("run_id") == run_id), None)

    fin = mine("run_finished")
    if fin is None:
        if mine("run_started") is not None:
            v.warnings.append(f"the case log has no run_finished for run {run_id} (still running, or interrupted)")
        else:
            v.warnings.append(f"run {run_id} is not announced in the case log")
        return
    details = fin.get("details") or {}
    recorded = details.get("audit_entries") or 0
    if not recorded:
        return
    if recorded > n:
        v.problems.append(f"truncated: the case log records {recorded} entries at run_finished, but the log ends at entry #{n}")
        return
    at = next((e for e in entries if e.get("seq") == recorded), None)
    if (at or {}).get("entry_hash") != details.get("audit_head"):
        v.problems.append(f"entry #{recorded} is not the audit head recorded in the case log at run_finished")
        return
    for later in (e for e in entries if (e.get("seq") or 0) > recorded):
        if later.get("action") != "timestamp_obtained":
            v.problems.append(f"entry #{later.get('seq')} ({later.get('action')}) was appended after run_finished")
    anchors.append((recorded, "the case log (run_finished)"))
