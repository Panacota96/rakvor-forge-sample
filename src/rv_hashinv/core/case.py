"""Shared case folder (rakvor.case/1): the link between Rakvor tools.

  <CASE>/case.json               created once, never changed
  <CASE>/case-log.jsonl          hash-chained (same rule as audit.jsonl), append-only, written under case-log.lock
  <CASE>/evidence/registry.json  written only by the intake tool; its SHA-256 is recorded in the case log
  <CASE>/evidence/registry.csv
  <CASE>/runs/<tool>/<RUN-ID>/{logs,reports}/

The intake tool registers evidence (E0001...); analysis tools re-hash and compare against the registry.
Every append re-verifies the case log first: a broken case is never extended. Same semantics and file formats
as the Rust profile (src/core/src/case.rs); the contract is references/case-folder.md of the forge.
"""

from __future__ import annotations

import json
import os
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .audit import GENESIS, build_entry, heads
from .audit import verify as verify_chain
from .hashing import ALGORITHMS, hash_bytes, hash_stream
from .inputs import normalize_path  # noqa: F401 - re-exported: the registry stores this form
from .timeutil import utc_now
from .trust import verify_timestamps

SCHEMA_CASE = "rakvor.case/1"
SCHEMA_REGISTRY = "rakvor.registry/1"
CASE_FILE = "case.json"
CASE_LOG = "case-log.jsonl"
LOCK_FILE = "case-log.lock"
REGISTRY_JSON = "evidence/registry.json"
REGISTRY_CSV = "evidence/registry.csv"
STALE_LOCK_S = 600  # a lock older than this is reported as stale; it is never deleted automatically
LOCK_WAIT_S = 30.0  # how long a tool waits for another tool's lock
INTAKE, ANALYSIS = "intake", "analysis"
ROLES = (INTAKE, ANALYSIS)


def same_path(a: str, b: str) -> bool:
    """Paths are compared as text after normalisation; Windows file systems are case-insensitive, so the comparison is too."""
    if os.name == "nt":
        return a.casefold() == b.casefold()
    return a == b


class CaseError(ValueError):
    """Case-folder problem. `exit_code`: 2 usage, 3 broken case, 1 otherwise."""

    exit_code = 1


class CaseUsageError(CaseError):
    """Wrong schema, case id mismatch, missing --case on creation, unknown evidence id."""

    exit_code = 2


class CaseBrokenError(CaseError):
    """Case log chain or registry digest broken: the case is never extended."""

    exit_code = 3


class CaseLockedError(CaseError):
    """Another tool holds case-log.lock, or a stale lock is left."""

    exit_code = 1


def _pretty(value: Any) -> bytes:
    # Same layout as the Rust profile (serde_json pretty, sorted keys).
    return (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def _sha256_file(p: Path) -> str | None:
    try:
        return hash_bytes(p.read_bytes(), "sha256")
    except OSError:
        return None


def registry_digest(directory: Path) -> str | None:
    """SHA-256 of evidence/registry.json (None when the case has no registry yet)."""
    return _sha256_file(Path(directory) / REGISTRY_JSON)


def evidence_id(n: int) -> str:
    return f"E{n:04d}"


def _number(eid: str) -> int:
    try:
        return int(eid.lstrip("E"))
    except ValueError:
        return 0


def parse_evidence_ids(raw: list[str] | tuple[str, ...]) -> list[str]:
    """ "E0001,e7" -> ["E0001", "E0007"]. CaseUsageError on anything else."""
    out: list[str] = []
    for part in (p.strip() for r in raw for p in r.split(",")):
        if not part:
            continue
        digits = part[1:] if part[:1] in ("E", "e") else ""
        if not digits.isdigit() or int(digits) == 0:
            raise CaseUsageError(f"invalid evidence id '{part}': use E0001, E0002, …")
        eid = evidence_id(int(digits))
        if eid not in out:
            out.append(eid)
    return out


@dataclass
class Comparison:
    kind: str  # match | mismatch | none
    algorithms: list[str] = field(default_factory=list)
    algorithm: str = ""
    expected: str = ""
    actual: str = ""


def compare(expected: dict[str, str], actual: list[tuple[str, str]]) -> Comparison:
    """Compares fresh hashes with a registry entry on every algorithm both have."""
    common = []
    for algo, digest in actual:
        if algo in expected:
            if expected[algo].lower() != digest.lower():
                return Comparison("mismatch", algorithm=algo, expected=expected[algo], actual=digest)
            common.append(algo)
    return Comparison("match", algorithms=common) if common else Comparison("none")


def ensure_case_algorithm(selected: list[str], registry: list[str]) -> tuple[list[str], tuple[str, str | None] | None]:
    """A run always includes at least one algorithm present in the registry (2-algorithm limit kept).
    Returns the effective selection and, when changed, (added, replaced)."""
    if not registry or any(a in registry for a in selected):
        return list(selected), None
    pick = "sha256" if "sha256" in registry else registry[0]
    out = list(selected)
    if len(out) < 2:
        return [*out, pick], (pick, None)
    replaced = out[1]
    out[1] = pick
    return out, (pick, replaced)


def _read_json(p: Path) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise ValueError(f"cannot read {p}: {e}") from e
    except json.JSONDecodeError as e:
        raise ValueError(f"{p} is not valid JSON: {e}") from e


def _entries(path: Path) -> list[dict]:
    out = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for line in lines:
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


@dataclass
class LogState:
    entries: int
    head: str
    registry_sha256: str | None


def verify_log_and_registry(directory: Path) -> tuple[LogState | None, list[str]]:
    """Verifies case.json, the case-log chain and the registry digest. (state, problems)."""
    directory = Path(directory)
    log_path = directory / CASE_LOG
    try:
        n, chain = verify_chain(log_path)
    except OSError as e:
        return None, [f"{CASE_LOG}: cannot open: {e}"]
    if chain:
        return None, [f"{CASE_LOG}: {p}" for p in chain]
    problems: list[str] = []
    entries = _entries(log_path)
    head = entries[-1]["entry_hash"] if entries else GENESIS
    first = entries[0] if entries else {}
    if first.get("action") == "case_created":
        try:
            case = _read_json(directory / CASE_FILE)
        except ValueError:
            case = {}
        if first.get("details", {}).get("case_id") != case.get("case_id"):
            problems.append(f"{CASE_FILE}: case_id differs from the case_created entry")
        recorded_case = first.get("details", {}).get("case_json_sha256")
        if isinstance(recorded_case, str) and _sha256_file(directory / CASE_FILE) != recorded_case:
            problems.append(f"{CASE_FILE}: content differs from the digest recorded at creation (edited)")
    else:
        problems.append(f"{CASE_LOG}: the first entry is not case_created")
    recorded = next(
        (e["details"]["registry_sha256"] for e in reversed(entries) if isinstance(e.get("details", {}).get("registry_sha256"), str)),
        None,
    )
    reg = directory / REGISTRY_JSON
    if recorded is not None and reg.is_file():
        if _sha256_file(reg) != recorded:
            problems.append(f"{REGISTRY_JSON}: SHA-256 differs from the digest recorded in the case log (edited registry)")
    elif recorded is not None:
        problems.append(f"{REGISTRY_JSON}: missing, but the case log records a registry digest")
    elif reg.is_file():
        problems.append(f"{REGISTRY_JSON}: present, but no registry digest is recorded in the case log")
    return (None if problems else LogState(n, head, recorded)), problems


@dataclass
class Writer:
    """Who is writing (stored in the lock file and in case-log entries)."""

    tool: str
    version: str
    run_id: str
    actor: str


class CaseLock:
    """Exclusive lock on the case log (created with O_EXCL); removed on exit."""

    def __init__(self, directory: Path, w: Writer, wait_s: float):
        self.path = Path(directory) / LOCK_FILE
        started = time.monotonic()
        while True:
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            except FileExistsError:
                try:
                    holder = json.loads(self.path.read_text(encoding="utf-8").strip() or "{}")
                except (OSError, json.JSONDecodeError):
                    holder = {}
                who = f"{holder.get('tool', '?')} run {holder.get('run_id', '?')} (since {holder.get('created_utc', '?')})"
                try:
                    age = time.time() - self.path.stat().st_mtime
                except OSError:
                    age = 0
                if age > STALE_LOCK_S:
                    raise CaseLockedError(
                        f"stale case lock {self.path} held by {who} for more than {STALE_LOCK_S // 60} minutes. "
                        "If no Rakvor tool is working on this case, delete the lock file by hand and run again "
                        "(it is never removed automatically)."
                    ) from None
                if time.monotonic() - started >= wait_s:
                    raise CaseLockedError(f"the case log is locked by {who} ({self.path}); try again when it has finished") from None
                time.sleep(0.1)
                continue
            except OSError as e:
                raise CaseError(f"cannot create lock {self.path}: {e}") from e
            info = {
                "tool": w.tool,
                "version": w.version,
                "run_id": w.run_id,
                "pid": os.getpid(),
                "host": socket.gethostname(),
                "created_utc": utc_now(),
            }
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(info, sort_keys=True, separators=(",", ":")) + "\n")
            return

    def __enter__(self) -> CaseLock:
        return self

    def __exit__(self, *exc) -> None:
        try:
            self.path.unlink()
        except OSError:
            pass


def _load_case_json(directory: Path) -> dict:
    p = Path(directory) / CASE_FILE
    try:
        v = _read_json(p)
    except ValueError as e:
        raise CaseUsageError(str(e)) from e
    if not isinstance(v, dict) or v.get("schema") != SCHEMA_CASE:
        schema = v.get("schema") if isinstance(v, dict) else None
        raise CaseUsageError(f"{p} has schema {json.dumps(schema)} ; this tool reads {SCHEMA_CASE} only")
    return v


def _load_registry(directory: Path) -> list[dict]:
    p = Path(directory) / REGISTRY_JSON
    if not p.is_file():
        return []
    try:
        v = _read_json(p)
    except ValueError as e:
        raise CaseBrokenError(str(e)) from e
    if v.get("schema") != SCHEMA_REGISTRY:
        raise CaseUsageError(f"{p} is not a {SCHEMA_REGISTRY} file")
    return sorted(v.get("items", []), key=lambda i: _number(i["evidence_id"]))


def registry_csv(items: list[dict]) -> str:
    """evidence_id,path,size,<algorithms present, standard order>,run_id"""
    algos = [a for a in ALGORITHMS if any(a in i["hashes"] for i in items)]

    def field_(s: str) -> str:
        return '"' + s.replace('"', '""') + '"' if any(c in s for c in ',"\n\r') else s

    lines = [",".join(["evidence_id", "path", "size", *algos, "run_id"])]
    for i in items:
        row = [i["evidence_id"], field_(i["path"]), str(i["size"]), *[i["hashes"].get(a, "") for a in algos], i["registered_by"]["run_id"]]
        lines.append(",".join(row))
    return "\n".join(lines) + "\n"


@dataclass
class Registration:
    """One item to register (intake role)."""

    path: str  # normalize_path() of the evidence file
    size: int
    hashes: list[tuple[str, str]]
    audit_seq: int


@dataclass
class Case:
    """An open, verified case folder."""

    dir: Path
    case_id: str
    jurisdiction: str
    created_utc: str
    items: list[dict] = field(default_factory=list)  # registry snapshot, sorted by evidence id
    lock_wait_s: float = LOCK_WAIT_S

    @classmethod
    def open(cls, directory: Path) -> Case:
        """Opens an existing case and verifies it (CaseBrokenError when broken)."""
        directory = Path(directory)
        v = _load_case_json(directory)
        _, problems = verify_log_and_registry(directory)
        if problems:
            raise CaseBrokenError(f"the case folder {directory} fails verification; a broken case is never extended: {'; '.join(problems)}")
        return cls(directory, v.get("case_id", ""), v.get("jurisdiction", "co"), v.get("created_utc", ""), _load_registry(directory))

    @classmethod
    def open_or_create(cls, directory: Path, case_id: str | None, jurisdiction: str, w: Writer) -> tuple[Case, bool]:
        """Opens the case, or creates it (case.json + case_created) when the folder has no case.json."""
        directory = Path(directory)
        if (directory / CASE_FILE).exists():
            c = cls.open(directory)
            c.check_case_id(case_id)
            return c, False
        cid = (case_id or "").strip()
        if not cid:
            raise CaseUsageError(f"{directory} is not a case folder yet: give --case ID (and --jurisdiction) to create it")
        if jurisdiction not in ("co", "fr"):
            raise CaseUsageError(f"unknown jurisdiction '{jurisdiction}': use co or fr")
        try:
            (directory / "evidence").mkdir(parents=True, exist_ok=True)
        except OSError as e:
            raise CaseError(f"cannot create {directory}: {e}") from e
        lock = CaseLock(directory, w, LOCK_WAIT_S)
        with lock:
            body = {
                "schema": SCHEMA_CASE,
                "case_id": cid,
                "jurisdiction": jurisdiction,
                "created_utc": utc_now(),
                "created_by": {"tool": w.tool, "version": w.version, "run_id": w.run_id, "actor": w.actor},
            }
            data = _pretty(body)
            try:
                with open(directory / CASE_FILE, "xb") as fh:
                    fh.write(data)
            except FileExistsError:
                created = None
            else:
                created = cls(directory, cid, jurisdiction, body["created_utc"])
                created._append_unlocked(
                    w,
                    "case_created",
                    {
                        "case_id": cid,
                        "jurisdiction": jurisdiction,
                        "schema": SCHEMA_CASE,
                        "case_json_sha256": hash_bytes(data, "sha256"),
                        "registry_sha256": None,
                        "tool": w.tool,
                        "version": w.version,
                    },
                )
        if created is None:  # another tool created it in the meantime
            c = cls.open(directory)
            c.check_case_id(case_id)
            return c, False
        return created, True

    def check_case_id(self, case_id: str | None) -> None:
        cid = (case_id or "").strip()
        if cid and cid != self.case_id:
            raise CaseUsageError(f"the case folder {self.dir} belongs to case {self.case_id}, not {cid}")

    def check_ids(self, ids: list[str]) -> None:
        unknown = [i for i in ids if self.get(i) is None]
        if unknown:
            raise CaseUsageError(f"evidence id(s) not in the case registry: {', '.join(unknown)}")

    def get(self, eid: str) -> dict | None:
        return next((i for i in self.items if i["evidence_id"] == eid), None)

    def find_by_path(self, normalized: str) -> dict | None:
        # Latest registration of that path wins (an earlier one may have been superseded by changed content).
        return next((i for i in reversed(self.items) if same_path(i["path"], normalized)), None)

    def find_by_content(self, hashes: list[tuple[str, str]]) -> dict | None:
        return next((i for i in self.items if compare(i["hashes"], hashes).kind == "match"), None)

    def registry_algorithms(self) -> list[str]:
        """Algorithms present in every registered item, in the standard order."""
        return [a for a in ALGORITHMS if self.items and all(a in i["hashes"] for i in self.items)]

    def _append_unlocked(self, w: Writer, action: str, details: dict) -> tuple[int, str]:
        path = self.dir / CASE_LOG
        if path.exists():
            n, problems = verify_chain(path)
            if problems:
                raise CaseBrokenError(f"refusing to extend a broken case log ({path}): {problems[0]}")
            entries = _entries(path)
            seq, prev = n + 1, (entries[-1]["entry_hash"] if entries else GENESIS)
        else:
            seq, prev = 1, GENESIS
        entry = build_entry(seq, w.run_id, w.actor, action, None, details, prev)
        try:
            with open(path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as e:
            raise CaseError(f"cannot write {path}: {e}") from e
        return seq, entry["entry_hash"]

    def _reverify(self) -> None:
        _, problems = verify_log_and_registry(self.dir)
        if problems:
            raise CaseBrokenError(f"refusing to extend a broken case ({self.dir}): {'; '.join(problems)}")

    def append(self, w: Writer, action: str, details: dict) -> tuple[int, str]:
        """Appends one event under the lock, after re-verifying the case log and registry digest."""
        with CaseLock(self.dir, w, self.lock_wait_s):
            self._reverify()
            return self._append_unlocked(w, action, details)

    def register(self, w: Writer, regs: list[Registration]) -> tuple[list[tuple[str, bool, str]], int]:
        """Intake: registers items under the lock (reloading the registry first), writes registry.json/.csv and
        appends evidence_registered with the new registry digest. Same path + same content -> the existing id;
        anything else -> a new id. Returns per input (evidence_id, newly added, registered_utc) and the case-log seq."""
        with CaseLock(self.dir, w, self.lock_wait_s):
            self._reverify()
            items = _load_registry(self.dir)
            nxt = max((_number(i["evidence_id"]) for i in items), default=0)
            now = utc_now()
            out: list[tuple[str, bool, str]] = []
            for r in regs:
                existing = next(
                    (i for i in reversed(items) if same_path(i["path"], r.path) and compare(i["hashes"], r.hashes).kind == "match"),
                    None,
                )
                if existing is not None:
                    out.append((existing["evidence_id"], False, existing["registered_utc"]))
                    continue
                nxt += 1
                eid = evidence_id(nxt)
                items.append(
                    {
                        "evidence_id": eid,
                        "path": r.path,
                        "size": r.size,
                        "hashes": dict(sorted(r.hashes)),
                        "registered_by": {"tool": w.tool, "version": w.version, "run_id": w.run_id, "audit_seq": r.audit_seq},
                        "registered_utc": now,
                    }
                )
                out.append((eid, True, now))
            items.sort(key=lambda i: _number(i["evidence_id"]))
            added = [o[0] for o in out if o[1]]
            reg_path = self.dir / REGISTRY_JSON
            if added or not reg_path.exists():
                try:
                    reg_path.parent.mkdir(parents=True, exist_ok=True)
                    reg_path.write_bytes(_pretty({"schema": SCHEMA_REGISTRY, "items": items}))
                    (self.dir / REGISTRY_CSV).write_bytes(registry_csv(items).encode("utf-8"))
                except OSError as e:
                    raise CaseError(f"cannot write the registry in {self.dir}: {e}") from e
            seq, _ = self._append_unlocked(
                w,
                "evidence_registered",
                {
                    "tool": w.tool,
                    "version": w.version,
                    "evidence_ids": [o[0] for o in out],
                    "added": added,
                    "registry_items": len(items),
                    "registry_sha256": _sha256_file(reg_path),
                },
            )
        self.items = items
        return out, seq


@dataclass
class CaseVerification:
    """What verify-case found."""

    case_id: str = ""
    entries: int = 0
    registry_items: int = 0
    runs: int = 0
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def verify_case(directory: Path) -> CaseVerification:
    """Full check of a case folder: case log chain, registry digest, each run's audit chain (and timestamps), the
    cross-links (case_linked <-> run_started) and that the audit head recorded at run_finished is the run's final
    entry (later entries may only be timestamp_obtained)."""
    directory = Path(directory)
    v = CaseVerification()
    try:
        v.case_id = _load_case_json(directory).get("case_id", "")
    except CaseError as e:
        v.problems.append(str(e))
        return v
    state, problems = verify_log_and_registry(directory)
    if state is not None:
        v.entries = state.entries
    v.problems += problems
    if not (directory / CASE_LOG).is_file():
        return v
    try:
        v.registry_items = len(_load_registry(directory))
    except CaseError:
        v.registry_items = 0
    started: dict[str, tuple[str, str]] = {}
    finished: dict[str, dict] = {}
    for e in _entries(directory / CASE_LOG):
        rid, action = e.get("run_id", ""), e.get("action")
        if action == "run_started":
            started[rid] = (e.get("details", {}).get("run_dir", ""), e.get("entry_hash", ""))
        elif action == "run_finished":
            if rid not in started:
                v.problems.append(f"case log: run_finished for {rid} without run_started")
            finished[rid] = e.get("details", {})
    v.runs = len(started)
    for rid, (run_dir, started_hash) in started.items():
        log_dir = directory / run_dir / "logs"
        audit_path = log_dir / "audit.jsonl"
        fin = finished.get(rid)
        recorded_entries = (fin or {}).get("audit_entries") or 0
        if not audit_path.is_file():
            if fin is None or recorded_entries > 0:
                v.problems.append(f"run {rid}: {audit_path} is missing")
            continue
        _, chain = verify_chain(audit_path)
        if chain:
            v.problems += [f"run {rid}: audit.jsonl {p}" for p in chain]
            continue
        entries = _entries(audit_path)
        linked = next((e for e in entries if e.get("action") == "case_linked"), None)
        if linked is None:
            v.problems.append(f"run {rid}: audit.jsonl has no case_linked entry")
        else:
            if linked["details"].get("case_id") != v.case_id:
                v.problems.append(f"run {rid}: case_linked names another case")
            if linked["details"].get("case_log_head_at_start") != started_hash:
                v.problems.append(f"run {rid}: case_linked does not point to its run_started entry in the case log")
        v.problems += [f"run {rid}: {p}" for p in verify_timestamps(log_dir, heads(audit_path))]
        if fin is None:
            v.warnings.append(f"run {rid}: no run_finished in the case log (still running, or interrupted)")
            continue
        if not recorded_entries:
            continue
        at = next((e for e in entries if e.get("seq") == recorded_entries), None)
        if (at or {}).get("entry_hash") != fin.get("audit_head"):
            v.problems.append(f"run {rid}: the audit head recorded in the case log is not entry #{recorded_entries} of the run's audit.jsonl")
        for later in (e for e in entries if e.get("seq", 0) > recorded_entries):
            if later.get("action") != "timestamp_obtained":
                v.problems.append(f"run {rid}: audit entry #{later.get('seq')} ({later.get('action')}) was appended after run_finished")
    runs = directory / "runs"
    if runs.is_dir():
        for tool in sorted(p for p in runs.iterdir() if p.is_dir()):
            for r in sorted(tool.iterdir()):
                if r.name not in started:
                    v.warnings.append(f"runs/{tool.name}/{r.name} is not announced in the case log")
    return v


@dataclass
class Rehash:
    """What verify-case --rehash found."""

    checked: int = 0  # registered items re-hashed (the latest registration of each reachable path)
    matched: int = 0  # of those, items whose digests all equal the registry's
    registered: int = 0


def rehash_registry(directory: Path, v: CaseVerification) -> Rehash:
    """Re-hashes every registered item that is still reachable and compares it with the registry (verify-case
    --rehash). A path registered several times (its content changed between intakes) is compared with its latest
    registration; earlier ones are reported as superseded. Differences go to v.problems (exit 3), unreachable or
    unreadable files to v.warnings."""
    try:
        items = _load_registry(Path(directory))
    except CaseError as e:
        v.problems.append(f"{REGISTRY_JSON}: cannot re-hash: {e}")
        return Rehash()
    r = Rehash(registered=len(items))
    for i, item in enumerate(items):
        eid, path = item["evidence_id"], item["path"]
        later = next((o for o in items[i + 1 :] if same_path(o["path"], path)), None)
        if later is not None:
            v.warnings.append(f"{eid} {path}: superseded by {later['evidence_id']} (same path registered again): not re-hashed")
            continue
        if not Path(path).is_file():
            v.warnings.append(f"{eid} {path}: not reachable from this workstation: not re-hashed")
            continue
        algos = [a for a in ALGORITHMS if a in item.get("hashes", {})][:2]
        if not algos:
            v.warnings.append(f"{eid} {path}: no supported algorithm in the registry: not re-hashed")
            continue
        try:
            with open(path, "rb") as fh:
                outcome = hash_stream(fh, algos)
        except OSError as e:
            v.warnings.append(f"{eid} {path}: cannot be read ({e}): not re-hashed")
            continue
        if outcome is None:
            continue
        r.checked += 1
        c = compare(item["hashes"], outcome.digests)
        if c.kind == "match":
            r.matched += 1
        elif c.kind == "mismatch":
            v.problems.append(f"{eid} {path}: {c.algorithm} differs from the registry (registered {c.expected}, now {c.actual})")
    return r


def preflight(directory: Path, case_id: str | None, evidence_ids: list[str]) -> None:
    """Checks done by front-ends before a run, so case problems map to exit codes (2 usage, 3 broken):
    schema, broken log/registry, case id, missing --case on creation, unknown evidence ids."""
    directory = Path(directory)
    if not (directory / CASE_FILE).exists():
        if not (case_id or "").strip():
            raise CaseUsageError(f"{directory} is not a case folder yet: give --case ID (and --jurisdiction) to create it")
        if evidence_ids:
            raise CaseUsageError("--evidence needs an existing case folder with a registry")
        return
    c = Case.open(directory)
    c.check_case_id(case_id)
    c.check_ids(evidence_ids)
