"""Shared case folder: intake registers, analysis verifies, tampering is detected, the lock is respected,
and (with RV_CROSS_PROJECT) a case written by the other profile verifies here and the reverse."""

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from rv_hashinv.core import CASE_ROLE, RunConfig, run
from rv_hashinv.core import case as casef
from rv_hashinv.gui.state import GuiState

ROOT = Path(__file__).resolve().parent.parent


def cli(*args) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "RV_NO_TIMESTAMP": "1"}
    return subprocess.run([sys.executable, "-m", "rv_hashinv", *map(str, args)], capture_output=True, text=True, encoding="utf-8", env=env)


def _cfg(case: Path, role: str, inputs: list[Path], **kw) -> RunConfig:
    base = dict(
        inputs=inputs,
        out_dir=case.parent / "unused",
        algorithms=["sha256", "md5"],
        langs=["en"],
        actor="tester",
        case_id="CASE-T",
        frontend="test",
        tool_version="0.0.0",
        case_dir=case,
        case_role=role,
    )
    base.update(kw)
    return RunConfig(**base)


def _go(cfg: RunConfig, cancel: bool = False, events: list | None = None):
    ev = threading.Event()
    if cancel:
        ev.set()
    return run(cfg, (events.append if events is not None else (lambda e: None)), ev)


def _log(case: Path) -> list[dict]:
    return [json.loads(line) for line in (case / casef.CASE_LOG).read_text("utf-8").splitlines()]


def _runs(case: Path) -> int:
    d = case / "runs" / "rv-hashinv"
    return len(list(d.iterdir())) if d.is_dir() else 0


def seed_registry(case: Path, inputs: list[Path], case_id: str) -> None:
    """Analysis-role tools (CASE_ROLE flipped by the scaffold) need registered evidence first: an intake run made
    through the core with the role set explicitly. Intake tools register through their own front-ends."""
    _go(_cfg(case, "intake", inputs, case_id=case_id, jurisdiction="fr", actor="seed"))


def _run_folder(stdout: str) -> Path:
    """The run folder printed on the "logs:" line of the summary."""
    return Path(next(line.split("logs:", 1)[1].strip() for line in stdout.splitlines() if line.strip().startswith("logs:"))).parent


@pytest.fixture
def evidence(tmp_path, sample) -> Path:
    ev = tmp_path / "evidence"
    shutil.copytree(sample, ev)
    return ev


def test_intake_then_analysis_detects_tampering(tmp_path, evidence):
    case = tmp_path / "case"
    # 1. Intake registers the three sample items.
    s = _go(_cfg(case, "intake", [evidence]))
    assert (s.case.tally.registered, s.case.tally.added) == (3, 3)
    assert s.log_dir.parent.parent == case / "runs" / "rv-hashinv" and s.log_dir.name == "logs" and s.report_dir.name == "reports"
    assert [i["evidence_id"] for i in casef.Case.open(case).items] == ["E0001", "E0002", "E0003"]
    actions = [json.loads(line)["action"] for line in (s.log_dir / "audit.jsonl").read_text("utf-8").splitlines()]
    assert actions[:2] == ["run_started", "case_linked"] and actions.count("evidence_registered") == 3
    item = s.report_dir / "items" / "00001-acta-copia.txt"
    assert json.loads((item / "technical.json").read_text("utf-8"))["item"]["evidence_id"] == "E0001"
    custody = json.loads((item / "custody.json").read_text("utf-8"))
    assert (custody["evidence_id"], custody["case_id"]) == ("E0001", "CASE-T") and custody["intake_utc"]
    v = casef.verify_case(case)
    assert v.problems == [] and (v.runs, v.registry_items) == (1, 3)
    assert (case / casef.REGISTRY_CSV).read_text("utf-8").startswith("evidence_id,path,size,md5,sha256,run_id\n")

    # 2. Re-running intake keeps the ids.
    s = _go(_cfg(case, "intake", [evidence]))
    assert (s.case.tally.registered, s.case.tally.added) == (3, 0)

    # 3. Analysis role (constructed here), all registered items, disjoint algorithm -> sha256 added.
    events: list = []
    s = _go(_cfg(case, "analysis", [], case_id=None, algorithms=["blake3"]), events=events)
    t = s.case.tally
    assert (t.verified, t.mismatched, t.unregistered, s.high) == (3, 0, 0, 0)
    audit = (s.log_dir / "audit.jsonl").read_text("utf-8")
    assert '"case_algorithm_added"' in audit and '"evidence_verified_against_case"' in audit
    assert sum(e["event"] == "evidence_linked" and e["status"] == "verified" for e in events) == 3

    # 4. Tampered evidence copy -> high mismatch finding (analysis still runs); unregistered file -> medium.
    (evidence / "acta.txt").write_text("tampered")
    (evidence / "extra.txt").write_text("not registered")
    s = _go(_cfg(case, "analysis", [evidence], case_id=None))
    t = s.case.tally
    assert (t.verified, t.mismatched, t.unregistered) == (2, 1, 1) and s.high >= 1
    stats = (s.report_dir / "statistics.json").read_text("utf-8")
    assert "EVIDENCE_HASH_MISMATCH_WITH_CASE" in stats and "EVIDENCE_NOT_IN_CASE_REGISTRY" in stats
    html = (s.report_dir / "statistics.en.html").read_text("utf-8")
    assert "E0003" in html and "Case folder" in html
    fin = _log(case)[-1]
    assert fin["action"] == "run_finished" and fin["details"]["verification"]["mismatched"] == 1
    assert fin["details"]["audit_head"] == s.audit_head
    # Intake of the changed file: new id + note.
    s = _go(_cfg(case, "intake", [evidence / "acta.txt"]))
    assert s.medium == 1 and len(casef.Case.open(case).items) == 4
    assert casef.verify_case(case).problems == []

    # 5. Cancelled and failed runs still close their entry in the case log.
    s = _go(_cfg(case, "analysis", [], case_id=None), cancel=True)
    assert s.cancelled and _log(case)[-1]["details"]["status"] == "cancelled"
    with pytest.raises(ValueError):
        _go(_cfg(case, "analysis", [tmp_path / "missing"], case_id=None))
    last = _log(case)[-1]
    assert (last["action"], last["details"]["status"]) == ("run_finished", "failed")
    assert casef.verify_case(case).problems == []

    # 6. A tampered case log: detected, and never extended.
    lp = case / casef.CASE_LOG
    original = lp.read_text("utf-8")
    tampered = original.replace('"tester"', '"mallory"', 1)
    lp.write_text(tampered, encoding="utf-8")
    assert casef.verify_case(case).problems
    before = _runs(case)
    with pytest.raises(casef.CaseBrokenError, match="never extended"):
        _go(_cfg(case, "analysis", [], case_id=None))
    assert _runs(case) == before and lp.read_text("utf-8") == tampered
    lp.write_text(original, encoding="utf-8")

    # 7. An edited registry is detected through the digest recorded in the case log.
    rp = case / casef.REGISTRY_JSON
    reg = rp.read_text("utf-8")
    rp.write_text(reg.replace("E0002", "E0009", 1), encoding="utf-8")
    assert any("registry" in p for p in casef.verify_case(case).problems)
    with pytest.raises(casef.CaseBrokenError):
        _go(_cfg(case, "analysis", [], case_id=None))
    rp.write_text(reg, encoding="utf-8")

    # 8. An edited run audit log is detected by verify-case.
    first = sorted((case / "runs" / "rv-hashinv").iterdir())[0]
    ap = first / "logs" / "audit.jsonl"
    ap.write_text(ap.read_text("utf-8").replace('"tester"', '"mallory"', 1), encoding="utf-8")
    assert casef.verify_case(case).problems


def test_evidence_ids_and_usage_errors(tmp_path, evidence):
    case = tmp_path / "case"
    with pytest.raises(casef.CaseUsageError):
        _go(_cfg(case, "intake", [evidence], case_id=None))
    _go(_cfg(case, "intake", [evidence]))
    s = _go(_cfg(case, "analysis", [], evidence_ids=["e2"]))
    assert s.items == 1 and s.case.tally.verified == 1
    with pytest.raises(casef.CaseUsageError, match="E0042"):
        _go(_cfg(case, "analysis", [], evidence_ids=["E0042"]))
    with pytest.raises(casef.CaseUsageError):
        _go(_cfg(case, "analysis", [], case_id="OTHER"))
    assert casef.parse_evidence_ids(["e1, E0007", "E0001"]) == ["E0001", "E0007"]
    with pytest.raises(casef.CaseUsageError):
        casef.parse_evidence_ids(["7"])
    assert casef.ensure_case_algorithm(["md5", "sha1"], ["blake3"]) == (["md5", "blake3"], ("blake3", "sha1"))
    assert casef.ensure_case_algorithm(["sha256"], ["sha256"]) == (["sha256"], None)


def test_lock_contention_and_stale_lock(tmp_path):
    case = tmp_path / "case"
    w = casef.Writer("rv-test", "0", "R1", "tester")
    c, created = casef.Case.open_or_create(case, "C-1", "co", w)
    assert created
    c.lock_wait_s = 0
    with casef.CaseLock(case, casef.Writer("rv-test", "0", "OTHER", "x"), 0):
        with pytest.raises(casef.CaseLockedError, match="locked by rv-test run OTHER"):
            c.append(w, "run_started", {})
    c.append(w, "run_started", {})
    lock = case / casef.LOCK_FILE
    lock.write_text("{}")
    old = time.time() - 11 * 60
    os.utime(lock, (old, old))
    with pytest.raises(casef.CaseLockedError, match="stale"):
        c.append(w, "run_started", {})
    assert lock.exists(), "a stale lock is never removed automatically"


def test_rehash_compares_reachable_items_with_the_registry(tmp_path):
    case, ev = tmp_path / "case", tmp_path / "ev"
    ev.mkdir()
    a, b = ev / "a.txt", ev / "b.txt"
    a.write_text("a")
    b.write_text("b")
    w = casef.Writer("rv-test", "0", "R1", "tester")

    def reg(p, sha):
        return casef.Registration(casef.normalize_path(p) if isinstance(p, Path) else p, 1, [("sha256", sha)], 3)

    def sha(p):
        return casef.hash_bytes(p.read_bytes(), "sha256")

    c, _ = casef.Case.open_or_create(case, "C-1", "co", w)
    c.register(w, [reg(a, sha(a)), reg(b, sha(b)), reg(str(ev / "gone.txt"), "00")])
    v = casef.CaseVerification()
    r = casef.rehash_registry(case, v)
    assert (r.registered, r.checked, r.matched) == (3, 2, 2) and v.problems == []
    assert any("E0003" in x and "not reachable" in x for x in v.warnings)
    b.write_text("B")  # evidence changed after intake
    v = casef.CaseVerification()
    r = casef.rehash_registry(case, v)
    assert (r.checked, r.matched) == (2, 1) and v.problems[0].startswith("E0002 ") and "sha256 differs" in v.problems[0]
    c.register(casef.Writer("rv-test", "0", "R2", "tester"), [reg(b, sha(b))])  # re-registered: E0002 superseded
    v = casef.CaseVerification()
    r = casef.rehash_registry(case, v)
    assert (r.registered, r.checked, r.matched) == (4, 2, 2) and v.problems == []
    assert any("superseded by E0004" in x for x in v.warnings)


def test_cli_case_flow_and_exit_codes(tmp_path, sample):
    case = tmp_path / "CASE-1"
    intake = CASE_ROLE == "intake"
    if not intake:
        seed_registry(case, [sample], "CASE-1")
    r = cli("scan", "-i", sample, "--case-dir", case, "--case", "CASE-1", "--hash", "sha256,md5", "--jurisdiction", "fr", "--progress", "none")
    assert r.returncode == 0, r.stderr
    expected = "(intake) registered 3 (new 3)" if intake else "(analysis) registered 0 (new 0), verified 3, mismatched 0"
    assert f"case:   CASE-1 {expected}" in r.stdout
    for f in ("case.json", "case-log.jsonl", "evidence/registry.json", "evidence/registry.csv"):
        assert (case / f).is_file(), f
    assert not (case / "case-log.lock").exists()
    run_dir = _run_folder(r.stdout)
    assert run_dir.is_relative_to(case / "runs")
    custody = next((run_dir / "reports" / "items").iterdir()) / "custody.fr.html"
    assert "E0001" in custody.read_text("utf-8")
    r = cli("verify-case", case)
    assert r.returncode == 0 and f"3 registered items, {1 if intake else 2} runs verified" in r.stdout
    r = cli("verify-case", case, "--rehash")
    assert r.returncode == 0 and "re-hashed 3 of 3 registered items: 3 match the registry" in r.stdout
    # verify-log of a run in a case: its end is anchored by run_finished in the case log; truncation is caught.
    r = cli("verify-log", run_dir / "logs")
    assert r.returncode == 0 and re.search(r"truncation: the final entry #\d+ is anchored by the case log \(run_finished\)", r.stdout), r.stdout
    audit = run_dir / "logs" / "audit.jsonl"
    full = audit.read_text("utf-8")
    audit.write_text("".join(full.splitlines(keepends=True)[:-1]), encoding="utf-8")
    r = cli("verify-log", run_dir / "logs")
    assert r.returncode == 3 and "truncated: the case log records" in r.stdout
    audit.write_text(full, encoding="utf-8")
    r = cli("scan", "--case-dir", case, "--evidence", "E0002", "--progress", "none")
    assert r.returncode == 0 and "items: 1" in r.stdout and ("registered 1 (new 0)" if intake else "verified 1") in r.stdout
    assert cli("scan", "--case-dir", case, "--case", "OTHER", "--progress", "none").returncode == 2
    assert cli("scan", "--case-dir", case, "--evidence", "E0099", "--progress", "none").returncode == 2
    assert cli("scan", "--evidence", "E0001").returncode == 2
    assert cli("scan", "-i", sample, "--case-dir", tmp_path / "NEW", "--progress", "none").returncode == 2
    odd = tmp_path / "ODD"
    odd.mkdir()
    (odd / "case.json").write_text('{"schema":"other/9"}')
    assert cli("scan", "-i", sample, "--case-dir", odd, "--progress", "none").returncode == 2
    assert cli("verify-case", tmp_path).returncode == 1
    log = case / "case-log.jsonl"
    original = log.read_text("utf-8")
    log.write_text(original.replace("CASE-1", "CASE-X", 1), encoding="utf-8")
    r = cli("verify-case", case)
    assert r.returncode == 3 and "BROKEN" in r.stdout
    before = len(list(case.glob("runs/*/*")))
    assert cli("scan", "-i", sample, "--case-dir", case, "--progress", "none").returncode == 3
    assert len(list(case.glob("runs/*/*"))) == before, "no run folder in a broken case"
    log.write_text(original, encoding="utf-8")
    reg = case / "evidence" / "registry.json"
    reg.write_text(reg.read_text("utf-8").replace('"size": ', '"size": 1', 1), encoding="utf-8")
    r = cli("verify-case", case)
    assert r.returncode == 3 and "registry.json" in r.stdout


def test_gui_case_folder_locks_output_and_shows_evidence_ids(tmp_path, evidence):
    s = GuiState(timestamp=False)
    assert not s.can_start()
    case = tmp_path / "CASE-G"
    s.set_case_dir(f'"{case}"')
    assert s.out_locked and s.can_start(), "a case folder alone can start (registered items)"
    assert s.out_dir_display().endswith("<RUN-ID>") and "runs" in s.out_dir_display()
    with pytest.raises(ValueError):
        s.to_config()  # creating a case needs a case id
    s.case_id = "CASE-G"
    s.add_input(evidence)
    if CASE_ROLE == "analysis":
        seed_registry(case, [evidence], "CASE-G")
    cfg = s.to_config()
    assert cfg.case_dir == case and cfg.case_role == CASE_ROLE
    assert [a for a, _ in cfg.preamble][0] == "ui_case_dir_changed"
    s.start()
    summary = run(cfg, s.apply, threading.Event())
    assert s.phase == "finished" and summary.log_dir.is_relative_to(case)
    assert [e.evidence_id for e in s.evidence] == ["E0001", "E0002", "E0003"]
    assert s.evidence_lines()[0].startswith("E0001  acta-copia.txt")
    log = (summary.log_dir / "audit.jsonl").read_text("utf-8")
    assert '"ui_case_dir_changed"' in log and '"case_linked"' in log
    s.set_case_dir("")
    assert not s.out_locked and s.out_dir_display() == "rakvor-out"


# ---------------------------------------------------------------- cross-language (other profile)


def _other_profile() -> tuple[list[str], Path] | None:
    """The other profile of this tool (RV_CROSS_PROJECT = its project folder, with .forge.json)."""
    d = os.environ.get("RV_CROSS_PROJECT")
    if not d:
        return None
    d = Path(d)
    try:
        forge = json.loads((d / ".forge.json").read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if forge.get("profile") == "python":
        py = next((p for p in (d / ".venv/bin/python", d / ".venv/Scripts/python.exe") if p.is_file()), None)
        return ([str(py), "-m", forge["module"]], d) if py else None
    return (list(forge["cli_command"]), d) if forge.get("cli_command") else None


def _other(cmd: tuple[list[str], Path], *args) -> subprocess.CompletedProcess:
    env = {**os.environ, "RV_NO_TIMESTAMP": "1"}
    return subprocess.run([*cmd[0], *map(str, args)], cwd=cmd[1], capture_output=True, text=True, encoding="utf-8", env=env, timeout=900)


def test_cross_language_case_verification(tmp_path, sample):
    """A case written by the other profile verifies here (and an analysis run here verifies its registry);
    then the other profile verifies what this one appended. Set RV_CROSS_PROJECT to run it."""
    if CASE_ROLE != "intake":
        pytest.skip("compares two intake reference profiles")
    cmd = _other_profile()
    if cmd is None:
        pytest.skip("set RV_CROSS_PROJECT to the other profile's project folder")
    case = tmp_path / "CASE-X"
    r = _other(cmd, "scan", "-i", sample, "--progress", "none", "--case-dir", case, "--case", "CASE-X")
    assert r.returncode == 0, r.stderr
    assert cli("verify-case", case).returncode == 0
    s = _go(_cfg(case, "analysis", [], case_id=None))
    assert (s.case.tally.verified, s.case.tally.mismatched) == (3, 0)
    r = cli("scan", "-i", sample, "--case-dir", case, "--progress", "none")
    assert r.returncode == 0 and "registered 3 (new 0)" in r.stdout
    r = _other(cmd, "verify-case", case)
    assert r.returncode == 0, r.stdout + r.stderr
    log = case / "case-log.jsonl"
    log.write_text(log.read_text("utf-8").replace('"seq":2', '"seq":7', 1), encoding="utf-8")
    assert _other(cmd, "verify-case", case).returncode == 3

    # Both profiles number the same folder identically (bytewise order of the normalised path).
    ev = tmp_path / "order"
    for f in ("a/x.txt", "a-b/x.txt", "B.txt", "a.txt", "é.txt", "z/w.txt", "a b.txt", "a_b.txt"):
        (ev / f).parent.mkdir(parents=True, exist_ok=True)
        (ev / f).write_text(f, encoding="utf-8")

    def numbering(out: Path) -> list[tuple[str, str]]:
        rows = (next((out / "logs").iterdir()) / "hashes.csv").read_text("utf-8").splitlines()[1:]
        return [tuple(r.split(",", 2)[:2]) for r in rows]

    assert cli("scan", "-r", "--progress", "none", "-i", ev, "-o", tmp_path / "mine").returncode == 0
    r = _other(cmd, "scan", "-r", "--progress", "none", "-i", ev, "-o", tmp_path / "theirs")
    assert r.returncode == 0, r.stderr
    assert numbering(tmp_path / "mine") == numbering(tmp_path / "theirs") and len(numbering(tmp_path / "mine")) == 8
