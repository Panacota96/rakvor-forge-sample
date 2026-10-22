"""End-to-end tests of the CLI: the contract every Rakvor CLI must meet."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def cli(*args, **kw) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run([sys.executable, "-m", "rv_hashinv", *map(str, args)], capture_output=True, text=True, encoding="utf-8", env=env, **kw)


def only_dir(p: Path) -> Path:
    return next(p.iterdir())


def test_help_has_every_required_section():
    text = cli("scan", "--help").stdout
    for section in ("DESCRIPTION:", "Options:", "EXAMPLES:", "EXIT CODES:", "FILES WRITTEN:", "FORENSIC NOTES:"):
        assert section in text, section
    for flag in ("--input", "--input-list", "--recursive", "--hash", "--out", "--lang", "--actor", "--case", "--progress"):
        assert flag in text, flag
    assert text.count("Default:") >= 9 and text.count("Example:") >= 9


def test_usage_errors():
    assert cli("scan", "-i", ".", "--hash", "md5,sha1,sha256").returncode == 2
    assert cli("scan", "-i", ".", "--lang", "de").returncode == 2
    assert cli("scan", "-i", ".", "--hash", "crc32").returncode == 2


def test_missing_input_is_runtime_error_and_audited(tmp_path):
    assert cli("scan", "-i", "does-not-exist", "-o", tmp_path, "--progress", "none").returncode == 1
    assert '"run_failed"' in (only_dir(tmp_path / "logs") / "audit.jsonl").read_text("utf-8")


def test_bulk_scan_and_verify(tmp_path, sample):
    r = cli(
        "scan",
        "-i",
        sample,
        "--hash",
        "sha256,blake3",
        "--lang",
        "all",
        "--case",
        "T-1",
        "--actor",
        "ci",
        "--progress",
        "none",
        "-o",
        tmp_path,
    )
    assert r.returncode == 0, r.stderr
    assert "items: 3" in r.stdout
    logs, reports = only_dir(tmp_path / "logs"), only_dir(tmp_path / "reports")
    for f in ("audit.jsonl", "audit.log", "hashes.csv", "environment.json"):
        assert (logs / f).is_file()
    for lang in ("en", "es", "fr"):
        assert (reports / f"statistics.{lang}.html").is_file() and (reports / f"statistics.{lang}.pdf").is_file()
    items = list((reports / "items").iterdir())
    assert len(items) == 3
    r = cli("verify-log", logs)
    assert r.returncode == 0 and "truncation not detectable without a timestamp or case record" in r.stdout
    # The standalone verifier: intact run, then a run folder without hashes.csv (reported, chain still checked).
    oracle = [sys.executable, str(ROOT / "tests" / "verify_chain.py"), str(logs)]
    r = subprocess.run(oracle, capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0 and "chain: intact | register: matches" in r.stdout
    (logs / "hashes.csv").unlink()
    r = subprocess.run(oracle, capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 3 and "chain: intact | register: MISSING" in r.stdout and "Traceback" not in r.stderr
    p = logs / "audit.jsonl"
    p.write_text(p.read_text("utf-8").replace('"actor":"ci"', '"actor":"mallory"', 1), encoding="utf-8")
    r = cli("verify-log", p)
    assert r.returncode == 3 and "BROKEN" in r.stdout


def test_jsonl_progress(tmp_path, sample):
    r = cli("scan", "-i", sample, "--progress", "jsonl", "-o", tmp_path)
    events = [json.loads(line) for line in r.stdout.splitlines()]
    assert events[0]["event"] == "run_started" and events[-1]["event"] == "run_finished"
    elapsed = [e["elapsed_ms"] for e in events if e["event"] == "progress"]
    assert elapsed and elapsed == sorted(elapsed)


def test_evidence_untouched(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"evidence")
    before = f.stat().st_mtime_ns
    assert cli("scan", "-i", f, "--progress", "none", "-o", tmp_path / "out").returncode == 0
    assert f.read_bytes() == b"evidence" and f.stat().st_mtime_ns == before


def test_executable_under_other_name_exits_3(tmp_path):
    (tmp_path / "invoice.pdf").write_bytes(b"MZ\x90\x00\x03\x00\x00\x00")
    assert cli("scan", "-i", tmp_path / "invoice.pdf", "--progress", "none", "-o", tmp_path / "out").returncode == 3


def test_timestamp_of_a_missing_log_exits_3(tmp_path):
    r = cli("timestamp", tmp_path)
    assert r.returncode == 3 and "no audit log at" in r.stderr and "Traceback" not in r.stderr
    r = cli("timestamp", tmp_path / "missing")
    assert r.returncode == 3 and "Traceback" not in r.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell script (run.ps1 is checked by the Windows CI jobs)")
def test_sample_script_compares_the_hash_register(tmp_path):
    """examples/sample/run.sh compares the tool's hashes.csv with expected_hashes.csv and fails on a difference."""
    exe = tmp_path / "rv-hashinv"
    exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" -m rv_hashinv "$@"\n')
    exe.chmod(0o755)
    env = {**os.environ, "RV_NO_TIMESTAMP": "1", "RV_SAMPLE_OUT": str(tmp_path / "out")}
    r = subprocess.run(["sh", str(ROOT / "examples" / "sample" / "run.sh"), str(exe)], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "hashes.csv matches expected_hashes.csv (3 files" in r.stdout


def test_self_test():
    r = cli("self-test")
    assert r.returncode == 0 and "FAIL" not in r.stdout


def test_usage_doc_matches_help():
    doc = ROOT / "docs" / "usage-cli.md"
    generated = cli("docs-cli").stdout
    assert doc.read_text(encoding="utf-8") == generated, "run: rv-hashinv docs-cli > docs/usage-cli.md"


def test_release_python_is_pinned_consistently():
    """The release build and its CI rehearsal (freeze-smoke) use the same pinned Python patch version."""
    import re

    pins = {}
    for wf in ("ci.yml", "release.yml"):
        text = (ROOT / ".github" / "workflows" / wf).read_text("utf-8")
        m = re.search(r'^\s*RELEASE_PYTHON:\s*"(\d+\.\d+\.\d+)"', text, re.M)
        assert m, f"{wf}: RELEASE_PYTHON must be a full x.y.z version"
        pins[wf] = m.group(1)
        assert 'python-version: "3.13"' not in text
    assert pins["ci.yml"] == pins["release.yml"], pins
    rel = (ROOT / ".github" / "workflows" / "release.yml").read_text("utf-8")
    assert "python-version: ${{ env.RELEASE_PYTHON }}" in rel
