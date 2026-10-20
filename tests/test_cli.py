"""End-to-end tests of the CLI: the contract every Rakvor CLI must meet."""

import json
import os
import subprocess
import sys
from pathlib import Path

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
    assert cli("verify-log", logs).returncode == 0
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


def test_self_test():
    r = cli("self-test")
    assert r.returncode == 0 and "FAIL" not in r.stdout


def test_usage_doc_matches_help():
    doc = ROOT / "docs" / "usage-cli.md"
    generated = cli("docs-cli").stdout
    assert doc.read_text(encoding="utf-8") == generated, "run: rv-hashinv docs-cli > docs/usage-cli.md"
