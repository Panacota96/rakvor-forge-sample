"""Cross-profile check without the other repository: a case folder written by the other profile of this tool
(tests/golden/case-by-<profile>.zip, made by tests/golden/regenerate.py) verifies with this profile's
verify-case and verify-log, and tampering with it is still detected."""

import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

GOLDEN = Path(__file__).resolve().parent / "golden"
ARCHIVES = sorted(GOLDEN.glob("case-by-*.zip"))


def cli(*args) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run([sys.executable, "-m", "rv_hashinv", *map(str, args)], capture_output=True, text=True, encoding="utf-8", env=env)


@pytest.mark.parametrize("archive", ARCHIVES, ids=lambda p: p.stem)
def test_golden_case_from_the_other_profile_verifies(tmp_path, archive):
    with zipfile.ZipFile(archive) as z:
        z.extractall(tmp_path)
    case = tmp_path / "CASE-GOLDEN"
    r = cli("verify-case", case)
    assert r.returncode == 0 and "3 registered items, 1 runs verified" in r.stdout, r.stdout + r.stderr
    logs = next(case.glob("runs/*/*/logs"))
    r = cli("verify-log", logs)
    assert r.returncode == 0 and "covers entry #" in r.stdout, r.stdout
    assert re.search(r"truncation: the final entry #\d+ is anchored by the case log \(run_finished\)", r.stdout), r.stdout
    audit = logs / "audit.jsonl"
    full = audit.read_bytes()
    audit.write_bytes(b"".join(full.splitlines(keepends=True)[:-1]))
    r = cli("verify-log", logs)
    assert r.returncode == 3 and "truncated: the case log records" in r.stdout
    assert cli("verify-case", case).returncode == 3
    audit.write_bytes(full)
    reg = case / "evidence" / "registry.json"
    reg.write_bytes(reg.read_bytes().replace(b'"size": ', b'"size": 1', 1))
    r = cli("verify-case", case)
    assert r.returncode == 3 and "registry.json" in r.stdout
