import hashlib
import io
import json
import threading
from pathlib import Path

import blake3
import pytest

from rv_hashinv.core import RunConfig, run
from rv_hashinv.core.analyzer import analyze
from rv_hashinv.core.audit import AuditLog, verify
from rv_hashinv.core.hashing import CHUNK, hash_stream, self_test, validate_selection
from rv_hashinv.core.i18n import catalog, parse_langs
from rv_hashinv.core.inputs import collect
from rv_hashinv.core.timeutil import human_duration


def test_known_answers():
    assert self_test() == []


def test_one_read_feeds_two_digests():
    data = bytes(i % 251 for i in range(3 * CHUNK + 17))
    out = hash_stream(io.BytesIO(data), ["sha256", "blake3"])
    assert out.bytes == len(data)
    assert dict(out.digests) == {"sha256": hashlib.sha256(data).hexdigest(), "blake3": blake3.blake3(data).hexdigest()}
    assert len(out.head) == 4096


def test_selection_rules_and_cancel():
    for bad in ([], ["md5", "md5"], ["md5", "sha1", "sha256"], ["crc32"]):
        with pytest.raises(ValueError):
            validate_selection(bad)
    assert hash_stream(io.BytesIO(bytes(4 * CHUNK)), ["sha256"], lambda n: n < 2 * CHUNK) is None


def test_audit_chain_detects_edit_delete_reorder(tmp_path):
    log = AuditLog(tmp_path, "RUN-1", "tester")
    log.record("run_started", None, {"note": "café ñ", "algorithms": ["sha256"]})
    log.record("item_hashed", "a.txt", {"sha256": "00"})
    log.record("run_finished", None, {"items": 1})
    log.close()
    p = tmp_path / "audit.jsonl"
    assert verify(p) == (3, [])
    lines = p.read_text(encoding="utf-8").splitlines()
    for broken in ([lines[0].replace("tester", "mallory"), *lines[1:]], [lines[0], lines[2]], [lines[1], lines[0], lines[2]]):
        p.write_text("\n".join(broken) + "\n", encoding="utf-8")
        assert verify(p)[1]


def test_analyzer():
    assert analyze("report.pdf", 10, b"%PDF-1.7").findings == []
    assert analyze("holiday.jpg", 10, b"%PDF-1.7").findings[0].code == "EXTENSION_MISMATCH"
    f = analyze("invoice.pdf", 10, b"MZ\x90\x00").findings[0]
    assert (f.code, f.severity) == ("EXECUTABLE_CONTENT", "high")
    assert analyze("empty.txt", 0, b"").findings[0].code == "EMPTY_FILE"
    assert analyze("clip.mov", 12, b"\0\0\0\x18ftypqt  ").findings == []


def test_i18n_catalogues_share_keys_and_langs_parse():
    def keys(v, prefix=""):
        return sorted(
            k for key, val in v.items() for k in (keys(val, f"{prefix}.{key}") if isinstance(val, dict) else [f"{prefix}.{key}"])
        )

    assert keys(catalog("en")) == keys(catalog("es")) == keys(catalog("fr"))
    assert parse_langs("all") == ["en", "es", "fr"]
    assert parse_langs("es,fr,es") == ["es", "fr"]
    with pytest.raises(ValueError):
        parse_langs("de")


def test_inputs(tmp_path):
    (tmp_path / "b.txt").write_text("b")
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "c.txt").write_text("c")
    (tmp_path / "list.txt").write_text("# evidence\na.txt\n\nsub/c.txt\n")
    flat = collect([tmp_path])
    assert [i.path.name for i in flat] == ["a.txt", "b.txt", "list.txt"] and flat[0].index == 1 and flat[0].path.is_absolute()
    assert len(collect([tmp_path], recursive=True)) == 4
    assert len(collect([], tmp_path / "list.txt")) == 2
    with pytest.raises(ValueError):
        collect([])


def test_durations():
    assert human_duration(12_300) == "12.3 s"
    assert human_duration(245_000) == "4 min 05 s"
    assert human_duration(3_723_000) == "1 h 02 min 03 s"


def _cfg(inp: Path, out: Path, **kw) -> RunConfig:
    base = dict(
        inputs=[inp],
        out_dir=out,
        algorithms=["sha256", "md5"],
        langs=["es", "en"],
        actor="tester",
        case_id="CASE-1",
        recursive=True,
        frontend="test",
        preamble=[("ui_setting_changed", {"lang": "es"})],
        tool_version="0.0.0",
    )
    base.update(kw)
    return RunConfig(**base)


def test_full_run(tmp_path):
    ev = tmp_path / "ev"
    ev.mkdir()
    (ev / "a.txt").write_text("same")
    (ev / "b.txt").write_text("same")
    (ev / "photo.jpg").write_bytes(b"%PDF-1.7\n...")
    events = []
    s = run(_cfg(ev, tmp_path / "out"), events.append, threading.Event())
    assert (s.items, s.medium, s.info) == (3, 1, 2)
    assert verify(s.log_dir / "audit.jsonl")[1] == []
    for f in ("audit.log", "hashes.csv", "environment.json"):
        assert (s.log_dir / f).is_file()
    item = s.report_dir / "items" / "00003-photo.jpg"
    for f in ("technical.json", "summary.json", "technical.es.html", "summary.en.pdf"):
        assert (item / f).is_file()
    pdf = (item / "technical.en.pdf").read_bytes()
    assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF")
    assert (s.report_dir / "statistics.es.html").read_text("utf-8") != (s.report_dir / "statistics.en.html").read_text("utf-8")
    assert events[0]["event"] == "run_started" and events[-1]["event"] == "run_finished"
    assert (s.log_dir / "hashes.csv").read_text().startswith("index,path,size,sha256,md5,")
    stats = json.loads((s.report_dir / "statistics.json").read_text("utf-8"))
    assert stats["schema"] == "rakvor.statistics/1"


def test_cancel_before_start(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    cancel = threading.Event()
    cancel.set()
    s = run(_cfg(tmp_path / "a.txt", tmp_path / "out"), lambda e: None, cancel)
    assert s.cancelled and s.items == 0
    assert '"run_cancelled"' in (s.log_dir / "audit.jsonl").read_text("utf-8")


def test_three_algorithms_refused(tmp_path):
    with pytest.raises(ValueError):
        run(_cfg(tmp_path, tmp_path, algorithms=["md5", "sha1", "sha256"]), lambda e: None, threading.Event())
