"""GUI rules, tested without Qt."""

import threading
from pathlib import Path

import pytest

from rv_hashinv.core import run
from rv_hashinv.gui.state import GuiState


def test_at_most_two_at_least_one():
    s = GuiState()
    assert s.selected == ["sha256"] and not s.can_toggle("sha256")
    with pytest.raises(ValueError):
        s.toggle_algo("sha256")
    s.toggle_algo("md5")
    assert not s.can_toggle("blake3")
    with pytest.raises(ValueError):
        s.toggle_algo("blake3")
    s.toggle_algo("sha256")
    assert s.selected == ["md5"]


def test_settings_become_audit_preamble():
    s = GuiState()
    with pytest.raises(ValueError):
        s.to_config()
    s.add_input('"C:\\evidence"')
    s.toggle_algo("blake3")
    s.set_lang("es")
    cfg = s.to_config()
    assert cfg.inputs == [Path("C:\\evidence")] and cfg.frontend == "gui"
    assert [a for a, _ in cfg.preamble] == [
        "ui_input_added",
        "ui_hash_selection_changed",
        "ui_language_changed",
        "ui_start_clicked",
    ]
    assert all("at_utc" in d for _, d in cfg.preamble)
    s.start()
    assert s.ui_actions == []


def test_events_drive_progress():
    s = GuiState()
    s.start()
    s.apply({"event": "run_started", "total_items": 4, "total_bytes": 400})
    s.apply({"event": "progress", "done": 1, "total": 4, "bytes_done": 100, "bytes_total": 400, "elapsed_ms": 2000, "eta_ms": 6000})
    assert s.fraction() == 0.25 and "6.0 s" in s.timing_text(2500) and s.progress_text().startswith("1 / 4")
    s.apply(
        {
            "event": "run_finished",
            "items": 4,
            "errors": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "info": 0,
            "elapsed_ms": 8000,
            "report_dir": "out/reports/R",
            "log_dir": "out/logs/R",
            "cancelled": False,
        }
    )
    assert s.phase == "finished" and s.outcome.report == Path("out/reports/R/statistics.en.html")


def test_real_run_from_gui_settings_is_audited(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    s = GuiState()
    s.add_input(tmp_path / "a.txt")
    s.out_dir = str(tmp_path / "out")
    cfg = s.to_config()
    s.start()
    summary = run(cfg, s.apply, threading.Event())
    assert s.phase == "finished"
    log = (summary.log_dir / "audit.jsonl").read_text("utf-8")
    assert '"ui_input_added"' in log and '"ui_start_clicked"' in log and '"frontend":"gui"' in log
