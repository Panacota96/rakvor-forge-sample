"""Drives the real PySide6 window offscreen: add evidence, pick 2 hashes, run, check result."""

import os

import pytest

pytest.importorskip("PySide6", reason="install the [gui] extra to run window tests")

from PySide6.QtCore import QCoreApplication, QEventLoop, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from rv_hashinv.gui.app import MainWindow  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


def wait_until(predicate, timeout_ms=20000):
    loop = QEventLoop()
    timer = QTimer(interval=50)
    timer.timeout.connect(lambda: loop.quit() if predicate() else None)
    QTimer.singleShot(timeout_ms, loop.quit)
    timer.start()
    loop.exec()
    timer.stop()
    return predicate()


def test_window_runs_a_review(qapp, tmp_path, sample):
    w = MainWindow([str(sample)])
    w.show()
    assert w.list.count() == 1
    w.algo_boxes["blake3"].click()
    assert not w.algo_boxes["md5"].isEnabled(), "third algorithm must be disabled"
    w.lang.setCurrentIndex(1)  # report language: Español
    w.ui_lang.setCurrentIndex(2)  # interface language: Français
    assert w.btn_start.text() == "Lancer l'analyse" and w.ev_box.title().startswith("1. Éléments")
    w.ui_lang.setCurrentIndex(1)  # Español
    assert w.btn_start.text() == "Iniciar revisión"
    w.chk_ts.setChecked(False)  # tests run offline: no timestamp
    w.out_edit.setText(str(tmp_path / "out"))
    assert w.btn_start.isEnabled()
    w.btn_start.click()
    assert wait_until(lambda: w.state.phase in ("finished", "failed"))
    assert w.state.phase == "finished", w.state.error
    assert w.state.outcome.items == 3 and w.btn_report.isVisible()
    assert w.state.outcome.report.name == "statistics.es.html" and w.state.outcome.report.is_file()
    log = (w.state.outcome.log_dir / "audit.jsonl").read_text("utf-8")
    assert '"ui_interface_language_changed"' in log and '"ui_timestamp_changed"' in log
    if os.environ.get("RV_SCREENSHOT"):
        w.grab().save(os.environ["RV_SCREENSHOT"])
    w.close()
    QCoreApplication.processEvents()
