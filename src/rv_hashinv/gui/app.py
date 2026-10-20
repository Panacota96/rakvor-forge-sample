"""The window (PySide6). Drawing only: rules live in state.py, work runs in the engine on a QThread."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

from PySide6.QtCore import QObject, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .. import __version__
from ..core import run
from ..core.hashing import ALGORITHMS
from .state import LANG_CHOICES, GuiState


class Worker(QObject):
    event = Signal(dict)
    done = Signal(object)  # RunSummary or Exception

    def __init__(self, cfg, cancel: threading.Event):
        super().__init__()
        self.cfg, self.cancel = cfg, cancel

    def work(self) -> None:
        try:
            self.done.emit(run(self.cfg, self.event.emit, self.cancel))
        except Exception as e:  # noqa: BLE001 - shown to the user, already in the audit log when a run existed
            self.done.emit(e)


class MainWindow(QMainWindow):
    def __init__(self, initial_inputs: list[str] | None = None):
        super().__init__()
        self.state = GuiState()
        self.cancel = threading.Event()
        self.thread: QThread | None = None
        self.started_at: float | None = None
        self.setWindowTitle("RV HashInv — Rakvor")
        self.resize(860, 720)
        self.setAcceptDrops(True)
        self._build()
        for p in initial_inputs or []:
            self.state.add_input(p)
        self.timer = QTimer(self, interval=200, timeout=self._refresh)  # keeps the elapsed time moving
        self._refresh()

    # ----- layout -----
    def _build(self) -> None:
        root = QWidget()
        v = QVBoxLayout(root)
        header = QLabel(
            f"<b>RAKVOR · RV HashInv</b> &nbsp; v{__version__} &nbsp;&nbsp;"
            "<span style='color:gray'>Every action is written to a tamper-evident audit log.</span>"
        )
        v.addWidget(header)

        ev = QGroupBox("1. Evidence")
        ev_l = QVBoxLayout(ev)
        ev_l.addWidget(
            QLabel("Add one file, several files or whole folders (bulk review). You can also drag them onto this window.")
        )
        row = QHBoxLayout()
        self.btn_files = QPushButton("Add files…", clicked=self._add_files)
        self.btn_folder = QPushButton("Add folder…", clicked=self._add_folder)
        self.path_edit = QLineEdit(placeholderText="…or type / paste a path and press Enter")
        self.path_edit.returnPressed.connect(self._add_typed)
        self.btn_remove = QPushButton("Remove selected", clicked=self._remove)
        for w in (self.btn_files, self.btn_folder, self.path_edit, self.btn_remove):
            row.addWidget(w)
        ev_l.addLayout(row)
        self.list = QListWidget()
        self.list.setMaximumHeight(110)
        ev_l.addWidget(self.list)
        self.chk_recursive = QCheckBox("Include subfolders", checked=True)
        self.chk_recursive.toggled.connect(lambda v: (self.state.set_recursive(v), self._refresh()))
        ev_l.addWidget(self.chk_recursive)
        v.addWidget(ev)

        hg = QGroupBox("2. Hash algorithms (choose 1 or 2)")
        h_l = QHBoxLayout(hg)
        self.algo_boxes: dict[str, QCheckBox] = {}
        for a in ALGORITHMS:
            cb = QCheckBox(a, checked=a in self.state.selected)
            cb.clicked.connect(lambda _checked, a=a: self._toggle(a))
            self.algo_boxes[a] = cb
            h_l.addWidget(cb)
        v.addWidget(hg)

        rg = QGroupBox("3. Reports")
        form = QFormLayout(rg)
        self.lang = QComboBox()
        for key, label in LANG_CHOICES:
            self.lang.addItem(label, key)
        self.lang.currentIndexChanged.connect(lambda _i: (self.state.set_lang(self.lang.currentData()), self._refresh()))
        out_row = QHBoxLayout()
        self.out_edit = QLineEdit(self.state.out_dir)
        self.out_edit.textChanged.connect(lambda t: (setattr(self.state, "out_dir", t), self._refresh()))
        out_row.addWidget(self.out_edit)
        out_row.addWidget(QPushButton("Browse…", clicked=self._browse_out))
        self.actor_edit = QLineEdit(self.state.actor)
        self.actor_edit.textChanged.connect(lambda t: setattr(self.state, "actor", t))
        self.case_edit = QLineEdit(placeholderText="optional, e.g. CASE-2026-014")
        self.case_edit.textChanged.connect(lambda t: setattr(self.state, "case_id", t))
        form.addRow("Report language", self.lang)
        form.addRow("Output folder", out_row)
        form.addRow("Examiner", self.actor_edit)
        form.addRow("Case ID", self.case_edit)
        v.addWidget(rg)

        run_row = QHBoxLayout()
        self.btn_start = QPushButton("Start review", clicked=self._start)
        self.btn_cancel = QPushButton("Cancel", clicked=self._cancel)
        run_row.addWidget(self.btn_start)
        run_row.addWidget(self.btn_cancel)
        run_row.addStretch(1)
        v.addLayout(run_row)
        self.bar = QProgressBar(maximum=1000)
        self.bar.setTextVisible(True)
        v.addWidget(self.bar)
        self.timing = QLabel()
        self.current = QLabel(styleSheet="color: gray")
        self.result = QLabel(wordWrap=True)
        v.addWidget(self.timing)
        v.addWidget(self.current)
        v.addWidget(self.result)
        open_row = QHBoxLayout()
        self.btn_report = QPushButton("Open report", clicked=lambda: self._open(self.state.outcome.report))
        self.btn_logs = QPushButton("Open log folder", clicked=lambda: self._open(self.state.outcome.log_dir))
        open_row.addWidget(self.btn_report)
        open_row.addWidget(self.btn_logs)
        open_row.addStretch(1)
        v.addLayout(open_row)
        self.warn_list = QListWidget()
        self.warn_list.setMaximumHeight(90)
        v.addWidget(self.warn_list)
        v.addStretch(1)
        self.setCentralWidget(root)

    # ----- actions -----
    def _add_files(self) -> None:
        for f in QFileDialog.getOpenFileNames(self, "Add evidence files")[0]:
            self.state.add_input(f)
        self._refresh()

    def _add_folder(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Add evidence folder")
        if d:
            self.state.add_input(d)
        self._refresh()

    def _add_typed(self) -> None:
        if self.path_edit.text().strip():
            self.state.add_input(self.path_edit.text())
            self.path_edit.clear()
        self._refresh()

    def _remove(self) -> None:
        for item in sorted(self.list.selectedIndexes(), key=lambda i: -i.row()):
            self.state.remove_input(item.row())
        self._refresh()

    def _browse_out(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Output folder")
        if d:
            self.out_edit.setText(d)

    def _toggle(self, algo: str) -> None:
        try:
            self.state.toggle_algo(algo)
        except ValueError as e:
            self.statusBar().showMessage(str(e), 4000)
        self._refresh()

    def dragEnterEvent(self, e) -> None:  # noqa: N802 - Qt naming
        if e.mimeData().hasUrls() and not self.state.running:
            e.acceptProposedAction()

    def dropEvent(self, e) -> None:  # noqa: N802
        for url in e.mimeData().urls():
            if url.isLocalFile():
                self.state.add_input(url.toLocalFile())
        self._refresh()

    def _start(self) -> None:
        try:
            cfg = self.state.to_config()
        except ValueError as e:
            QMessageBox.warning(self, "Cannot start", str(e))
            return
        self.state.start()
        self.cancel.clear()
        self.started_at = time.monotonic()
        self.thread = QThread(self)
        self.worker = Worker(cfg, self.cancel)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.work)
        self.worker.event.connect(self._on_event)
        self.worker.done.connect(self._on_done)
        self.thread.start()
        self.timer.start()
        self._refresh()

    def _cancel(self) -> None:
        self.cancel.set()
        self.statusBar().showMessage("Cancelling: finishing the current file, then writing partial reports…")

    def _on_event(self, e: dict) -> None:
        self.state.apply(e)
        self._refresh()

    def _on_done(self, result) -> None:
        if isinstance(result, Exception):
            self.state.fail(str(result))
        self.timer.stop()
        self.started_at = None
        self.thread.quit()
        self.thread.wait()
        self.thread = None
        self._refresh()

    def _open(self, path: Path) -> None:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    # ----- render state -----
    def _refresh(self) -> None:
        s = self.state
        idle = not s.running
        if self.list.count() != len(s.inputs) or any(self.list.item(i).text() != str(p) for i, p in enumerate(s.inputs)):
            self.list.clear()
            self.list.addItems([str(p) for p in s.inputs])
        for w in (
            self.btn_files,
            self.btn_folder,
            self.path_edit,
            self.btn_remove,
            self.chk_recursive,
            self.lang,
            self.out_edit,
            self.actor_edit,
            self.case_edit,
        ):
            w.setEnabled(idle)
        for a, cb in self.algo_boxes.items():
            cb.setChecked(a in s.selected)
            cb.setEnabled(idle and s.can_toggle(a))
        self.btn_start.setEnabled(s.can_start())
        self.btn_cancel.setEnabled(s.running)
        self.bar.setValue(int(s.fraction() * 1000))
        self.bar.setFormat(s.progress_text())
        live = int((time.monotonic() - self.started_at) * 1000) if self.started_at else None
        self.timing.setText(s.timing_text(live))
        self.current.setText(f"Now: {s.current_item}" if s.current_item else "")
        if s.phase == "failed":
            self.result.setText(f"<span style='color:#B42318'>The review failed: {s.error}</span>")
        elif s.outcome:
            o = s.outcome
            title = "Cancelled — partial results" if s.phase == "cancelled" else "Done"
            self.result.setText(
                f"<b>{title}</b><br>{o.items} files · {o.errors} errors · findings: {o.high} high, "
                f"{o.medium} medium, {o.low} low, {o.info} info"
            )
        else:
            self.result.setText("")
        self.btn_report.setVisible(s.outcome is not None)
        self.btn_logs.setVisible(s.outcome is not None)
        self.warn_list.setVisible(bool(s.warnings))
        if self.warn_list.count() != len(s.warnings):
            self.warn_list.clear()
            self.warn_list.addItems(s.warnings)


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("RV HashInv")
    # Files or folders dropped on the executable's icon (or passed as arguments) are pre-loaded.
    w = MainWindow([a for a in sys.argv[1:] if not a.startswith("-")])
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
