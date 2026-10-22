"""The window (PySide6). Drawing only: rules live in state.py, work runs in the engine on a QThread.

Rakvor dark theme; interface language ES/EN/FR switchable at any time (texts from i18n "ui").
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

from PySide6.QtCore import QObject, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QIcon
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
from .state import GuiState

# Rakvor palette
NIGHT, NIGHT2, BLUE, INDIGO, VIOLET, CYAN, MIST = "#0D1117", "#1A1F26", "#2A5CFF", "#4D23FF", "#6B00FF", "#00E5FF", "#E6E6E6"
STYLE = f"""
QWidget {{ background: {NIGHT}; color: {MIST}; font-size: 10pt; }}
QLabel, QCheckBox {{ background: transparent; }}
QGroupBox {{ border: 1px solid #2B3240; border-radius: 8px; margin-top: 14px; padding: 10px; background: {NIGHT2}; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; color: {CYAN}; font-weight: 600; }}
QLineEdit, QComboBox, QListWidget {{ background: {NIGHT}; border: 1px solid #2B3240; border-radius: 6px; padding: 4px; }}
QPushButton {{ background: {NIGHT2}; border: 1px solid {BLUE}; border-radius: 6px; padding: 5px 12px; }}
QPushButton:hover {{ border-color: {CYAN}; }}
QPushButton:disabled, QCheckBox:disabled, QLineEdit:disabled {{ color: #5B6472; border-color: #2B3240; }}
QPushButton#primary {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {BLUE}, stop:1 {VIOLET}); border: none; font-weight: 600; }}
QProgressBar {{ border: 1px solid #2B3240; border-radius: 6px; text-align: center; background: {NIGHT2}; }}
QProgressBar::chunk {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {BLUE}, stop:0.6 {INDIGO}, stop:1 {CYAN}); border-radius: 5px; }}
QLabel#brand {{ font-weight: 800; letter-spacing: 3px; font-size: 13pt; }}
QLabel#descriptor {{ color: {CYAN}; font-size: 8pt; letter-spacing: 1px; }}
QLabel#muted {{ color: #9AA4B2; }}
"""
LANGS = [("en", "English"), ("es", "Español"), ("fr", "Français")]


def icon_path() -> Path:
    return Path(__file__).resolve().parent.parent / "resources" / "brand" / "rv-mark.png"


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
    def __init__(self, initial_inputs: list[str] | None = None, ui_lang: str = "en"):
        super().__init__()
        self.state = GuiState()
        self.state.ui_lang = ui_lang if ui_lang in ("en", "es", "fr") else "en"
        self.cancel = threading.Event()
        self.thread: QThread | None = None
        self.started_at: float | None = None
        self.resize(900, 820)
        self.setAcceptDrops(True)
        self.setStyleSheet(STYLE)
        if icon_path().exists():
            self.setWindowIcon(QIcon(str(icon_path())))
        self._build()
        for p in initial_inputs or []:
            self.state.add_input(p)
        self.timer = QTimer(self, interval=200, timeout=self._refresh)  # keeps the elapsed time moving
        self.retranslate()
        self._refresh()

    # ----- layout -----
    def _build(self) -> None:
        root = QWidget()
        v = QVBoxLayout(root)
        top = QHBoxLayout()
        mark = QLabel("RV")
        mark.setStyleSheet(f"border: 2px solid {BLUE}; border-radius: 9px; padding: 4px 8px; font-weight: 800; color: {MIST};")
        top.addWidget(mark)
        words = QVBoxLayout()
        self.brand = QLabel("RAKVOR", objectName="brand")
        self.descriptor = QLabel(objectName="descriptor")
        words.addWidget(self.brand)
        words.addWidget(self.descriptor)
        top.addLayout(words)
        top.addStretch(1)
        self.ui_lang_label = QLabel(objectName="muted")
        self.ui_lang = QComboBox()
        for key, label in LANGS:
            self.ui_lang.addItem(label, key)
        self.ui_lang.setCurrentIndex([k for k, _ in LANGS].index(self.state.ui_lang))
        self.ui_lang.currentIndexChanged.connect(lambda _i: (self.state.set_ui_lang(self.ui_lang.currentData()), self.retranslate()))
        top.addWidget(self.ui_lang_label)
        top.addWidget(self.ui_lang)
        v.addLayout(top)
        self.audit_note = QLabel(objectName="muted")
        v.addWidget(self.audit_note)

        self.ev_box = QGroupBox()
        ev_l = QVBoxLayout(self.ev_box)
        self.ev_help = QLabel(wordWrap=True)
        ev_l.addWidget(self.ev_help)
        row = QHBoxLayout()
        self.btn_files = QPushButton(clicked=self._add_files)
        self.btn_folder = QPushButton(clicked=self._add_folder)
        self.path_edit = QLineEdit()
        self.path_edit.returnPressed.connect(self._add_typed)
        self.btn_remove = QPushButton(clicked=self._remove)
        for w in (self.btn_files, self.btn_folder, self.path_edit, self.btn_remove):
            row.addWidget(w)
        ev_l.addLayout(row)
        self.list = QListWidget()
        self.list.setMaximumHeight(100)
        ev_l.addWidget(self.list)
        self.chk_recursive = QCheckBox(checked=True)
        self.chk_recursive.toggled.connect(lambda v: (self.state.set_recursive(v), self._refresh()))
        ev_l.addWidget(self.chk_recursive)
        case_row = QHBoxLayout()
        self.lbl_case_dir = QLabel()
        self.case_dir_edit = QLineEdit()
        self.case_dir_edit.editingFinished.connect(lambda: (self.state.set_case_dir(self.case_dir_edit.text()), self._refresh()))
        self.btn_case_dir = QPushButton(clicked=self._browse_case)
        for w in (self.lbl_case_dir, self.case_dir_edit, self.btn_case_dir):
            case_row.addWidget(w)
        ev_l.addLayout(case_row)
        v.addWidget(self.ev_box)

        self.hash_box = QGroupBox()
        h_l = QHBoxLayout(self.hash_box)
        self.algo_boxes: dict[str, QCheckBox] = {}
        for a in ALGORITHMS:
            cb = QCheckBox(a, checked=a in self.state.selected)
            cb.clicked.connect(lambda _checked, a=a: self._toggle(a))
            self.algo_boxes[a] = cb
            h_l.addWidget(cb)
        v.addWidget(self.hash_box)

        self.rep_box = QGroupBox()
        form = QFormLayout(self.rep_box)
        self.form = form
        self.lang = QComboBox()
        self.lang.currentIndexChanged.connect(lambda _i: (self.state.set_lang(self.lang.currentData() or "en"), self._refresh()))
        out_row = QHBoxLayout()
        self.out_edit = QLineEdit(self.state.out_dir)
        self.out_edit.textChanged.connect(lambda t: (setattr(self.state, "out_dir", t), self._refresh()))
        self.btn_browse = QPushButton(clicked=self._browse_out)
        out_row.addWidget(self.out_edit)
        out_row.addWidget(self.btn_browse)
        self.actor_edit = QLineEdit(self.state.actor)
        self.actor_edit.textChanged.connect(lambda t: setattr(self.state, "actor", t))
        self.case_edit = QLineEdit()
        self.case_edit.textChanged.connect(lambda t: setattr(self.state, "case_id", t))
        self.lbl_lang, self.lbl_out, self.lbl_actor, self.lbl_case = QLabel(), QLabel(), QLabel(), QLabel()
        form.addRow(self.lbl_lang, self.lang)
        form.addRow(self.lbl_out, out_row)
        form.addRow(self.lbl_actor, self.actor_edit)
        form.addRow(self.lbl_case, self.case_edit)
        v.addWidget(self.rep_box)

        self.trust_box = QGroupBox()
        tf = QFormLayout(self.trust_box)
        self.jur = QComboBox()
        self.jur.currentIndexChanged.connect(lambda _i: self.state.set_jurisdiction(self.jur.currentData() or "co"))
        ts_row = QHBoxLayout()
        self.chk_ts = QCheckBox(checked=self.state.timestamp)
        self.tsa_edit = QLineEdit(self.state.tsa_url)
        self.chk_ts.toggled.connect(lambda on: (self.state.set_timestamp(on, self.tsa_edit.text()), self._refresh()))
        self.tsa_edit.editingFinished.connect(lambda: self.state.set_timestamp(self.chk_ts.isChecked(), self.tsa_edit.text()))
        ts_row.addWidget(self.chk_ts)
        ts_row.addWidget(self.tsa_edit)
        cert_row = QHBoxLayout()
        self.cert_edit = QLineEdit()
        self.cert_edit.editingFinished.connect(lambda: self.state.set_sign_cert(self.cert_edit.text()))
        self.btn_cert = QPushButton(clicked=self._browse_cert)
        cert_row.addWidget(self.cert_edit)
        cert_row.addWidget(self.btn_cert)
        self.pass_edit = QLineEdit(echoMode=QLineEdit.EchoMode.Password)
        self.pass_edit.textChanged.connect(lambda t: setattr(self.state, "sign_password", t))
        self.lbl_jur, self.lbl_ts, self.lbl_cert, self.lbl_pass = QLabel(), QLabel(), QLabel(), QLabel()
        tf.addRow(self.lbl_jur, self.jur)
        tf.addRow(self.lbl_ts, ts_row)
        tf.addRow(self.lbl_cert, cert_row)
        tf.addRow(self.lbl_pass, self.pass_edit)
        v.addWidget(self.trust_box)

        run_row = QHBoxLayout()
        self.btn_start = QPushButton(clicked=self._start, objectName="primary")
        self.btn_cancel = QPushButton(clicked=self._cancel)
        run_row.addWidget(self.btn_start)
        run_row.addWidget(self.btn_cancel)
        run_row.addStretch(1)
        v.addLayout(run_row)
        self.bar = QProgressBar(maximum=1000)
        self.bar.setTextVisible(True)
        v.addWidget(self.bar)
        self.timing = QLabel()
        self.current = QLabel(objectName="muted")
        self.result = QLabel(wordWrap=True)
        self.evidence_list = QListWidget()  # case folder: evidence id per item
        self.evidence_list.setMaximumHeight(110)
        v.addWidget(self.timing)
        v.addWidget(self.current)
        v.addWidget(self.result)
        v.addWidget(self.evidence_list)
        open_row = QHBoxLayout()
        self.btn_report = QPushButton(clicked=lambda: self._open(self.state.outcome.report))
        self.btn_logs = QPushButton(clicked=lambda: self._open(self.state.outcome.log_dir))
        open_row.addWidget(self.btn_report)
        open_row.addWidget(self.btn_logs)
        open_row.addStretch(1)
        v.addLayout(open_row)
        self.warn_list = QListWidget()
        self.warn_list.setMaximumHeight(80)
        v.addWidget(self.warn_list)
        v.addStretch(1)
        self.setCentralWidget(root)

    def retranslate(self) -> None:
        """Applies the interface language to every text (called on start and on every language change)."""
        tr = self.state.tr
        from ..core.i18n import catalog

        self.setWindowTitle(f"RV HashInv — Rakvor v{__version__}")
        self.descriptor.setText(catalog(self.state.ui_lang)["brand"]["descriptor"])
        self.ui_lang_label.setText(tr("ui_lang"))
        self.audit_note.setText(tr("audit_note"))
        self.ev_box.setTitle(tr("evidence"))
        self.ev_help.setText(tr("evidence_help"))
        self.btn_files.setText(tr("add_files"))
        self.btn_folder.setText(tr("add_folder"))
        self.path_edit.setPlaceholderText(tr("path_hint"))
        self.btn_remove.setText(tr("remove"))
        self.chk_recursive.setText(tr("subfolders"))
        self.lbl_case_dir.setText(tr("case_dir"))
        self.case_dir_edit.setPlaceholderText(tr("case_dir_hint"))
        self.btn_case_dir.setText(tr("browse"))
        self.hash_box.setTitle(tr("hashes"))
        self.rep_box.setTitle(tr("reports"))
        self.lbl_lang.setText(tr("report_lang"))
        self.lbl_out.setText(tr("out_dir"))
        self.btn_browse.setText(tr("browse"))
        self.lbl_actor.setText(tr("examiner"))
        self.lbl_case.setText(tr("case"))
        self.case_edit.setPlaceholderText(tr("case_hint"))
        self.trust_box.setTitle(tr("trust"))
        self.lbl_jur.setText(tr("jurisdiction"))
        self.lbl_ts.setText(tr("tsa"))
        self.lbl_cert.setText(tr("sign_cert"))
        self.btn_cert.setText(tr("browse"))
        self.lbl_pass.setText(tr("sign_pass"))
        self.btn_start.setText(tr("start"))
        self.btn_cancel.setText(tr("cancel"))
        self.btn_report.setText(tr("open_report"))
        self.btn_logs.setText(tr("open_logs"))
        # combo boxes: keep the selected key while relabelling
        for combo, items, current in (
            (self.lang, [("en", "English"), ("es", "Español"), ("fr", "Français"), ("all", tr("lang_all"))], self.state.lang),
            (self.jur, [("co", tr("jur_co")), ("fr", tr("jur_fr"))], self.state.jurisdiction),
        ):
            combo.blockSignals(True)
            combo.clear()
            for key, label in items:
                combo.addItem(label, key)
            combo.setCurrentIndex([k for k, _ in items].index(current))
            combo.blockSignals(False)
        self._refresh()

    # ----- actions -----
    def _add_files(self) -> None:
        for f in QFileDialog.getOpenFileNames(self, self.state.tr("add_files"))[0]:
            self.state.add_input(f)
        self._refresh()

    def _add_folder(self) -> None:
        d = QFileDialog.getExistingDirectory(self, self.state.tr("add_folder"))
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
        d = QFileDialog.getExistingDirectory(self, self.state.tr("out_dir"))
        if d:
            self.out_edit.setText(d)

    def _browse_case(self) -> None:
        d = QFileDialog.getExistingDirectory(self, self.state.tr("case_dir"))
        if d:
            self.case_dir_edit.setText(d)
            self.state.set_case_dir(d)
            self._refresh()

    def _browse_cert(self) -> None:
        f, _ = QFileDialog.getOpenFileName(self, self.state.tr("sign_cert"), "", "PKCS#12 (*.p12 *.pfx)")
        if f:
            self.cert_edit.setText(f)
            self.state.set_sign_cert(f)

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
        self.state.set_case_dir(self.case_dir_edit.text())
        self.state.set_sign_cert(self.cert_edit.text())
        self.state.set_timestamp(self.chk_ts.isChecked(), self.tsa_edit.text())
        try:
            cfg = self.state.to_config()
        except ValueError as e:
            QMessageBox.warning(self, self.state.tr("failed"), str(e))
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
        self.statusBar().showMessage(self.state.tr("cancelling"))

    def _on_event(self, e: dict) -> None:
        self.state.apply(e)
        if e["event"] == "timestamp" and e.get("status") != "ok":
            self.state.warnings.append(f"timestamp: {e.get('reason')}")
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
        s, tr = self.state, self.state.tr
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
            self.actor_edit,
            self.case_dir_edit,
            self.btn_case_dir,
            self.case_edit,
            self.jur,
            self.chk_ts,
            self.cert_edit,
            self.btn_cert,
            self.pass_edit,
        ):
            w.setEnabled(idle)
        self.tsa_edit.setEnabled(idle and s.timestamp)
        # Rule (state.py): a case folder decides where the run is written; the output field is locked.
        self.out_edit.setEnabled(idle and not s.out_locked)
        self.btn_browse.setEnabled(idle and not s.out_locked)
        self.out_edit.setToolTip(tr("out_from_case") if s.out_locked else "")
        shown = s.out_dir_display()
        if self.out_edit.text() != shown:
            self.out_edit.blockSignals(True)
            self.out_edit.setText(shown)
            self.out_edit.blockSignals(False)
        for a, cb in self.algo_boxes.items():
            cb.setChecked(a in s.selected)
            cb.setEnabled(idle and s.can_toggle(a))
            cb.setToolTip("" if s.can_toggle(a) else tr("hash_tip_one" if a in s.selected else "hash_tip_two"))
        self.btn_start.setEnabled(s.can_start())
        self.btn_cancel.setEnabled(s.running)
        self.bar.setValue(int(s.fraction() * 1000))
        p = s.progress
        self.bar.setFormat(f"{p.done} / {p.total} {tr('files')}  ·  {s.fraction() * 100:.0f}%")
        live = int((time.monotonic() - self.started_at) * 1000) if self.started_at else None
        text = s.timing_text(live)
        self.timing.setText(text.replace("Elapsed", tr("elapsed")).replace("Remaining (estimate)", tr("remaining")))
        self.current.setText(f"{tr('now')}: {s.current_item}" if s.current_item else "")
        if s.phase == "failed":
            self.result.setText(f"<span style='color:#FF6B6B'>{tr('failed')}: {s.error}</span>")
        elif s.outcome:
            o = s.outcome
            title = tr("cancelled") if s.phase == "cancelled" else tr("done")
            self.result.setText(
                f"<b style='color:{CYAN}'>{title}</b><br>{o.items} {tr('files')} · {o.errors} {tr('errors')} · "
                f"{tr('findings')}: {o.high} / {o.medium} / {o.low} / {o.info}"
            )
        else:
            self.result.setText("")
        lines = s.evidence_lines()
        self.evidence_list.setVisible(bool(lines))
        if [self.evidence_list.item(i).text() for i in range(self.evidence_list.count())] != [f"{tr('evidence_ids')}:", *lines]:
            self.evidence_list.clear()
            if lines:
                self.evidence_list.addItems([f"{tr('evidence_ids')}:", *lines])
        self.btn_report.setVisible(s.outcome is not None)
        self.btn_logs.setVisible(s.outcome is not None)
        self.warn_list.setVisible(bool(s.warnings))
        if self.warn_list.count() != len(s.warnings):
            self.warn_list.clear()
            self.warn_list.addItems(s.warnings)


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("RV HashInv")
    if icon_path().exists():
        app.setWindowIcon(QIcon(str(icon_path())))
    # Files or folders dropped on the executable's icon (or passed as arguments) are pre-loaded.
    w = MainWindow([a for a in sys.argv[1:] if not a.startswith("-")])
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
