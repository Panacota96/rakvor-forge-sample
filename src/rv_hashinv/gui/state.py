"""Everything the window shows and every rule it enforces, without any Qt code.
Kept separate from app.py so it can be unit-tested headless (CI has no display).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .. import TOOL_NAME, __version__
from ..core import RunConfig
from ..core.envinfo import os_user
from ..core.hashing import ALGORITHMS, MAX_SELECTED, validate_selection
from ..core.i18n import parse_langs
from ..core.timeutil import human_duration, utc_now

LANG_CHOICES = [("en", "English"), ("es", "Español"), ("fr", "Français"), ("all", "All three (EN + ES + FR)")]


@dataclass
class Progress:
    done: int = 0
    total: int = 0
    bytes_done: int = 0
    bytes_total: int = 0
    elapsed_ms: int = 0
    eta_ms: int | None = None


@dataclass
class Outcome:
    items: int
    errors: int
    high: int
    medium: int
    low: int
    info: int
    report: Path
    log_dir: Path


@dataclass
class GuiState:
    inputs: list[Path] = field(default_factory=list)
    recursive: bool = True
    selected: list[str] = field(default_factory=lambda: ["sha256"])
    lang: str = "en"
    out_dir: str = "rakvor-out"
    actor: str = field(default_factory=os_user)
    case_id: str = ""
    phase: str = "idle"  # idle | running | finished | cancelled | failed
    error: str = ""
    progress: Progress = field(default_factory=Progress)
    current_item: str = ""
    warnings: list[str] = field(default_factory=list)
    outcome: Outcome | None = None
    ui_actions: list[tuple[str, dict]] = field(default_factory=list)

    def _note(self, action: str, details: dict) -> None:
        """Records a user action with the time it happened (audited when the run starts)."""
        self.ui_actions.append((action, {**details, "at_utc": utc_now()}))

    @property
    def running(self) -> bool:
        return self.phase == "running"

    def can_toggle(self, algo: str) -> bool:
        return len(self.selected) > 1 if algo in self.selected else len(self.selected) < MAX_SELECTED

    def toggle_algo(self, algo: str) -> None:
        if algo not in ALGORITHMS:
            raise ValueError(f"unknown algorithm {algo}")
        if not self.can_toggle(algo):
            raise ValueError(
                "At least one hash algorithm is required."
                if algo in self.selected
                else f"At most {MAX_SELECTED} hash algorithms can be selected."
            )
        if algo in self.selected:
            self.selected.remove(algo)
        else:
            self.selected.append(algo)
        self._note("ui_hash_selection_changed", {"algorithms": list(self.selected)})

    def add_input(self, path: Path | str) -> None:
        p = Path(str(path).strip().strip('"'))
        if str(p) and p not in self.inputs:
            self.inputs.append(p)
            self._note("ui_input_added", {"path": str(p)})

    def remove_input(self, index: int) -> None:
        if 0 <= index < len(self.inputs):
            p = self.inputs.pop(index)
            self._note("ui_input_removed", {"path": str(p)})

    def set_lang(self, lang: str) -> None:
        if lang != self.lang:
            self.lang = lang
            self._note("ui_language_changed", {"lang": lang})

    def set_recursive(self, value: bool) -> None:
        if value != self.recursive:
            self.recursive = value
            self._note("ui_recursive_changed", {"recursive": value})

    def can_start(self) -> bool:
        return not self.running and bool(self.inputs) and bool(self.out_dir.strip())

    def to_config(self) -> RunConfig:
        """Builds the run configuration; recorded UI actions become audit preamble entries."""
        if not self.inputs:
            raise ValueError("Add at least one file or folder.")
        validate_selection(self.selected)
        langs = parse_langs(self.lang)
        preamble = list(self.ui_actions) + [
            (
                "ui_start_clicked",
                {
                    "algorithms": list(self.selected),
                    "lang": self.lang,
                    "recursive": self.recursive,
                    "inputs": len(self.inputs),
                    "at_utc": utc_now(),
                },
            )
        ]
        settings = [
            f"{TOOL_NAME} (gui)",
            "inputs=" + ";".join(map(str, self.inputs)),
            "hash=" + ",".join(self.selected),
            f"lang={self.lang}",
            f"recursive={str(self.recursive).lower()}",
            f"out={self.out_dir.strip()}",
        ]
        return RunConfig(
            inputs=list(self.inputs),
            out_dir=Path(self.out_dir.strip()),
            algorithms=list(self.selected),
            langs=langs,
            actor=self.actor.strip() or os_user(),
            case_id=self.case_id.strip() or None,
            recursive=self.recursive,
            frontend="gui",
            preamble=preamble,
            command_line=settings,
            tool_name=TOOL_NAME,
            tool_version=__version__,
        )

    def start(self) -> None:
        self.phase, self.error = "running", ""
        self.progress, self.current_item, self.warnings, self.outcome = Progress(), "", [], None
        self.ui_actions = []  # now part of this run's audit log

    def apply(self, e: dict) -> None:
        kind = e["event"]
        if kind == "run_started":
            self.progress.total, self.progress.bytes_total = e["total_items"], e["total_bytes"]
        elif kind == "item_started":
            self.current_item = e["path"]
        elif kind == "progress":
            self.progress = Progress(e["done"], e["total"], e["bytes_done"], e["bytes_total"], e["elapsed_ms"], e["eta_ms"])
        elif kind == "error":
            self.warnings.append(f"{e.get('path') or '-'}: {e['message']}")
        elif kind == "run_finished":
            self.progress.elapsed_ms, self.progress.eta_ms = e["elapsed_ms"], None
            lang = "en" if self.lang == "all" else self.lang
            self.outcome = Outcome(
                e["items"],
                e["errors"],
                e["high"],
                e["medium"],
                e["low"],
                e["info"],
                Path(e["report_dir"]) / f"statistics.{lang}.html",
                Path(e["log_dir"]),
            )
            self.phase = "cancelled" if e["cancelled"] else "finished"
            self.current_item = ""

    def fail(self, message: str) -> None:
        self.phase, self.error = "failed", message

    def fraction(self) -> float:
        p = self.progress
        if p.bytes_total:
            return min(1.0, p.bytes_done / p.bytes_total)
        if p.total:
            return p.done / p.total
        return 1.0 if self.phase == "finished" else 0.0

    def timing_text(self, live_elapsed_ms: int | None = None) -> str:
        elapsed = max(live_elapsed_ms or 0, self.progress.elapsed_ms)
        eta = human_duration(self.progress.eta_ms) if self.running and self.progress.eta_ms is not None else "—"
        return f"Elapsed: {human_duration(elapsed)}   ·   Remaining (estimate): {eta}"

    def progress_text(self) -> str:
        return f"{self.progress.done} / {self.progress.total} files  ·  {self.fraction() * 100:.0f}%"
