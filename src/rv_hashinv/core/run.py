"""The pipeline both front-ends call: intake -> hash + analyze each item -> duplicates ->
hashes.csv -> per-item reports -> statistics report. Every step is written to the audit log.
"""

from __future__ import annotations

import csv
import io
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import i18n
from .analyzer import Finding, analyze
from .audit import AuditLog
from .envinfo import describe
from .events import Sink, eta_ms, event
from .hashing import hash_bytes, hash_stream, validate_selection
from .inputs import collect
from .report import (
    AuditRef,
    ItemResult,
    RunInfo,
    RunTotals,
    duplicate_groups,
    pretty,
    write_hashed,
    write_item_reports,
    write_statistics,
)
from .timeutil import utc_compact, utc_from_timestamp, utc_now

PROGRESS_EVERY_S = 0.15


@dataclass
class RunConfig:
    inputs: list[Path]
    out_dir: Path
    algorithms: list[str] = field(default_factory=lambda: ["sha256"])
    langs: list[str] = field(default_factory=lambda: ["en"])
    actor: str = "unknown"
    case_id: str | None = None
    input_list: Path | None = None
    recursive: bool = False
    frontend: str = "cli"
    preamble: list[tuple[str, dict]] = field(default_factory=list)  # front-end actions to audit first
    command_line: list[str] = field(default_factory=list)
    tool_name: str = "rv-hashinv"
    tool_version: str = "0.0.0"


@dataclass
class RunSummary:
    run_id: str
    items: int
    bytes: int
    errors: int
    elapsed_ms: int
    high: int
    medium: int
    low: int
    info: int
    cancelled: bool
    report_dir: Path
    log_dir: Path
    audit_head: str


def _new_run_id() -> str:
    seed = f"{time.time_ns()}-{os.getpid()}"
    return f"{utc_compact()}-{hash_bytes(seed.encode(), 'sha256')[:6]}"


def run(cfg: RunConfig, sink: Sink, cancel: threading.Event) -> RunSummary:
    """Runs the whole pipeline. Raises ValueError (bad config / input) or OSError (output not writable)."""
    validate_selection(cfg.algorithms)
    if not cfg.langs:
        raise ValueError("select at least one report language")
    for lang in cfg.langs:
        i18n.parse_langs(lang)
    started = time.monotonic()
    started_utc = utc_now()
    run_id = _new_run_id()
    log_dir = Path(cfg.out_dir) / "logs" / run_id
    report_dir = Path(cfg.out_dir) / "reports" / run_id
    log = AuditLog(log_dir, run_id, cfg.actor)

    def elapsed() -> int:
        return int((time.monotonic() - started) * 1000)

    try:
        log.record(
            "run_started",
            None,
            {
                "tool": cfg.tool_name,
                "version": cfg.tool_version,
                "frontend": cfg.frontend,
                "algorithms": cfg.algorithms,
                "langs": cfg.langs,
                "case_id": cfg.case_id,
                "inputs": [str(p) for p in cfg.inputs],
                "input_list": str(cfg.input_list) if cfg.input_list else None,
                "recursive": cfg.recursive,
                "out_dir": str(cfg.out_dir),
            },
        )
        for action, details in cfg.preamble:
            log.record(action, None, details)
        _, env_digest = write_hashed(
            log_dir,
            "environment.json",
            pretty(describe(cfg.tool_name, cfg.tool_version, cfg.frontend, cfg.command_line)),
            cfg.algorithms,
        )
        log.record("environment_recorded", "environment.json", env_digest)

        try:
            items = collect([Path(p) for p in cfg.inputs], cfg.input_list, cfg.recursive)
        except ValueError as e:
            log.record("error", None, {"stage": "input", "message": str(e)})
            log.record("run_failed", None, {"reason": str(e)})
            raise
        total_items, total_bytes = len(items), sum(i.size for i in items)
        log.record("inputs_resolved", None, {"items": total_items, "bytes": total_bytes})
        sink(
            event(
                "run_started",
                run_id=run_id,
                tool=cfg.tool_name,
                version=cfg.tool_version,
                frontend=cfg.frontend,
                algorithms=cfg.algorithms,
                langs=cfg.langs,
                total_items=total_items,
                total_bytes=total_bytes,
            )
        )

        results: list[ItemResult] = []
        bytes_before, errors, cancelled = 0, 0, False
        last_progress = [0.0]
        for item in items:
            if cancel.is_set():
                cancelled = True
                break
            path_s = str(item.path)
            try:
                mtime = item.path.stat().st_mtime_ns
                modified_utc = utc_from_timestamp(mtime / 1e9)
            except OSError:
                mtime, modified_utc = None, None
            sink(event("item_started", index=item.index, path=path_s, size=item.size))
            first = log.record("item_started", path_s, {"index": item.index, "size": item.size, "modified_utc": modified_utc})
            result = ItemResult(item.index, item.path, item.size, modified_utc, audit_first_seq=first, audit_last_seq=first)

            def on_chunk(n: int, _idx=item.index, _before=bytes_before) -> bool:
                now = time.monotonic()
                if now - last_progress[0] >= PROGRESS_EVERY_S:
                    last_progress[0] = now
                    e = elapsed()
                    sink(
                        event(
                            "progress",
                            done=_idx - 1,
                            total=total_items,
                            bytes_done=_before + n,
                            bytes_total=total_bytes,
                            elapsed_ms=e,
                            eta_ms=eta_ms(e, _before + n, total_bytes),
                        )
                    )
                return not cancel.is_set()

            try:
                with open(item.path, "rb") as fh:  # read-only: evidence is never opened for writing
                    outcome = hash_stream(fh, cfg.algorithms, on_chunk)
            except OSError as e:
                outcome = e
            if outcome is None:
                log.record("item_cancelled", path_s, {"index": item.index})
                cancelled = True
                break
            if isinstance(outcome, OSError):
                errors += 1
                msg = outcome.strerror or str(outcome)
                result.error = msg
                result.findings.append(Finding("UNREADABLE", "high", {"error": msg}))
                sink(event("error", path=path_s, message=msg))
                log.record("item_error", path_s, {"index": item.index, "message": msg})
            else:
                try:
                    unchanged = item.path.stat().st_mtime_ns == mtime
                except OSError:
                    unchanged = False
                hashes = dict(sorted(outcome.digests))
                log.record(
                    "item_hashed",
                    path_s,
                    {"index": item.index, "bytes_read": outcome.bytes, "hashes": hashes, "mtime_unchanged": unchanged},
                )
                sink(event("item_hashed", index=item.index, path=path_s, hashes=hashes))
                a = analyze(result.file_name, outcome.bytes, outcome.head)
                result.size, result.hashes = outcome.bytes, outcome.digests
                result.detected_type, result.extension, result.findings = a.detected_type, a.extension, a.findings
            result.audit_last_seq = log.record(
                "item_analyzed",
                path_s,
                {
                    "index": item.index,
                    "detected_type": result.detected_type,
                    "extension": result.extension,
                    "findings": [f.to_json() for f in result.findings],
                    "status": result.status,
                },
            )
            sink(
                event(
                    "item_finished",
                    index=item.index,
                    path=path_s,
                    status=result.status,
                    findings=[f.code for f in result.findings],
                )
            )
            bytes_before += item.size
            e = elapsed()
            sink(
                event(
                    "progress",
                    done=item.index,
                    total=total_items,
                    bytes_done=bytes_before,
                    bytes_total=total_bytes,
                    elapsed_ms=e,
                    eta_ms=eta_ms(e, bytes_before, total_bytes),
                )
            )
            results.append(result)

        if cancelled:
            log.record("run_cancelled", None, {"processed": len(results), "of": total_items, "frontend": cfg.frontend})
            sink(event("cancelled", done=len(results), elapsed_ms=elapsed()))

        primary = cfg.algorithms[0]
        for digest, idx in duplicate_groups(results):
            names = [results[i].file_name for i in idx]
            log.record("duplicate_group", None, {"algorithm": primary, "hash": digest, "items": [results[i].index for i in idx]})
            for pos, i in enumerate(idx):
                others = ", ".join(n for j, n in enumerate(names) if j != pos)
                results[i].findings.append(
                    Finding("DUPLICATE", "info", {"algorithm": primary, "count": str(len(idx)), "others": others})
                )

        buf = io.StringIO(newline="")
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(["index", "path", "size", *cfg.algorithms, "status", "error"])
        for r in results:
            d = dict(r.hashes)
            w.writerow([r.index, str(r.path), r.size, *[d.get(a, "") for a in cfg.algorithms], r.status, r.error or ""])
        _, csv_digest = write_hashed(log_dir, "hashes.csv", buf.getvalue().encode("utf-8"), cfg.algorithms)
        log.record("hash_register_written", "hashes.csv", csv_digest)

        info = RunInfo(
            cfg.tool_name,
            cfg.tool_version,
            run_id,
            cfg.case_id,
            cfg.actor,
            cfg.frontend,
            list(cfg.algorithms),
            list(cfg.langs),
            started_utc,
            utc_now(),
            elapsed(),
            cancelled,
        )
        for r in results:
            files = write_item_reports(report_dir / "items" / r.folder, info, r, AuditRef(log.head, log.seq, str(log_dir)))
            log.record("item_reports_written", str(r.path), {"folder": f"items/{r.folder}", "files": files})
        if results:
            sink(event("report_written", kind="items", path=str(report_dir / "items")))
        totals = RunTotals(len(results), sum(r.size for r in results), errors)
        files = write_statistics(report_dir, info, results, totals, AuditRef(log.head, log.seq, str(log_dir)))
        log.record("statistics_report_written", None, {"files": files})
        sink(event("report_written", kind="statistics", path=str(report_dir / f"statistics.{cfg.langs[0]}.html")))

        sev: dict[str, Any] = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for f in (f for r in results for f in r.findings):
            sev[f.severity] += 1
        done_ms = elapsed()
        log.record(
            "run_finished",
            None,
            {
                "items": totals.items,
                "bytes": totals.bytes,
                "errors": errors,
                "elapsed_ms": done_ms,
                **sev,
                "cancelled": cancelled,
            },
        )
        sink(
            event(
                "run_finished",
                items=totals.items,
                bytes=totals.bytes,
                errors=errors,
                elapsed_ms=done_ms,
                **sev,
                report_dir=str(report_dir),
                log_dir=str(log_dir),
                cancelled=cancelled,
            )
        )
        return RunSummary(
            run_id,
            totals.items,
            totals.bytes,
            errors,
            done_ms,
            sev["high"],
            sev["medium"],
            sev["low"],
            sev["info"],
            cancelled,
            report_dir,
            log_dir,
            log.head,
        )
    finally:
        log.close()
