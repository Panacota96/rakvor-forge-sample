"""The pipeline both front-ends call: intake -> hash + analyze each item -> duplicates ->
hashes.csv -> per-item reports -> statistics report. Every step is written to the audit log.

With `case_dir` the run works inside a shared case folder (see case.py): outputs go to
<CASE>/runs/<tool>/<RUN-ID>/, the case log records run_started / run_finished, and depending on the
role every item is registered (intake) or verified against the registry (analysis).
"""

from __future__ import annotations

import csv
import io
import os
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from . import case as casef
from . import i18n
from .analyzer import Finding, analyze
from .audit import AuditLog, heads
from .envinfo import describe
from .events import Sink, eta_ms, event
from .hashing import hash_bytes, hash_stream, validate_selection
from .inputs import collect
from .report import (
    AuditRef,
    CaseInfo,
    CaseTally,
    ItemResult,
    RunInfo,
    RunTotals,
    capped_list,
    duplicate_groups,
    pretty,
    write_hashed,
    write_item_reports,
    write_statistics,
)
from .timeutil import utc_compact, utc_from_timestamp, utc_now
from .trust import PdfSigner, TimestampError, timestamp_head

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
    jurisdiction: str = "co"  # custody form: co (Colombia, Fiscalía) | fr (France, scellés)
    tsa_url: str | None = None  # RFC 3161 time-stamping authority; None = no timestamp
    sign_cert: Path | None = None  # examiner's .p12/.pfx for PDF signatures
    sign_password: str | None = field(default=None, repr=False)  # never logged
    case_dir: Path | None = None  # shared case folder (--case-dir); None = standalone run in out_dir
    evidence_ids: list[str] = field(default_factory=list)  # case only: E0001...; none + no input = every registered item
    case_role: str = field(default_factory=lambda: _default_role())  # "intake" | "analysis" (default: core.CASE_ROLE)


def _default_role() -> str:
    from . import CASE_ROLE

    return CASE_ROLE


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
    timestamp: dict = field(default_factory=lambda: {"status": "off"})
    case: CaseInfo | None = None  # case folder runs: case id, role and how the items relate to the registry


@dataclass
class _CaseLink:
    """A run linked to a case folder."""

    case: casef.Case
    writer: casef.Writer
    run_rel: str  # "runs/<tool>/<RUN-ID>" (relative to the case folder, forward slashes)
    run_dir: Path
    started_seq: int
    started_head: str
    created: bool
    requested_algorithms: list[str]
    algo_change: tuple[str, str | None] | None
    requested_jurisdiction: str
    registry_sha256: str | None
    by_evidence: dict[str, str]  # normalised path -> evidence id, for items selected with --evidence
    tally: CaseTally = field(default_factory=CaseTally)

    def info(self, role: str) -> CaseInfo:
        return CaseInfo(self.case.case_id, role, str(self.case.dir), CaseTally(**vars(self.tally)))


def _open_case(cfg: RunConfig, directory: Path, run_id: str) -> tuple[RunConfig, _CaseLink]:
    """Opens (or creates) the case, resolves --evidence, applies the case rules to the configuration and appends
    run_started to the case log. Nothing is written into a case that fails verification."""
    writer = casef.Writer(cfg.tool_name, cfg.tool_version, run_id, cfg.actor)
    ids = casef.parse_evidence_ids(cfg.evidence_ids)
    case, created = casef.Case.open_or_create(directory, cfg.case_id, cfg.jurisdiction, writer)
    case.check_ids(ids)
    algos, change = casef.ensure_case_algorithm(list(cfg.algorithms), case.registry_algorithms())
    c = replace(cfg, case_id=case.case_id, jurisdiction=case.jurisdiction, algorithms=algos, evidence_ids=ids, inputs=list(cfg.inputs))
    by_evidence: dict[str, str] = {}
    for eid in ids:
        it = case.get(eid)
        c.inputs.append(Path(it["path"]))
        by_evidence[it["path"]] = eid
    if not c.inputs and c.input_list is None:
        c.inputs = [Path(i["path"]) for i in case.items]
    run_rel = f"runs/{cfg.tool_name}/{run_id}"
    started_seq, started_head = case.append(
        writer,
        "run_started",
        {
            "tool": cfg.tool_name,
            "version": cfg.tool_version,
            "run_dir": run_rel,
            "frontend": cfg.frontend,
            "role": cfg.case_role,
            "evidence_ids": ids,
        },
    )
    link = _CaseLink(
        case,
        writer,
        run_rel,
        Path(directory) / "runs" / cfg.tool_name / run_id,
        started_seq,
        started_head,
        created,
        list(cfg.algorithms),
        change,
        cfg.jurisdiction,
        casef.registry_digest(directory),
        by_evidence,
    )
    return c, link


def _finish_case(link: _CaseLink, cfg: RunConfig, log_dir: Path, s: RunSummary | None, error: str | None, sink: Sink) -> None:
    """Appends run_finished to the case log (also after a cancel or a failure). The audit head recorded here is
    the run's final audit entry, read back from disk."""
    try:
        h = heads(log_dir / "audit.jsonl")
    except OSError:
        h = {}
    entries = max(h) if h else 0
    head = h.get(entries)
    verification = dict(vars(link.tally))
    base = {"tool": cfg.tool_name, "version": cfg.tool_version, "run_dir": link.run_rel, "audit_head": head, "audit_entries": entries}
    if s is not None:
        details = {
            **base,
            "status": "cancelled" if s.cancelled else "completed",
            "timestamp_status": s.timestamp.get("status", "off"),
            "totals": {"items": s.items, "bytes": s.bytes, "errors": s.errors, "high": s.high, "medium": s.medium, "low": s.low, "info": s.info},
            "verification": verification,
        }
    else:
        details = {**base, "status": "failed", "reason": error, "timestamp_status": "off", "totals": None, "verification": verification}
    try:
        link.case.append(link.writer, "run_finished", details)
    except casef.CaseError as e:
        sink(event("error", path=None, message=f"case log: run_finished not recorded: {e}"))


def _case_check_item(link: _CaseLink, role: str, result: ItemResult, log: AuditLog, sink: Sink) -> None:
    """Analysis: compares the fresh hashes with the registry (by --evidence id, else by path, else by content).
    Intake: notes a registered path whose content changed. Findings are added to the item."""
    norm = casef.normalize_path(result.path)
    path_s = str(result.path)
    if role == casef.INTAKE:
        prev = link.case.find_by_path(norm)
        if prev is not None and casef.compare(prev["hashes"], result.hashes).kind == "mismatch":
            result.findings.append(Finding("REGISTRY_PATH_CONTENT_CHANGED", "medium", {"previous_id": prev["evidence_id"]}))
        return
    expected, by = None, ""
    if norm in link.by_evidence:
        expected, by = link.case.get(link.by_evidence[norm]), "evidence_id"
    if expected is None:
        expected, by = link.case.find_by_path(norm), "path"
    if expected is None:
        expected, by = link.case.find_by_content(result.hashes), "content"
    if expected is None:
        log.record("evidence_not_in_case_registry", path_s, {"index": result.index, "case_id": link.case.case_id})
        result.findings.append(Finding("EVIDENCE_NOT_IN_CASE_REGISTRY", "medium", {"case_id": link.case.case_id}))
        link.tally.unregistered += 1
        status = "not_in_registry"
    else:
        eid = expected["evidence_id"]
        result.evidence_id, result.intake_utc = eid, expected["registered_utc"]
        cmp = casef.compare(expected["hashes"], result.hashes)
        if cmp.kind == "match":
            log.record(
                "evidence_verified_against_case",
                path_s,
                {"index": result.index, "evidence_id": eid, "algorithm": "+".join(cmp.algorithms), "match": True, "matched_by": by},
            )
            link.tally.verified += 1
            status = "verified"
        else:
            algo, exp, act = (cmp.algorithm, cmp.expected, cmp.actual) if cmp.kind == "mismatch" else ("none", "-", "-")
            log.record(
                "evidence_verified_against_case",
                path_s,
                {
                    "index": result.index,
                    "evidence_id": eid,
                    "algorithm": algo,
                    "match": False,
                    "matched_by": by,
                    "expected": exp,
                    "actual": act,
                },
            )
            result.findings.append(
                Finding("EVIDENCE_HASH_MISMATCH_WITH_CASE", "high", {"evidence_id": eid, "algorithm": algo, "expected": exp, "actual": act})
            )
            link.tally.mismatched += 1
            status = "mismatch"
    result.case_status = status
    sink(event("evidence_linked", index=result.index, path=path_s, evidence_id=result.evidence_id, status=status))


def _register_items(link: _CaseLink, results: list[ItemResult], hashed_seq: dict[int, int], log: AuditLog, sink: Sink) -> None:
    """Intake: registers every hashed item (same path + same content keeps its id) and audits each id."""
    todo = [r for r in results if r.hashes]
    if not todo:
        return
    regs = [casef.Registration(casef.normalize_path(r.path), r.size, list(r.hashes), hashed_seq.get(r.index, 0)) for r in todo]
    try:
        ids, case_seq = link.case.register(link.writer, regs)
    except casef.CaseError as e:
        log.record("error", None, {"stage": "case_registry", "message": str(e)})
        log.record("run_failed", None, {"reason": str(e)})
        raise
    digest = casef.registry_digest(link.case.dir)
    for r, (eid, added, utc) in zip(todo, ids, strict=True):
        status = "registered" if added else "already_registered"
        log.record(
            "evidence_registered",
            str(r.path),
            {"index": r.index, "evidence_id": eid, "new": added, "case_log_seq": case_seq, "registry_sha256": digest},
        )
        link.tally.registered += 1
        link.tally.added += int(added)
        r.evidence_id, r.case_status, r.intake_utc = eid, status, utc
        sink(event("evidence_linked", index=r.index, path=str(r.path), evidence_id=eid, status=status))


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
    if cfg.jurisdiction not in ("co", "fr"):
        raise ValueError(f"unknown jurisdiction '{cfg.jurisdiction}': use co or fr")
    if cfg.case_role not in casef.ROLES:
        raise ValueError(f"unknown case role '{cfg.case_role}': use intake or analysis")
    run_id = _new_run_id()
    if cfg.case_dir is None:
        out = Path(cfg.out_dir)
        return _pipeline(cfg, sink, cancel, run_id, out / "logs" / run_id, out / "reports" / run_id, None)
    cfg, link = _open_case(cfg, Path(cfg.case_dir), run_id)
    log_dir, report_dir = link.run_dir / "logs", link.run_dir / "reports"
    try:
        summary = _pipeline(cfg, sink, cancel, run_id, log_dir, report_dir, link)
    except Exception as e:
        _finish_case(link, cfg, log_dir, None, str(e), sink)
        raise
    _finish_case(link, cfg, log_dir, summary, None, sink)
    return summary


def _pipeline(
    cfg: RunConfig, sink: Sink, cancel: threading.Event, run_id: str, log_dir: Path, report_dir: Path, link: _CaseLink | None
) -> RunSummary:
    started = time.monotonic()
    started_utc = utc_now()
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
                "jurisdiction": cfg.jurisdiction,
                "tsa_url": cfg.tsa_url,
                "sign_cert": str(cfg.sign_cert) if cfg.sign_cert else None,
                "case_dir": str(cfg.case_dir) if cfg.case_dir is not None else None,
                "evidence_ids": list(cfg.evidence_ids),
            },
        )
        if link is not None:
            log.record(
                "case_linked",
                None,
                {
                    "case_id": link.case.case_id,
                    "case_dir": str(link.case.dir),
                    "role": cfg.case_role,
                    "run_dir": link.run_rel,
                    "case_created": link.created,
                    "case_log_seq_at_start": link.started_seq,
                    "case_log_head_at_start": link.started_head,
                    "registry_sha256": link.registry_sha256,
                    "registry_items": len(link.case.items),
                    "jurisdiction": link.case.jurisdiction,
                    "requested_jurisdiction": link.requested_jurisdiction,
                },
            )
            if link.algo_change is not None:
                log.record(
                    "case_algorithm_added",
                    None,
                    {
                        "requested": link.requested_algorithms,
                        "added": link.algo_change[0],
                        "replaced": link.algo_change[1],
                        "algorithms": cfg.algorithms,
                        "registry_algorithms": link.case.registry_algorithms(),
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
        signer = None
        if cfg.sign_cert:
            try:
                signer = PdfSigner.load(Path(cfg.sign_cert), cfg.sign_password)
            except ValueError as e:
                log.record("run_failed", None, {"reason": str(e)})
                raise
            log.record(
                "signing_certificate_loaded",
                str(cfg.sign_cert),
                {"subject": signer.subject, "certificate_sha256": signer.fingerprint_sha256},
            )

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
        hashed_seq: dict[int, int] = {}
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
                hashed_seq[item.index] = log.record(
                    "item_hashed",
                    path_s,
                    {"index": item.index, "bytes_read": outcome.bytes, "hashes": hashes, "mtime_unchanged": unchanged},
                )
                sink(event("item_hashed", index=item.index, path=path_s, hashes=hashes))
                a = analyze(result.file_name, outcome.bytes, outcome.head)
                result.size, result.hashes = outcome.bytes, outcome.digests
                result.detected_type, result.extension, result.findings = a.detected_type, a.extension, a.findings
                if link is not None:
                    _case_check_item(link, cfg.case_role, result, log, sink)
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

        # Intake: register every successfully hashed item in the case registry (under the case lock).
        if link is not None and cfg.case_role == casef.INTAKE:
            _register_items(link, results, hashed_seq, log, sink)

        primary = cfg.algorithms[0]
        for digest, idx in duplicate_groups(results):
            names = [results[i].file_name for i in idx]
            log.record("duplicate_group", None, {"algorithm": primary, "hash": digest, "items": [results[i].index for i in idx]})
            for pos, i in enumerate(idx):
                others = capped_list([n for j, n in enumerate(names) if j != pos], 10)
                results[i].findings.append(Finding("DUPLICATE", "info", {"algorithm": primary, "count": str(len(idx)), "others": others}))

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
            jurisdiction=cfg.jurisdiction,
            signer=signer,
            case=link.info(cfg.case_role) if link is not None else None,
        )
        for r in results:
            files = write_item_reports(report_dir / "items" / r.folder, info, r, AuditRef(log.head, log.seq, str(log_dir)))
            log.record("item_reports_written", str(r.path), {"folder": f"items/{r.folder}", "files": files})
        if results:
            sink(event("report_written", kind="items", path=str(report_dir / "items")))
        totals = RunTotals(len(results), sum(r.size for r in results), errors)
        # Trusted timestamp of the chain head: covers every evidence hash, finding and per-item report digest.
        info.timestamp = {"status": "off"}
        if cfg.tsa_url:
            try:
                ts = timestamp_head(log_dir, log.seq, log.head, cfg.tsa_url)
                log.record("timestamp_obtained", ts.file, ts.to_json())
                info.timestamp = {"status": "ok", **ts.to_json()}
            except TimestampError as e:
                log.record("timestamp_pending", None, {"tsa": cfg.tsa_url, "reason": str(e), "covers_seq": log.seq, "head": log.head})
                info.timestamp = {"status": "pending", "tsa": cfg.tsa_url, "reason": str(e)}
            sink(event("timestamp", **info.timestamp))
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
            info.timestamp,
            info.case,
        )
    finally:
        log.close()
