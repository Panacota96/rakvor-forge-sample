"""Reports: one statistics report per run, and two reports per item (technical + customer summary),
each in JSON (language-neutral, schema-versioned), HTML and PDF (one file per selected language).

HTML and PDF are rendered from the same view model (*_context), so they never disagree.
The JSON layout and the view model are identical to the Rust profile.
"""

from __future__ import annotations

import io
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from jinja2 import Environment, select_autoescape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from . import i18n
from .analyzer import SEVERITY_ORDER, Finding
from .hashing import hash_bytes
from .timeutil import human_duration

SCHEMA_STATISTICS = "rakvor.statistics/1"
SCHEMA_TECHNICAL = "rakvor.item-technical/1"
SCHEMA_SUMMARY = "rakvor.item-summary/1"
LIMITATIONS = [
    "SIGNATURE_TABLE_LIMITED",
    "TIMESTAMPS_FROM_FILESYSTEM",
    "CLEAN_RESULT_IS_NOT_AUTHENTICITY",
    "TIMESTAMP_PROVES_EXISTENCE_ONLY",
]
SCHEMA_CUSTODY = "rakvor.item-custody/1"
JURISDICTIONS = {"co": "es", "fr": "fr"}  # custody form language per country; an English copy is always added
BLANK_TRANSFER_ROWS = 6


@dataclass
class CaseTally:
    """How the run's items relate to the case registry."""

    registered: int = 0  # items that carry an evidence id from intake (new or already registered)
    added: int = 0  # of those, newly added to the registry by this run
    verified: int = 0
    mismatched: int = 0
    unregistered: int = 0


@dataclass
class CaseInfo:
    case_id: str
    role: str  # intake | analysis
    dir: str
    tally: CaseTally = field(default_factory=CaseTally)

    def to_json(self) -> dict:
        return {"case_id": self.case_id, "role": self.role, "case_dir": self.dir, "counts": dict(vars(self.tally))}


@dataclass
class RunInfo:
    tool_name: str
    tool_version: str
    run_id: str
    case_id: str | None
    actor: str
    frontend: str
    algorithms: list[str]
    langs: list[str]
    started_utc: str
    finished_utc: str
    elapsed_ms: int
    cancelled: bool
    jurisdiction: str = "co"
    signer: Any = None  # trust.PdfSigner or None
    timestamp: dict | None = None  # {"status": ok|pending|off, ...}
    case: CaseInfo | None = None  # set when the run works in a shared case folder (--case-dir)

    def custody_langs(self) -> list[str]:
        return list(dict.fromkeys([JURISDICTIONS[self.jurisdiction], "en"]))


@dataclass
class ItemResult:
    index: int
    path: Path
    size: int
    modified_utc: str | None = None
    hashes: list[tuple[str, str]] = field(default_factory=list)
    detected_type: str | None = None
    extension: str | None = None
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    audit_first_seq: int = 0
    audit_last_seq: int = 0
    evidence_id: str | None = None  # case folder only: E0001...
    case_status: str | None = None  # registered | already_registered | verified | mismatch | not_in_registry
    intake_utc: str | None = None

    @property
    def file_name(self) -> str:
        return self.path.name or str(self.path)

    @property
    def status(self) -> str:
        worst = max((SEVERITY_ORDER[f.severity] for f in self.findings), default=0)
        return "problem" if worst == 3 else "attention" if worst >= 1 else "ok"

    @property
    def folder(self) -> str:
        clean = "".join(c if c.isalnum() or c in ".-_" else "_" for c in self.file_name)[:60]
        return f"{self.index:05d}-{clean}"


@dataclass
class AuditRef:
    head: str
    entries: int
    log_dir: str


@dataclass
class RunTotals:
    items: int
    bytes: int
    errors: int


def _resource(path: str) -> str:
    return resources.files("rv_hashinv.resources").joinpath(path).read_text(encoding="utf-8")


_ENV = Environment(autoescape=select_autoescape(["html"]), keep_trailing_newline=True)
_TEMPLATES = {n: _ENV.from_string(_resource(f"templates/{n}")) for n in ("statistics.html", "technical.html", "summary.html", "custody.html")}
_CSS = _resource("templates/report.css")
_LOGO = _resource("templates/rv-mark.svg")


def render_html(template: str, ctx: dict) -> str:
    return _TEMPLATES[template].render(**ctx)


def capped_list(names: list[str], limit: int) -> str:
    """Keeps reports readable at scale: the first `limit` names, then "… (+N)". Full lists stay in hashes.csv/JSON."""
    return ", ".join(names) if len(names) <= limit else ", ".join(names[:limit]) + f", \u2026 (+{len(names) - limit})"


def duplicate_groups(items: list[ItemResult]) -> list[tuple[str, list[int]]]:
    """Groups of identical content by primary hash (hashed, non-empty items), sorted by hash."""
    by: dict[str, list[int]] = {}
    for i, it in enumerate(items):
        if it.hashes and it.size > 0:
            by.setdefault(it.hashes[0][1], []).append(i)
    return sorted((h, v) for h, v in by.items() if len(v) > 1)


def _throughput(nbytes: int, ms: int) -> str:
    if ms == 0:
        return "-"
    per_s = nbytes * 1000 / ms
    return f"{per_s / 1048576:.1f} MiB/s" if per_s >= 1048576 else f"{per_s / 1024:.1f} KiB/s"


def _finding_view(lang: str, f: Finding) -> dict:
    title, shows, dnp = i18n.finding(lang, f.code, f.params)
    return {
        "code": f.code,
        "severity": f.severity,
        "severity_label": i18n.severity(lang, f.severity),
        "title": title,
        "shows": shows,
        "does_not_prove": dnp,
    }


def _base(lang: str, run: RunInfo) -> dict:
    return {
        "lang": lang,
        "t": i18n.catalog(lang)["labels"],
        "css": _CSS,
        "tool": {"name": run.tool_name, "version": run.tool_version},
        "run": {
            "run_id": run.run_id,
            "case_id": run.case_id,
            "actor": run.actor,
            "frontend": run.frontend,
            "started_utc": run.started_utc,
            "finished_utc": run.finished_utc,
            "duration_text": human_duration(run.elapsed_ms),
            "algorithms_text": " + ".join(run.algorithms),
            "cancelled": run.cancelled,
            "lang": lang,
        },
        "limitations": [i18n.limitation(lang, code) for code in LIMITATIONS],
        "brand": i18n.catalog(lang)["brand"],
        "logo_svg": _LOGO,
        "signature": {
            "signed": run.signer is not None,
            "by": getattr(run.signer, "subject", ""),
            "certificate_sha256": getattr(run.signer, "fingerprint_sha256", ""),
        },
        "timestamp": _timestamp_view(lang, run.timestamp),
    }


def _timestamp_view(lang: str, ts: dict | None) -> dict:
    ts = ts or {"status": "off"}
    return {**ts, "status_label": i18n.label(lang, f"timestamp_{ts['status']}")}


def _case_view(run: RunInfo) -> dict | None:
    if run.case is None:
        return None
    return {"case_id": run.case.case_id, "role": run.case.role, "dir": run.case.dir, **vars(run.case.tally)}


def statistics_context(lang: str, run: RunInfo, items: list[ItemResult], totals: RunTotals, audit: AuditRef) -> dict:
    ctx = _base(lang, run)
    sev = Counter(f.severity for it in items for f in it.findings)
    codes = Counter(f.code for it in items for f in it.findings)
    types = Counter(it.detected_type or i18n.label(lang, "unknown") for it in items)
    ctx.update(
        {
            "totals": {
                "items": totals.items,
                "bytes": totals.bytes,
                "errors": totals.errors,
                "throughput_text": _throughput(totals.bytes, run.elapsed_ms),
            },
            "severity_rows": [{"key": s, "label": i18n.severity(lang, s), "count": sev.get(s, 0)} for s in ("high", "medium", "low", "info")],
            "code_rows": [{"code": c, "title": i18n.finding(lang, c, {})[0], "count": n} for c, n in sorted(codes.items())],
            "type_rows": [{"name": n, "count": c} for n, c in sorted(types.items())],
            "duplicate_rows": [
                {"hash": h, "paths": [str(items[i].path) for i in idx[:20]] + ([f"\u2026 (+{len(idx) - 20})"] if len(idx) > 20 else [])}
                for h, idx in duplicate_groups(items)
            ],
            "item_rows": [
                {
                    "index": it.index,
                    "file_name": it.file_name,
                    "size": it.size,
                    "finding_count": len(it.findings),
                    "evidence_id": it.evidence_id,
                    "status": it.status,
                    "status_label": i18n.label(lang, f"status_{it.status}"),
                    "link": f"items/{it.folder}/technical.{lang}.html",
                }
                for it in items
            ],
            "case": _case_view(run),
            "audit": {"head": audit.head, "entries": audit.entries, "log_dir": audit.log_dir},
        }
    )
    return ctx


def item_context(lang: str, run: RunInfo, it: ItemResult, audit: AuditRef) -> dict:
    ctx = _base(lang, run)
    alg, digest = it.hashes[0] if it.hashes else ("-", i18n.label(lang, "none"))
    ctx.update(
        {
            "item": {
                "index": it.index,
                "file_name": it.file_name,
                "path": str(it.path),
                "size": it.size,
                "modified_utc": it.modified_utc or i18n.label(lang, "unknown"),
                "extension_text": f".{it.extension}" if it.extension else i18n.label(lang, "none"),
                "detected_text": it.detected_type or i18n.label(lang, "unknown"),
                "status": it.status,
                "status_label": i18n.label(lang, f"status_{it.status}"),
                "summary_text": i18n.label(lang, f"summary_{it.status}"),
                "next_text": i18n.label(lang, f"next_{it.status}"),
                "primary_algorithm": alg,
                "primary_hash": digest,
                "audit_first_seq": it.audit_first_seq,
                "audit_last_seq": it.audit_last_seq,
                "evidence_id": it.evidence_id,
                "intake_utc": it.intake_utc,
                "case_status": it.case_status,
                "case_status_label": i18n.label(lang, f"case_status_{it.case_status}") if it.case_status else None,
            },
            "case": _case_view(run),
            "hash_rows": [{"algorithm": a, "value": h} for a, h in it.hashes],
            "findings": [_finding_view(lang, f) for f in it.findings],
            "audit": {"head": audit.head, "entries": audit.entries, "log_dir": audit.log_dir},
        }
    )
    return ctx


# ---------- JSON (language-neutral; texts included for each selected language) ----------


def _findings_json(it: ItemResult, langs: list[str]) -> list[dict]:
    out = []
    for f in it.findings:
        texts = {}
        for lang in langs:
            title, shows, dnp = i18n.finding(lang, f.code, f.params)
            texts[lang] = {"title": title, "shows": shows, "does_not_prove": dnp}
        out.append({**f.to_json(), "text": texts})
    return out


def _run_json(run: RunInfo) -> dict:
    return {
        "run_id": run.run_id,
        "case_id": run.case_id,
        "actor": run.actor,
        "frontend": run.frontend,
        "algorithms": run.algorithms,
        "langs": run.langs,
        "started_utc": run.started_utc,
        "finished_utc": run.finished_utc,
        "elapsed_ms": run.elapsed_ms,
        "cancelled": run.cancelled,
        "jurisdiction": run.jurisdiction,
        "pdf_signed_by": getattr(run.signer, "subject", None),
        "pdf_signer_certificate_sha256": getattr(run.signer, "fingerprint_sha256", None),
    }


def statistics_json(run: RunInfo, items: list[ItemResult], totals: RunTotals, audit: AuditRef) -> dict:
    sev = {k: 0 for k in ("high", "info", "low", "medium")}
    sev.update(Counter(f.severity for it in items for f in it.findings))
    return {
        "schema": SCHEMA_STATISTICS,
        "tool": {"name": run.tool_name, "version": run.tool_version},
        "run": _run_json(run),
        "totals": {"items": totals.items, "bytes": totals.bytes, "errors": totals.errors},
        "findings_by_severity": sev,
        "findings_by_code": dict(sorted(Counter(f.code for it in items for f in it.findings).items())),
        "items_by_status": dict(sorted(Counter(it.status for it in items).items())),
        "items_by_type": dict(sorted(Counter(it.detected_type or "unknown" for it in items).items())),
        "duplicate_groups": [{"hash": h, "items": [items[i].index for i in idx]} for h, idx in duplicate_groups(items)],
        "case": run.case.to_json() if run.case else None,
        "items": [
            {
                "index": it.index,
                "evidence_id": it.evidence_id,
                "path": str(it.path),
                "size": it.size,
                "status": it.status,
                "findings": [f.code for f in it.findings],
                "report_folder": f"items/{it.folder}",
            }
            for it in items
        ],
        "limitations": LIMITATIONS,
        "audit": {"head": audit.head, "entries": audit.entries, "log_dir": audit.log_dir},
        "timestamp": run.timestamp or {"status": "off"},
    }


def technical_json(run: RunInfo, it: ItemResult) -> dict:
    return {
        "schema": SCHEMA_TECHNICAL,
        "tool": {"name": run.tool_name, "version": run.tool_version},
        "run": _run_json(run),
        "item": {
            "index": it.index,
            "evidence_id": it.evidence_id,
            "path": str(it.path),
            "file_name": it.file_name,
            "size": it.size,
            "modified_utc": it.modified_utc,
            "extension": it.extension,
            "detected_type": it.detected_type,
            "status": it.status,
            "error": it.error,
        },
        "case": (
            {"case_id": run.case.case_id, "role": run.case.role, "case_dir": run.case.dir, "status": it.case_status, "intake_utc": it.intake_utc}
            if run.case
            else None
        ),
        "hashes": dict(it.hashes),
        "findings": _findings_json(it, run.langs),
        "limitations": LIMITATIONS,
        "audit": {"first_seq": it.audit_first_seq, "last_seq": it.audit_last_seq},
    }


def summary_json(run: RunInfo, it: ItemResult) -> dict:
    return {
        "schema": SCHEMA_SUMMARY,
        "run_id": run.run_id,
        "case_id": run.case_id,
        "item": {"index": it.index, "evidence_id": it.evidence_id, "file_name": it.file_name},
        "status": it.status,
        "fingerprint": {"algorithm": it.hashes[0][0], "value": it.hashes[0][1]} if it.hashes else None,
        "findings": _findings_json(it, run.langs),
        "text": {
            lang: {
                "status": i18n.label(lang, f"status_{it.status}"),
                "summary": i18n.label(lang, f"summary_{it.status}"),
                "next_step": i18n.label(lang, f"next_{it.status}"),
            }
            for lang in run.langs
        },
    }


def pretty(value: Any) -> bytes:
    # Sorted keys: byte-for-byte the same layout as the Rust profile (serde_json maps are sorted).
    return (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


# ---------- PDF (ReportLab, built from the same view model as HTML) ----------

# Rakvor palette. Pages stay light for printing and court bundles; the brand lives in the header band.
INK, MUTED, ACCENT, LINE = (
    colors.HexColor("#0D1117"),
    colors.HexColor("#475467"),
    colors.HexColor("#2A5CFF"),
    colors.HexColor("#E4E7EC"),
)
NIGHT, NIGHT2, VIOLET, CYAN, MIST = (colors.HexColor(c) for c in ("#0D1117", "#1A1F26", "#6B00FF", "#00E5FF", "#E6E6E6"))
_ST = {
    "brand": ParagraphStyle("brand", fontName="Helvetica-Bold", fontSize=8, textColor=ACCENT, spaceAfter=4),
    "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=INK),
    "sub": ParagraphStyle("sub", fontName="Helvetica", fontSize=10, textColor=MUTED, spaceAfter=10),
    "h": ParagraphStyle("h", fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=INK, spaceBefore=12, spaceAfter=4),
    "p": ParagraphStyle("p", fontName="Helvetica", fontSize=9.5, leading=12.8, textColor=INK, spaceAfter=3),
    "key": ParagraphStyle("key", fontName="Helvetica", fontSize=9, leading=12, textColor=MUTED),
    "val": ParagraphStyle("val", fontName="Helvetica", fontSize=9, leading=12, textColor=INK),
    "mono": ParagraphStyle("mono", fontName="Courier", fontSize=8, leading=11, textColor=INK, wordWrap="CJK"),
    "status": ParagraphStyle(
        "status",
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=INK,
        borderPadding=6,
        leftIndent=6,
        borderColor=ACCENT,
        borderWidth=0,
        spaceBefore=4,
        spaceAfter=8,
    ),
    "note": ParagraphStyle("note", fontName="Helvetica-Bold", fontSize=9.5, leading=12.8, textColor=colors.HexColor("#B54708")),
}
_HASHLIKE = re.compile(r"^\S{32,}$")


def _p(text: Any, style: str = "p") -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "")), _ST[style])


def _kv(rows: list[tuple[str, Any]]):
    if not rows:  # e.g. a run cancelled before the first item
        return _p("\u2014")
    data = [[_p(k, "key"), _p(v, "mono" if _HASHLIKE.match(str(v)) else "val")] for k, v in rows]
    t = Table(data, colWidths=[55 * mm, None], hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return t


def _bullets(items: list[str]) -> list[Paragraph]:
    return [Paragraph("•&nbsp;&nbsp;" + escape(str(x)), _ST["p"]) for x in items]


def _render_pdf(make_story, ctx: dict, title_key: str) -> bytes:
    """Builds twice (flowables are single-use, hence `make_story`): the first pass counts pages so every
    footer can say "page n of m"."""
    t = ctx["t"]
    footer = f"{t['generated_by']} {ctx['tool']['name']} {ctx['tool']['version']} \u00b7 {ctx['run']['run_id']}"
    total = [0]

    def build(final: bool) -> bytes:
        buf = io.BytesIO()

        def on_page(canvas, doc):
            total[0] = max(total[0], doc.page) if not final else total[0]
            canvas.saveState()
            _brand_band(canvas, ctx)
            canvas.setFont("Helvetica-Oblique", 7)
            canvas.setFillColor(MUTED)
            canvas.drawString(18 * mm, 7 * mm, ctx["brand"]["tagline"])
            canvas.setStrokeColor(LINE)
            canvas.line(18 * mm, 15 * mm, A4[0] - 18 * mm, 15 * mm)
            canvas.setFont("Helvetica", 7.5)
            canvas.setFillColor(MUTED)
            canvas.drawString(18 * mm, 11 * mm, f"{footer}  \u2014  {t['page']} {doc.page} {t['of']} {total[0] or '?'}")
            canvas.restoreState()

        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=30 * mm,
            bottomMargin=22 * mm,
            title=t[title_key],
            author=ctx["run"]["actor"],
            creator=f"{ctx['tool']['name']} {ctx['tool']['version']}",
            producer=f"{ctx['tool']['name']} {ctx['tool']['version']} (ReportLab)",
        )
        doc.build(make_story(), onFirstPage=on_page, onLaterPages=on_page)
        return buf.getvalue()

    build(final=False)
    return build(final=True)


def _brand_band(canvas, ctx: dict) -> None:
    """Dark Rakvor band with the RV mark (placeholder until the official logo file exists)."""
    w, h = A4
    canvas.setFillColor(NIGHT)
    canvas.rect(0, h - 22 * mm, w, 22 * mm, stroke=0, fill=1)
    for i, c in enumerate((ACCENT, VIOLET, CYAN)):  # gradient-like rule
        canvas.setFillColor(c)
        canvas.rect(i * w / 3, h - 22.8 * mm, w / 3, 0.8 * mm, stroke=0, fill=1)
    x, y = 18 * mm, h - 18.5 * mm
    canvas.setStrokeColor(ACCENT)
    canvas.setLineWidth(1.2)
    canvas.setFillColor(NIGHT2)
    canvas.roundRect(x, y, 15 * mm, 15 * mm, 3.2 * mm, stroke=1, fill=1)
    canvas.setFillColor(MIST)
    canvas.setFont("Helvetica-Bold", 15)
    canvas.drawCentredString(x + 7.5 * mm, y + 5.2 * mm, "RV")
    canvas.setFillColor(CYAN)
    canvas.rect(x + 4 * mm, y + 2.6 * mm, 7 * mm, 0.7 * mm, stroke=0, fill=1)
    canvas.setFillColor(MIST)
    canvas.setFont("Helvetica-Bold", 12)
    canvas.drawString(x + 19 * mm, y + 8.6 * mm, "R A K V O R")
    canvas.setFillColor(CYAN)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(x + 19 * mm, y + 3.6 * mm, ctx["brand"]["descriptor"])


def _header(ctx: dict, title_key: str, subtitle: str) -> list:
    return [_p(ctx["t"][title_key], "title"), _p(subtitle, "sub")]


def _signature_row(ctx: dict) -> tuple[str, str]:
    t, sig = ctx["t"], ctx["signature"]
    return (
        t["signature"],
        f"{t['signed_by']} {sig['by']} ({t['certificate_sha256']} {sig['certificate_sha256']})" if sig["signed"] else t["not_signed"],
    )


def statistics_pdf(ctx: dict) -> bytes:
    def story() -> list:
        t, run, tot = ctx["t"], ctx["run"], ctx["totals"]
        s = _header(ctx, "title_statistics", f"{t['run_id']}: {run['run_id']}")
        if run["cancelled"]:
            s.append(_p(t["cancelled_note"], "note"))
        rows = [(t["tool"], f"{ctx['tool']['name']} {ctx['tool']['version']}")]
        if run["case_id"]:
            rows.append((t["case"], run["case_id"]))
        rows += [
            (t["actor"], run["actor"]),
            (t["started"], run["started_utc"]),
            (t["finished"], run["finished_utc"]),
            (t["duration"], run["duration_text"]),
            (t["frontend"], run["frontend"]),
            (t["algorithms"], run["algorithms_text"]),
            (t["items"], tot["items"]),
            (t["bytes"], tot["bytes"]),
            (t["errors"], tot["errors"]),
            (t["throughput"], tot["throughput_text"]),
        ]
        s.append(_kv(rows))
        s += [_p(t["findings_by_severity"], "h"), _kv([(r["label"], r["count"]) for r in ctx["severity_rows"]])]
        s.append(_p(t["findings_by_code"], "h"))
        s.append(_kv([(r["title"], r["count"]) for r in ctx["code_rows"]]) if ctx["code_rows"] else _p(t["none"]))
        s += [_p(t["by_type"], "h"), _kv([(r["name"], r["count"]) for r in ctx["type_rows"]])]
        s.append(_p(t["duplicates"], "h"))
        if not ctx["duplicate_rows"]:
            s.append(_p(t["none"]))
        for d in ctx["duplicate_rows"]:
            s.append(KeepTogether([_p(d["hash"], "mono"), *_bullets(d["paths"]), Spacer(1, 4)]))
        case = ctx["case"]
        if case:
            rows = [(t["case"], case["case_id"])] + [(t[k], case[k]) for k in ("registered", "added", "verified", "mismatched", "unregistered")]
            s += [_p(t["case_verification"], "h"), _kv([*rows, (t["case_dir"], case["dir"])])]
        s.append(_p(t["items"], "h"))
        s.append(
            _kv(
                [
                    (
                        f"#{r['index']}  {r['evidence_id']}  {r['file_name']}" if r["evidence_id"] else f"#{r['index']}  {r['file_name']}",
                        f"{r['status_label']} · {r['size']} {t['bytes'].lower()} · {r['finding_count']} {t['findings'].lower()}",
                    )
                    for r in ctx["item_rows"]
                ]
            )
        )
        s += [_p(t["limitations"], "h"), *_bullets(ctx["limitations"])]
        ts = ctx["timestamp"]
        ts_rows = [(t["status"], ts["status_label"])]
        if ts.get("tsa"):
            ts_rows.append((t["tsa"], ts["tsa"]))
        if ts.get("gen_time"):
            ts_rows += [(t["gen_time"], ts["gen_time"]), (t["covers"], f"#{ts['covers_seq']}"), (t["audit_head"], ts["head"])]
        s += [_p(t["timestamp"], "h"), _kv(ts_rows), _kv([_signature_row(ctx)])]
        s += [
            _p(t["audit"], "h"),
            _kv(
                [
                    (t["audit_head"], ctx["audit"]["head"]),
                    (t["audit_entries"], ctx["audit"]["entries"]),
                    (t["log_dir"], ctx["audit"]["log_dir"]),
                ]
            ),
        ]
        return s

    return _render_pdf(story, ctx, "title_statistics")


def technical_pdf(ctx: dict) -> bytes:
    def story() -> list:
        t, it = ctx["t"], ctx["item"]
        s = _header(ctx, "title_technical", f"{t['item']} #{it['index']} · {it['file_name']} · {t['run_id']}: {ctx['run']['run_id']}")
        rows = [
            (t["path"], it["path"]),
            (t["size"], it["size"]),
            (t["modified"], it["modified_utc"]),
            (t["extension"], it["extension_text"]),
            (t["detected_type"], it["detected_text"]),
            (t["status"], it["status_label"]),
        ]
        if ctx["case"]:
            rows += [
                (t["case"], ctx["case"]["case_id"]),
                (t["evidence_id"], it["evidence_id"] or t["none"]),
                (t["case_registry"], it["case_status_label"]),
            ]
            if it["intake_utc"]:
                rows.append((t["intake_date"], it["intake_utc"]))
        s.append(_kv(rows))
        s += [_p(t["hashes"], "h"), _kv([(h["algorithm"], h["value"]) for h in ctx["hash_rows"]])]
        s.append(_p(t["findings"], "h"))
        if not ctx["findings"]:
            s.append(_p(t["none"]))
        for f in ctx["findings"]:
            s.append(
                KeepTogether(
                    [
                        _p(f"[{f['severity_label']}]  {f['title']}  ({f['code']})", "p"),
                        _kv([(t["shows"], f["shows"]), (t["does_not_prove"], f["does_not_prove"])]),
                        Spacer(1, 4),
                    ]
                )
            )
        s += [_p(t["method"], "h"), _p(t["method_text"])]
        s += [
            _p(t["audit"], "h"),
            _kv(
                [
                    (t["audit_entries"], f"#{it['audit_first_seq']} – #{it['audit_last_seq']}"),
                    (t["log_dir"], ctx["audit"]["log_dir"]),
                    _signature_row(ctx),
                ]
            ),
        ]
        s += [_p(t["limitations"], "h"), *_bullets(ctx["limitations"])]
        return s

    return _render_pdf(story, ctx, "title_technical")


def summary_pdf(ctx: dict) -> bytes:
    def story() -> list:
        t, it, run = ctx["t"], ctx["item"], ctx["run"]
        sub = it["file_name"] + (f" · {t['evidence_id']}: {it['evidence_id']}" if it["evidence_id"] else "")
        sub += f" · {t['case']}: {run['case_id']}" if run["case_id"] else ""
        s = _header(ctx, "title_summary", sub)
        s += [_p(it["status_label"], "status"), _p(it["summary_text"])]
        s += [_p(t["what_we_did"], "h"), _p(t["method_text"]), _p(t["what_we_found"], "h")]
        s += _bullets([f"{f['title']}. {f['shows']}" for f in ctx["findings"]]) if ctx["findings"] else [_p(t["none"])]
        s += [_p(t["fingerprint"], "h"), _p(t["fingerprint_text"]), _kv([(it["primary_algorithm"], it["primary_hash"])])]
        s += [_p(t["next_steps"], "h"), _p(it["next_text"])]
        return s

    return _render_pdf(story, ctx, "title_summary")


# ---------- Chain-of-custody form (one per item; jurisdiction language + English) ----------


def custody_context(lang: str, run: RunInfo, it: ItemResult, audit: AuditRef) -> dict:
    ctx = item_context(lang, run, it, audit)
    c = i18n.catalog(lang)["custody"]
    j = run.jurisdiction
    ctx["custody"] = {
        **c,
        "title": c[f"title_{j}"],
        "basis": c[f"basis_{j}"],
        "case_label": c[f"case_{j}"],
        "evidence_id_label": c[f"evidence_id_{j}"],
        "evidence_id": _custody_evidence_id(run, it),
        "intake_utc": it.intake_utc,
        "jurisdiction_label": i18n.catalog(lang)["ui"][f"jur_{j}"],
        "operation_text": i18n.fill(
            c["operation_text"],
            {
                "tool": run.tool_name,
                "version": run.tool_version,
                "run_id": run.run_id,
                "start": run.started_utc,
                "end": run.finished_utc,
                "first": str(it.audit_first_seq),
                "last": str(it.audit_last_seq),
            },
        ),
        "blank_rows": list(range(BLANK_TRANSFER_ROWS)),
    }
    return ctx


def _custody_evidence_id(run: RunInfo, it: ItemResult) -> str:
    """The case registry id (E0001...) when the run is linked to a case, else "<RUN-ID>-<NNNNN>"."""
    return it.evidence_id or f"{run.run_id}-{it.index:05d}"


def custody_json(run: RunInfo, it: ItemResult) -> dict:
    return {
        "schema": SCHEMA_CUSTODY,
        "jurisdiction": run.jurisdiction,
        "run_id": run.run_id,
        "case_id": run.case_id,
        "evidence_id": _custody_evidence_id(run, it),
        "intake_utc": it.intake_utc,
        "item": {"index": it.index, "path": str(it.path), "file_name": it.file_name, "size": it.size},
        "hashes": dict(it.hashes),
        "examiner": run.actor,
        "operations": [
            {
                "tool": run.tool_name,
                "version": run.tool_version,
                "start_utc": run.started_utc,
                "end_utc": run.finished_utc,
                "audit_first_seq": it.audit_first_seq,
                "audit_last_seq": it.audit_last_seq,
            }
        ],
        "transfers": [],
    }


def custody_pdf(ctx: dict) -> bytes:
    def story() -> list:
        c, it, run, t = ctx["custody"], ctx["item"], ctx["run"], ctx["t"]
        s = [
            _p(c["title"], "title"),
            _p(f"{t['jurisdiction']}: {c['jurisdiction_label']} · {t['run_id']}: {run['run_id']}", "sub"),
            _p(c["basis"], "note"),
            Spacer(1, 6),
        ]
        rows = [(c["case_label"], run["case_id"] or ""), (c["evidence_id_label"], c["evidence_id"])]
        if c["intake_utc"]:
            rows.append((c["intake_date"], c["intake_utc"]))
        rows += [(c["description"], f"{it['file_name']} · {it['size']} bytes · {it['detected_text']}"), (c["location"], it["path"])]
        s.append(_kv(rows))
        s += [_p(c["integrity"], "h"), _kv([(h["algorithm"], h["value"]) for h in ctx["hash_rows"]])]
        s += [_p(c["operations"], "h"), _p(c["operation_text"]), _kv([(c["examiner"], run["actor"])])]
        head = [_p(x, "key") for x in (c["date_time"], c["delivered_by"], c["received_by"], c["purpose"], c["condition"])]
        rows = [head] + [["", "", "", "", ""] for _ in c["blank_rows"]]
        tbl = Table(rows, colWidths=[28 * mm, 42 * mm, 42 * mm, 28 * mm, 34 * mm], rowHeights=[None] + [12 * mm] * len(c["blank_rows"]))
        tbl.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, MUTED),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F5F7FB")),
                ]
            )
        )
        s += [_p(c["transfers"], "h"), tbl]
        obs = Table([[""], [""]], colWidths=[174 * mm], rowHeights=[12 * mm, 12 * mm])
        obs.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, MUTED)]))
        s += [_p(c["observations"], "h"), obs, Spacer(1, 16)]
        sig = Table(
            [[f"{c['examiner']}: {run['actor']}", c["received_by"]], [c["signature_line"], c["signature_line"]]],
            colWidths=[87 * mm, 87 * mm],
            rowHeights=[None, 14 * mm],
        )
        sig.setStyle(
            TableStyle(
                [
                    ("LINEABOVE", (0, 1), (-1, 1), 0.6, INK),
                    ("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
                    ("FONT", (0, 0), (-1, -1), "Helvetica", 8.5),
                    ("TEXTCOLOR", (0, 1), (-1, 1), MUTED),
                ]
            )
        )
        s.append(KeepTogether([sig]))
        return s

    return _render_pdf(story, ctx, "custody")


def _finish_pdf(run: RunInfo, data: bytes, reason: str) -> bytes:
    """Signs the PDF with the examiner's certificate when one was given."""
    return run.signer.sign(data, reason=reason) if run.signer is not None else data


# ---------- Writing ----------


def write_hashed(directory: Path, name: str, data: bytes, algos: list[str]) -> tuple[str, dict]:
    path = directory / name
    path.write_bytes(data)
    return name, {a: hash_bytes(data, a) for a in algos}


def write_item_reports(directory: Path, run: RunInfo, it: ItemResult, audit: AuditRef) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    files: dict[str, dict] = {}

    def put(r):
        files[r[0]] = r[1]

    put(write_hashed(directory, "technical.json", pretty(technical_json(run, it)), run.algorithms))
    put(write_hashed(directory, "summary.json", pretty(summary_json(run, it)), run.algorithms))
    for lang in run.langs:
        ctx = item_context(lang, run, it, audit)
        put(write_hashed(directory, f"technical.{lang}.html", render_html("technical.html", ctx).encode("utf-8"), run.algorithms))
        put(write_hashed(directory, f"summary.{lang}.html", render_html("summary.html", ctx).encode("utf-8"), run.algorithms))
        put(
            write_hashed(
                directory,
                f"technical.{lang}.pdf",
                _finish_pdf(run, technical_pdf(ctx), ctx["t"]["title_technical"]),
                run.algorithms,
            )
        )
        put(write_hashed(directory, f"summary.{lang}.pdf", _finish_pdf(run, summary_pdf(ctx), ctx["t"]["title_summary"]), run.algorithms))
    put(write_hashed(directory, "custody.json", pretty(custody_json(run, it)), run.algorithms))
    for lang in run.custody_langs():
        ctx = custody_context(lang, run, it, audit)
        put(write_hashed(directory, f"custody.{lang}.html", render_html("custody.html", ctx).encode("utf-8"), run.algorithms))
        put(write_hashed(directory, f"custody.{lang}.pdf", _finish_pdf(run, custody_pdf(ctx), ctx["custody"]["title"]), run.algorithms))
    return files


def write_statistics(directory: Path, run: RunInfo, items: list[ItemResult], totals: RunTotals, audit: AuditRef) -> dict:
    directory.mkdir(parents=True, exist_ok=True)
    files = dict([write_hashed(directory, "statistics.json", pretty(statistics_json(run, items, totals, audit)), run.algorithms)])
    for lang in run.langs:
        ctx = statistics_context(lang, run, items, totals, audit)
        files.update([write_hashed(directory, f"statistics.{lang}.html", render_html("statistics.html", ctx).encode("utf-8"), run.algorithms)])
        pdf = _finish_pdf(run, statistics_pdf(ctx), ctx["t"]["title_statistics"])
        files.update([write_hashed(directory, f"statistics.{lang}.pdf", pdf, run.algorithms)])
    return files
