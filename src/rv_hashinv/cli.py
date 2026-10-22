"""rv-hashinv command-line interface. All work happens in rv_hashinv.core; this module only parses
arguments, renders events (progress bar or JSON Lines) and maps results to exit codes.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
from pathlib import Path

import click
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from . import TOOL_NAME, __version__
from .core import CASE_ROLE, RunConfig, run
from .core import case as casef
from .core.audit import AuditLog
from .core.envinfo import os_user
from .core.hashing import ALGORITHMS, KNOWN_ANSWERS, parse, self_test, validate_selection
from .core.i18n import parse_langs
from .core.timeutil import human_duration
from .core.trust import DEFAULT_TSA, TimestampError, timestamp_head
from .core.verify import verify_log as verify_audit_log

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_FINDINGS, EXIT_CANCELLED = 0, 1, 2, 3, 130
HELP_WIDTH = 100

DESCRIPTION = """\b
DESCRIPTION:
  rv-hashinv reviews a single file, a whole folder (bulk) or a list of files. For every file it:
    1. opens the file read-only and hashes it in one pass with one or two algorithms;
    2. detects the real file type from its signature (magic bytes);
    3. flags empty files, extensions that do not match the content, programs hidden under
       another name and duplicated content;
    4. writes a technical report and a customer-friendly summary (HTML, PDF and JSON).
  Each run also writes a statistics report and an audit trail under <OUT>/logs/<RUN-ID>/.
  Every action is appended to a hash-chained log that `rv-hashinv verify-log` can check later.

  CASE FOLDER (--case-dir): Rakvor tools share one folder per case. rv-hashinv is the intake tool: it
  registers every hashed file in evidence/registry.json (evidence ids E0001, E0002, ...) so later tools
  can prove they examined bit-identical copies. `rv-hashinv verify-case <CASE>` checks it all."""

SCAN_EPILOG = """\b
EXAMPLES:
  Review one file (SHA-256, English reports):
    rv-hashinv scan --input evidence/contract.pdf
  Review a folder and its subfolders with SHA-256 + MD5, Spanish reports, for case CASE-2026-014:
    rv-hashinv scan -i D:\\evidence -r --hash sha256,md5 --lang es --case CASE-2026-014
  Review the files listed in a text file, reports in the three languages, machine-readable progress:
    rv-hashinv scan --input-list files.txt --lang all --progress jsonl > events.jsonl
  Verify the audit log afterwards:
    rv-hashinv verify-log rakvor-out/logs/<RUN-ID>/audit.jsonl
  Open a case folder and register the evidence (intake), then verify the whole case:
    rv-hashinv scan -i D:\\evidence -r --case-dir E:\\CASE-014 --case CASE-014 --jurisdiction fr
    rv-hashinv verify-case E:\\CASE-014
  Re-examine two registered items of the case:
    rv-hashinv scan --case-dir E:\\CASE-014 --evidence E0001,E0002

\b
EXIT CODES:
  0    Completed; no high-severity finding.
  1    Runtime error (input not found, output not writable, case log locked, ...).
       See the audit log.
  2    Usage error (unknown option, more than two hash algorithms, unsupported language).
       With --case-dir: folder of another case or schema, --case missing when creating the
       case, unknown evidence id.
  3    Completed with at least one high-severity finding (e.g. unreadable file, program under
       another name, evidence that differs from the case registry), or the case folder fails
       verification (nothing is written to it).
  130  Cancelled with Ctrl+C. Partial reports and the cancellation are written to the audit log.

\b
FILES WRITTEN:
  <OUT>/logs/<RUN-ID>/audit.jsonl         Hash-chained log of every action (one JSON object per line).
  <OUT>/logs/<RUN-ID>/audit.log           The same actions, human-readable.
  <OUT>/logs/<RUN-ID>/hashes.csv          Hash register: index, path, size, digests, status.
  <OUT>/logs/<RUN-ID>/environment.json    Tool and dependency versions, OS, host, user, command line.
  <OUT>/reports/<RUN-ID>/statistics.json  Run statistics (+ statistics.<LANG>.html and .pdf).
  <OUT>/reports/<RUN-ID>/items/<NNNNN>-<NAME>/technical.json|.<LANG>.html|.<LANG>.pdf
  <OUT>/reports/<RUN-ID>/items/<NNNNN>-<NAME>/summary.json|.<LANG>.html|.<LANG>.pdf
  <OUT>/reports/<RUN-ID>/items/<NNNNN>-<NAME>/custody.json|.<es|fr>.html|.pdf|.en.html|.pdf
  <OUT>/logs/<RUN-ID>/timestamp-<SEQ>.tsr|.json  RFC 3161 token for the audit chain head.
  With --case-dir <CASE>, logs/ and reports/ go to <CASE>/runs/rv-hashinv/<RUN-ID>/, plus:
  <CASE>/case.json                        Case id, jurisdiction, creation (written once).
  <CASE>/case-log.jsonl                   Hash-chained case log of every tool: case_created,
                                          run_started, evidence_registered, run_finished.
  <CASE>/evidence/registry.json|.csv      Evidence registry: E0001..., path, size, hashes.

\b
FORENSIC NOTES:
  - Evidence is opened read-only and never modified; modification times are compared before and after.
  - Work on a verified copy (write-blocked image or export), not on original media.
  - Each audit entry stores the SHA-256 of the previous one; editing, deleting or re-ordering any
    line is detected by `verify-log`. Removing the last lines is detected only against a record
    kept outside the log: the RFC 3161 timestamp or, with --case-dir, the case log. Keep the log
    folder with the reports.
  - A file without findings is not proven authentic; read the Limitations section of each report.
  - MD5 and SHA-1 are accepted for compatibility with older case files; pair them with SHA-256 or BLAKE3.
  - The chain head is timestamped by an RFC 3161 authority (proves when the log existed). Offline? The run
    finishes with `timestamp_pending`; run `rv-hashinv timestamp <LOG>` later.
  - With --sign-cert every PDF is signed with the examiner's certificate; the password is never logged.
  - Case folder: every tool re-verifies case-log.jsonl and the registry digest before
    writing, and refuses a broken case (exit 3). Appends happen under case-log.lock; a lock
    older than 10 minutes is reported as stale and never deleted automatically.
  - Each run's audit.jsonl records case_linked (the case-log entry it started from); the case
    log records the run's final audit head, so the two chains vouch for each other."""

CONTEXT = {"help_option_names": ["-h", "--help"], "max_content_width": HELP_WIDTH, "terminal_width": HELP_WIDTH}


def _opt_help(text: str, default: str, example: str) -> str:
    """Every option documents its default and an example (contract checked by tests)."""
    return f"{text} Default: {default}. Example: {example}"


@click.group(
    context_settings=CONTEXT,
    help=DESCRIPTION,
    epilog="Run `rv-hashinv <COMMAND> --help` for the options, examples and exit codes of each command.",
)
@click.version_option(__version__, "-V", "--version", prog_name=TOOL_NAME)
def cli() -> None:
    """Inventory digital evidence with dual hashing, findings, reports and a tamper-evident audit log."""


@cli.command(help=DESCRIPTION, epilog=SCAN_EPILOG, short_help="Hash, check and report on a file, a folder or a list of files.")
@click.option(
    "-i",
    "--input",
    "inputs",
    multiple=True,
    type=click.Path(path_type=Path),
    metavar="PATH",
    help=_opt_help(
        "File or folder to review. Repeat for several. Folders are reviewed one level deep unless "
        "--recursive is given. Symbolic links are not followed.",
        "none (required unless --input-list, --case-dir or --evidence is given)",
        "--input D:\\evidence --input E:\\phone-export\\chat.txt",
    ),
)
@click.option(
    "-L",
    "--input-list",
    type=click.Path(path_type=Path),
    metavar="FILE",
    help=_opt_help(
        "Text file with one path per line (bulk review). Lines starting with # are ignored. Relative paths are resolved from the list file's folder.",
        "none",
        "--input-list case-014-files.txt",
    ),
)
@click.option(
    "-r",
    "--recursive",
    is_flag=True,
    help=_opt_help("Also review files in subfolders.", "off (only the first level of each folder)", "-i D:\\evidence --recursive"),
)
@click.option(
    "-H",
    "--hash",
    "hashes",
    multiple=True,
    metavar="ALGO",
    help=_opt_help(
        f"Hash algorithm(s): one or two of {', '.join(ALGORITHMS)}. Both are computed in the same read of "
        "each file. More than two is refused (exit code 2).",
        "sha256",
        "--hash sha256,md5  or  --hash sha256 --hash blake3",
    ),
)
@click.option(
    "-o",
    "--out",
    type=click.Path(path_type=Path),
    default=Path("rakvor-out"),
    show_default=False,
    metavar="DIR",
    help=_opt_help(
        "Folder where logs/ and reports/ are created (if missing). Not used with --case-dir.", "./rakvor-out", "--out E:\\case-014\\rv-hashinv"
    ),
)
@click.option(
    "-l",
    "--lang",
    default="en",
    metavar="LANG",
    help=_opt_help(
        "Report language: en, es, fr, or all (one HTML and PDF per language). JSON is language-neutral.",
        "en",
        "--lang es  or  --lang all",
    ),
)
@click.option(
    "-a",
    "--actor",
    metavar="NAME",
    help=_opt_help("Name of the examiner, written in every audit entry and report.", "the operating-system user name", '--actor "Ana Ruiz"'),
)
@click.option(
    "-c",
    "--case",
    "case_id",
    metavar="ID",
    help=_opt_help(
        "Case or engagement identifier printed on the reports. With --case-dir it names the case when the folder is created, "
        "and must match case.json afterwards (it can be left out).",
        "none",
        "--case CASE-2026-014",
    ),
)
@click.option(
    "-p",
    "--progress",
    "progress_mode",
    type=click.Choice(["bar", "jsonl", "none"]),
    default="bar",
    metavar="MODE",
    help=_opt_help(
        "How progress is shown: bar (elapsed, throughput, ETA on stderr), jsonl (one JSON event per line on stdout) or none.",
        "bar (hidden automatically when stderr is not a terminal)",
        "--progress jsonl",
    ),
)
@click.option(
    "-j",
    "--jurisdiction",
    type=click.Choice(["co", "fr"]),
    default="co",
    metavar="CC",
    help=_opt_help(
        "Chain-of-custody form per item: co (Colombia, Fiscalía style, Spanish) or fr (France, scellés, French); an English copy is always added. "
        "In a case folder (--case-dir) the case's jurisdiction applies.",
        "co",
        "--jurisdiction fr",
    ),
)
@click.option(
    "--tsa-url",
    default=DEFAULT_TSA,
    metavar="URL",
    help=_opt_help("RFC 3161 time-stamping authority for the audit chain head.", DEFAULT_TSA, "--tsa-url https://freetsa.org/tsr"),
)
@click.option(
    "--no-timestamp",
    is_flag=True,
    envvar="RV_NO_TIMESTAMP",
    help=_opt_help("Do not request a trusted timestamp (offline labs).", "off (a timestamp is requested)", "--no-timestamp"),
)
@click.option(
    "--sign-cert",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    metavar="P12",
    help=_opt_help(
        "Examiner's certificate (.p12/.pfx) used to sign every PDF report. The password is read from the "
        "environment variable named by --sign-pass-env, or asked for interactively.",
        "none (PDFs are not signed)",
        "--sign-cert C:\\certs\\ana-ruiz.p12",
    ),
)
@click.option(
    "--sign-pass-env",
    default="RV_SIGN_PASSWORD",
    metavar="VAR",
    help=_opt_help("Environment variable holding the certificate password.", "RV_SIGN_PASSWORD", "--sign-pass-env CERT_PASS"),
)
@click.option(
    "--case-dir",
    type=click.Path(path_type=Path, file_okay=False),
    metavar="DIR",
    help=_opt_help(
        "Shared case folder that links the Rakvor tools of one case (created with --case if missing). Outputs go to "
        "<DIR>/runs/rv-hashinv/<RUN-ID>/; every hashed file is registered in <DIR>/evidence/registry.json; the run is "
        "recorded in <DIR>/case-log.jsonl. With no --input, every registered item is examined.",
        "none (standalone run in --out)",
        "--case-dir E:\\CASE-014 --case CASE-014",
    ),
)
@click.option(
    "-E",
    "--evidence",
    "evidence",
    multiple=True,
    metavar="IDS",
    help=_opt_help(
        "Registered evidence ids to examine (needs --case-dir), comma-separated or repeated.",
        "none (the --input files, or every registered item)",
        "--evidence E0001,E0007",
    ),
)
@click.pass_context
def scan(
    ctx,
    inputs,
    input_list,
    recursive,
    hashes,
    out,
    lang,
    actor,
    case_id,
    progress_mode,
    jurisdiction,
    tsa_url,
    no_timestamp,
    sign_cert,
    sign_pass_env,
    case_dir,
    evidence,
) -> None:
    algos: list[str] = []
    for h in (x for raw in (hashes or ("sha256",)) for x in raw.split(",") if x.strip()):
        a = parse(h)
        if a is None:
            _usage(f"unknown hash algorithm '{h}': use {', '.join(ALGORITHMS)}")
        algos.append(a)
    try:
        validate_selection(algos)
        langs = parse_langs(lang)
    except ValueError as e:
        _usage(str(e))
    if not inputs and not input_list and case_dir is None:
        _usage("no input given: use --input FILE|FOLDER or --input-list FILE")
    try:
        evidence_ids = casef.parse_evidence_ids(list(evidence))
    except casef.CaseError as e:
        _usage(str(e))
    if evidence_ids and case_dir is None:
        _usage("--evidence needs --case-dir")
    if case_dir is not None:
        # Case problems found before the run map to their own exit codes (2 usage, 3 broken case).
        try:
            casef.preflight(case_dir, case_id, evidence_ids)
        except casef.CaseError as e:
            if e.exit_code == EXIT_USAGE:
                _usage(str(e))
            click.echo(f"error: {e}", err=True)
            ctx.exit(e.exit_code)

    cancel = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: cancel.set())
    cfg = RunConfig(
        inputs=list(inputs),
        input_list=input_list,
        recursive=recursive,
        algorithms=algos,
        out_dir=out,
        langs=langs,
        actor=actor or os_user(),
        case_id=case_id,
        frontend="cli",
        command_line=sys.argv,
        tool_name=TOOL_NAME,
        tool_version=__version__,
        jurisdiction=jurisdiction,
        tsa_url=None if no_timestamp else tsa_url,
        sign_cert=sign_cert,
        sign_password=_password(sign_cert, sign_pass_env),
        case_dir=case_dir,
        evidence_ids=evidence_ids,
        case_role=CASE_ROLE,
    )

    err = Console(stderr=True)
    stdout_open = [True]
    bar = None
    if progress_mode == "bar" and err.is_terminal:
        bar = Progress(
            TextColumn("{task.description}"),
            BarColumn(),
            DownloadColumn(binary_units=True),
            TransferSpeedColumn(),
            TimeElapsedColumn(),
            TextColumn("ETA"),
            TimeRemainingColumn(),
            console=err,
            transient=True,
        )
        bar.start()
        task = bar.add_task("0/0 files", total=None)

    def sink(e: dict) -> None:
        if progress_mode == "jsonl" and stdout_open[0]:
            try:  # a closed stdout (e.g. `| head`) must never abort a forensic run half-way
                sys.stdout.write(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n")
                sys.stdout.flush()
            except (BrokenPipeError, OSError):
                stdout_open[0] = False
        if bar is not None:
            kind = e["event"]
            if kind == "run_started":
                bar.update(task, total=e["total_bytes"], description=f"0/{e['total_items']} files")
            elif kind == "progress":
                bar.update(task, completed=e["bytes_done"], description=f"{e['done']}/{e['total']} files")
            elif kind == "error":
                bar.console.print(f"warning: {e['path']}: {e['message']}")
            elif kind == "cancelled":
                bar.console.print("cancelled: writing partial reports...")
            elif kind == "timestamp" and e["status"] != "ok":
                bar.console.print(f"warning: timestamp pending ({e.get('reason')}); run `rv-hashinv timestamp` later")

    try:
        s = run(cfg, sink, cancel)
    except (ValueError, OSError) as e:
        if bar:
            bar.stop()
        click.echo(f"error: {e}", err=True)
        ctx.exit(EXIT_ERROR)
    if bar:
        bar.stop()
    if progress_mode != "jsonl":
        status = "CANCELLED" if s.cancelled else "DONE (high-severity findings)" if s.high else "DONE"
        try:
            click.echo(
                f"{status}  run {s.run_id}\n"
                f"  items: {s.items}  bytes: {s.bytes}  errors: {s.errors}  elapsed: {human_duration(s.elapsed_ms)}\n"
                f"  findings: high {s.high}, medium {s.medium}, low {s.low}, info {s.info}\n"
                f"  timestamp: {s.timestamp['status']}{' ' + s.timestamp.get('gen_time', '') if s.timestamp['status'] == 'ok' else ''}\n"
                f"  report: {s.report_dir / f'statistics.{langs[0]}.html'}\n  logs:   {s.log_dir}"
            )
            if s.case is not None:
                t = s.case.tally
                click.echo(
                    f"  case:   {s.case.case_id} ({s.case.role}) registered {t.registered} (new {t.added}), verified {t.verified}, "
                    f"mismatched {t.mismatched}, not in registry {t.unregistered}"
                )
        except OSError:
            pass
    ctx.exit(EXIT_CANCELLED if s.cancelled else EXIT_FINDINGS if s.high else EXIT_OK)


@cli.command(
    "verify-log",
    short_help="Verify an audit log (audit.jsonl): edited, deleted or re-ordered entries, and truncation.",
    epilog="\b\nCHECKS:\n"
    "  - every entry links to the previous one (hash chain): an edited, deleted or re-ordered entry\n"
    "    breaks it;\n"
    "  - every timestamp token (timestamp-<SEQ>.tsr) covers the hash of the entry it names, and every\n"
    "    timestamp_obtained entry still has its token file;\n"
    "  - truncation: a chain alone cannot show that entries were removed from its end. The log must\n"
    "    still contain the entry covered by its RFC 3161 timestamp (covers_seq) and, for a run inside\n"
    "    a case folder (<CASE>/runs/<TOOL>/<RUN-ID>/logs), end with the audit head that the case log\n"
    "    recorded at run_finished (only timestamp_obtained may follow). Entries after the last\n"
    "    anchored one are listed as not provable; with neither record the output says\n"
    '    "truncation not detectable without a timestamp or case record".\n\n'
    "\b\nEXAMPLES:\n  rv-hashinv verify-log rakvor-out/logs/20261019T101500Z-a1b2c3/audit.jsonl\n"
    "  rv-hashinv verify-log rakvor-out/logs/20261019T101500Z-a1b2c3\n"
    "  rv-hashinv verify-log E:\\CASE-014\\runs\\rv-hashinv\\20261019T101500Z-a1b2c3\\logs\n\n\b\nEXIT CODES:\n"
    "  0  The chain is intact and agrees with its timestamps and case record (if any).\n  1  The log cannot be read.\n"
    "  3  The chain is broken (an entry was edited, deleted or re-ordered), a timestamp does not\n"
    "     match, or the log is shorter than its timestamp or case record says (truncated).",
)
@click.argument("log", type=click.Path(path_type=Path), metavar="LOG")
@click.pass_context
def verify_log(ctx, log: Path) -> None:
    """Verify an audit log (audit.jsonl): edited, deleted or re-ordered entries, and truncation.

    LOG is the path to audit.jsonl, or to the run's log folder that contains it.
    Example: rakvor-out/logs/20261019T101500Z-a1b2c3
    """
    path = log / "audit.jsonl" if log.is_dir() else log
    try:
        v = verify_audit_log(path)
    except OSError as e:
        click.echo(f"error: cannot open {path}: {e}", err=True)
        ctx.exit(EXIT_ERROR)
    if not v.problems:
        click.echo(f"OK  {v.entries} entries, chain intact: {path}")
        for t in v.timestamps:
            click.echo(f"    {t}")
        click.echo(f"    {v.truncation}")
    else:
        click.echo(f"BROKEN  {path}")
        for p in v.problems:
            click.echo(f"  - {p}")
    for w in v.warnings:
        click.echo(f"  warning: {w}")
    ctx.exit(EXIT_FINDINGS if v.problems else EXIT_OK)


@cli.command(
    "verify-case",
    short_help="Verify a whole case folder: case log, evidence registry and every run's audit log.",
    epilog="\b\nCHECKS:\n"
    "  - case-log.jsonl is an intact hash chain starting with case_created; case.json is unchanged;\n"
    "  - evidence/registry.json has the SHA-256 recorded at the last registry change;\n"
    "  - every run announced in the case log has an intact audit.jsonl (and valid timestamp\n"
    "    tokens), its case_linked entry points to its run_started entry, and the audit head\n"
    "    recorded at run_finished is its final entry (only timestamp_obtained may follow);\n"
    "  - with --rehash: every registered item still reachable at its registered path is read again\n"
    "    and its digests are compared with the registry (the latest registration of a path).\n\n"
    "\b\nEXAMPLES:\n  rv-hashinv verify-case E:\\CASE-014\n  rv-hashinv verify-case E:\\CASE-014 --rehash\n\n\b\nEXIT CODES:\n"
    "  0  The case folder is intact (warnings, e.g. a run still in progress or an item not\n"
    "     reachable for --rehash, are printed).\n"
    "  1  The folder is not a case folder (no case.json).\n"
    "  3  At least one check failed: the case was edited, truncated or re-ordered, or (--rehash)\n"
    "     an evidence file differs from the registry.",
)
@click.argument("case_dir", type=click.Path(path_type=Path), metavar="CASE")
@click.option(
    "--rehash",
    is_flag=True,
    help=_opt_help(
        "Also re-hash every registered item still reachable and compare it with the registry.",
        "off (only the registry's digest is checked)",
        "--rehash",
    ),
)
@click.pass_context
def verify_case_cmd(ctx, case_dir: Path, rehash: bool) -> None:
    """Verify a whole case folder: case log, evidence registry and every run's audit log.

    CASE is the case folder (the one that holds case.json). Example: E:\\CASE-014
    """
    if not (case_dir / casef.CASE_FILE).is_file():
        click.echo(f"error: {case_dir} is not a case folder (no {casef.CASE_FILE})", err=True)
        ctx.exit(EXIT_ERROR)
    v = casef.verify_case(case_dir)
    r = casef.rehash_registry(case_dir, v) if rehash else None
    if not v.problems:
        click.echo(f"OK  case {v.case_id}: {v.entries} case-log entries, {v.registry_items} registered items, {v.runs} runs verified: {case_dir}")
    else:
        click.echo(f"BROKEN  case {v.case_id}: {case_dir}")
        for p in v.problems:
            click.echo(f"  - {p}")
    if r is not None:
        click.echo(f"    re-hashed {r.checked} of {r.registered} registered items: {r.matched} match the registry")
    for w in v.warnings:
        click.echo(f"  warning: {w}")
    ctx.exit(EXIT_FINDINGS if v.problems else EXIT_OK)


@cli.command(
    "timestamp",
    short_help="Add an RFC 3161 timestamp to a finished run (e.g. after working offline).",
    epilog="\b\nEXAMPLES:\n  rv-hashinv timestamp rakvor-out/logs/20261019T101500Z-a1b2c3\n"
    "  rv-hashinv timestamp rakvor-out/logs/20261019T101500Z-a1b2c3 --tsa-url https://freetsa.org/tsr\n\n\b\nEXIT CODES:\n"
    "  0  Timestamp obtained and logged.\n  1  The TSA could not be reached (nothing changed; try again).\n"
    "  3  The log is missing or broken: no timestamp is added.",
)
@click.argument("log", type=click.Path(path_type=Path), metavar="LOG")
@click.option(
    "--tsa-url",
    default=DEFAULT_TSA,
    metavar="URL",
    help=_opt_help("RFC 3161 time-stamping authority.", DEFAULT_TSA, "--tsa-url https://freetsa.org/tsr"),
)
@click.option(
    "-a",
    "--actor",
    metavar="NAME",
    help=_opt_help("Name written in the new audit entry.", "the operating-system user name", '--actor "Ana Ruiz"'),
)
@click.pass_context
def timestamp_cmd(ctx, log: Path, tsa_url: str, actor: str | None) -> None:
    """Add an RFC 3161 timestamp of the current audit chain head to a finished run.

    LOG is the run's log folder (or its audit.jsonl). Example: rakvor-out/logs/20261019T101500Z-a1b2c3
    """
    d = log.parent if log.is_file() else log
    if not (d / "audit.jsonl").is_file():
        click.echo(f"error: no audit log at {d / 'audit.jsonl'}: nothing to timestamp", err=True)
        ctx.exit(EXIT_FINDINGS)
    try:
        audit = AuditLog.resume(d, actor or os_user())
    except (ValueError, OSError) as e:
        click.echo(f"error: {e}", err=True)
        ctx.exit(EXIT_FINDINGS)
    try:
        ts = timestamp_head(d, audit.seq, audit.head, tsa_url)
    except TimestampError as e:
        audit.close()
        click.echo(f"error: {e}", err=True)
        ctx.exit(EXIT_ERROR)
    audit.record("timestamp_obtained", ts.file, ts.to_json())
    audit.close()
    click.echo(f"OK  timestamp {ts.gen_time} by {ts.tsa} covers entry #{ts.covers_seq}")
    ctx.exit(EXIT_OK)


@cli.command(
    "self-test",
    short_help="Check every hash algorithm against known-answer test vectors.",
    epilog="\b\nEXAMPLES:\n  rv-hashinv self-test\n\n\b\nEXIT CODES:\n"
    '  0  All algorithms give the published answer for the input "abc".\n'
    "  1  At least one algorithm failed: do not use this build for evidence.",
)
@click.pass_context
def self_test_cmd(ctx) -> None:
    """Check every hash algorithm against known-answer test vectors."""
    failed = self_test()
    for algo in KNOWN_ANSWERS:
        click.echo(f"{algo:<9} {'FAIL' if algo in failed else 'PASS'}")
    ctx.exit(EXIT_ERROR if failed else EXIT_OK)


@cli.command("docs-cli", hidden=True)
def docs_cli() -> None:
    """Print the full help of every command as Markdown (generates docs/usage-cli.md)."""
    click.echo(docs_markdown(), nl=False)


def docs_markdown() -> str:
    out = [
        "# Command-line reference\n\n<!-- Generated by `rv-hashinv docs-cli`. Do not edit by hand: CI fails if this file differs. -->\n\n",
        "```mermaid\nflowchart LR\n  A[rv-hashinv] --> B[scan]\n  A --> C[verify-log]\n  A --> D[self-test]\n  A --> T[timestamp]\n"
        "  A --> V[verify-case]\n  T --> E\n  B --> E[(logs/RUN-ID)]\n  B --> F[(reports/RUN-ID)]\n  B -. --case-dir .-> K[(CASE folder)]\n"
        "  V --> K\n  C --> E\n```\n\n",
    ]
    root = click.Context(cli, info_name=TOOL_NAME, **{k: v for k, v in CONTEXT.items() if k != "help_option_names"})
    out.append(f"## rv-hashinv\n\n```text\n{cli.get_help(root).rstrip()}\n```\n\n")
    for name in ("scan", "verify-log", "timestamp", "self-test", "verify-case"):
        cmd = cli.commands[name]
        sub = click.Context(cmd, info_name=name, parent=root, **{k: v for k, v in CONTEXT.items() if k != "help_option_names"})
        out.append(f"## rv-hashinv {name}\n\n```text\n{cmd.get_help(sub).rstrip()}\n```\n\n")
    return "".join(out)


def _password(cert: Path | None, env: str) -> str | None:
    if cert is None:
        return None
    if os.environ.get(env) is not None:
        return os.environ[env]
    if sys.stdin.isatty():
        return click.prompt(f"Password for {cert.name}", hide_input=True, default="", show_default=False) or None
    return None


def _usage(msg: str) -> None:
    click.echo(f"error: {msg}\n\nFor more information, try 'rv-hashinv scan --help'.", err=True)
    sys.exit(EXIT_USAGE)


def main() -> None:
    cli(prog_name=TOOL_NAME)


if __name__ == "__main__":
    main()
