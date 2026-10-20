"""rv-hashinv command-line interface. All work happens in rv_hashinv.core; this module only parses
arguments, renders events (progress bar or JSON Lines) and maps results to exit codes.
"""

from __future__ import annotations

import json
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
from .core import RunConfig, run
from .core.audit import verify
from .core.envinfo import os_user
from .core.hashing import ALGORITHMS, KNOWN_ANSWERS, parse, self_test, validate_selection
from .core.i18n import parse_langs
from .core.timeutil import human_duration

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
  Every action is appended to a hash-chained log that `rv-hashinv verify-log` can check later."""

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

\b
EXIT CODES:
  0    Completed; no high-severity finding.
  1    Runtime error (input not found, output not writable, ...). See the audit log.
  2    Usage error (unknown option, more than two hash algorithms, unsupported language).
  3    Completed with at least one high-severity finding (e.g. unreadable file, program under
       another name).
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

\b
FORENSIC NOTES:
  - Evidence is opened read-only and never modified; modification times are compared before and after.
  - Work on a verified copy (write-blocked image or export), not on original media.
  - Each audit entry stores the SHA-256 of the previous one; editing, deleting or re-ordering any
    line is detected by `verify-log`. Keep the log folder with the reports.
  - A file without findings is not proven authentic; read the Limitations section of each report.
  - MD5 and SHA-1 are accepted for compatibility with older case files; pair them with SHA-256 or BLAKE3."""

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
        "none (required unless --input-list is given)",
        "--input D:\\evidence --input E:\\phone-export\\chat.txt",
    ),
)
@click.option(
    "-L",
    "--input-list",
    type=click.Path(path_type=Path),
    metavar="FILE",
    help=_opt_help(
        "Text file with one path per line (bulk review). Lines starting with # are ignored. Relative "
        "paths are resolved from the list file's folder.",
        "none",
        "--input-list case-014-files.txt",
    ),
)
@click.option(
    "-r",
    "--recursive",
    is_flag=True,
    help=_opt_help(
        "Also review files in subfolders.", "off (only the first level of each folder)", "-i D:\\evidence --recursive"
    ),
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
        "Folder where logs/ and reports/ are created. Created if missing.", "./rakvor-out", "--out E:\\case-014\\rv-hashinv"
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
    help=_opt_help(
        "Name of the examiner, written in every audit entry and report.", "the operating-system user name", '--actor "Ana Ruiz"'
    ),
)
@click.option(
    "-c",
    "--case",
    "case_id",
    metavar="ID",
    help=_opt_help("Case or engagement identifier printed on the reports.", "none", "--case CASE-2026-014"),
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
@click.pass_context
def scan(ctx, inputs, input_list, recursive, hashes, out, lang, actor, case_id, progress_mode) -> None:
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
    if not inputs and not input_list:
        _usage("no input given: use --input FILE|FOLDER or --input-list FILE")

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
                f"  report: {s.report_dir / f'statistics.{langs[0]}.html'}\n  logs:   {s.log_dir}"
            )
        except OSError:
            pass
    ctx.exit(EXIT_CANCELLED if s.cancelled else EXIT_FINDINGS if s.high else EXIT_OK)


@cli.command(
    "verify-log",
    short_help="Verify that an audit log has not been edited, truncated or re-ordered.",
    epilog="\b\nEXAMPLES:\n  rv-hashinv verify-log rakvor-out/logs/20261019T101500Z-a1b2c3/audit.jsonl\n"
    "  rv-hashinv verify-log rakvor-out/logs/20261019T101500Z-a1b2c3\n\n\b\nEXIT CODES:\n"
    "  0  The chain is intact.\n  1  The log cannot be read.\n"
    "  3  The chain is broken: at least one entry was edited, deleted or re-ordered.",
)
@click.argument("log", type=click.Path(path_type=Path), metavar="LOG")
@click.pass_context
def verify_log(ctx, log: Path) -> None:
    """Verify that an audit log (audit.jsonl) has not been edited, truncated or re-ordered.

    LOG is the path to audit.jsonl, or to the run's log folder that contains it.
    Example: rakvor-out/logs/20261019T101500Z-a1b2c3
    """
    path = log / "audit.jsonl" if log.is_dir() else log
    try:
        n, problems = verify(path)
    except OSError as e:
        click.echo(f"error: cannot open {path}: {e}", err=True)
        ctx.exit(EXIT_ERROR)
    if not problems:
        click.echo(f"OK  {n} entries, chain intact: {path}")
        ctx.exit(EXIT_OK)
    click.echo(f"BROKEN  {path}")
    for p in problems:
        click.echo(f"  - {p}")
    ctx.exit(EXIT_FINDINGS)


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
        "# Command-line reference\n\n"
        "<!-- Generated by `rv-hashinv docs-cli`. Do not edit by hand: CI fails if this file differs. -->\n\n",
        "```mermaid\nflowchart LR\n  A[rv-hashinv] --> B[scan]\n  A --> C[verify-log]\n  A --> D[self-test]\n"
        "  B --> E[(logs/RUN-ID)]\n  B --> F[(reports/RUN-ID)]\n  C --> E\n```\n\n",
    ]
    root = click.Context(cli, info_name=TOOL_NAME, **{k: v for k, v in CONTEXT.items() if k != "help_option_names"})
    out.append(f"## rv-hashinv\n\n```text\n{cli.get_help(root).rstrip()}\n```\n\n")
    for name in ("scan", "verify-log", "self-test"):
        cmd = cli.commands[name]
        sub = click.Context(cmd, info_name=name, parent=root, **{k: v for k, v in CONTEXT.items() if k != "help_option_names"})
        out.append(f"## rv-hashinv {name}\n\n```text\n{cmd.get_help(sub).rstrip()}\n```\n\n")
    return "".join(out)


def _usage(msg: str) -> None:
    click.echo(f"error: {msg}\n\nFor more information, try 'rv-hashinv scan --help'.", err=True)
    sys.exit(EXIT_USAGE)


def main() -> None:
    cli(prog_name=TOOL_NAME)


if __name__ == "__main__":
    main()
