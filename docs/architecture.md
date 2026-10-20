# Architecture

One engine, two front-ends. The engine (`src/rv_hashinv/core`) does all the work and never prints; the CLI and
the GUI only turn user input into a `RunConfig` and render the `Event`s the engine emits. This is why
both interfaces always produce identical logs and reports.

```mermaid
flowchart TB
    subgraph Front-ends
        CLI["rv-hashinv (cli.py)<br/>click · rich"]
        GUI["rv-hashinv-gui (gui/)<br/>PySide6 · QThread"]
    end
    subgraph Core["rv_hashinv.core"]
        RUN["run.py<br/>pipeline"]
        IN["inputs.py"]
        H["hashing.py"]
        AN["analyzer.py<br/>(domain logic)"]
        AU["audit.py"]
        REP["report.py<br/>JSON · Jinja2 HTML · ReportLab PDF"]
        I18N["i18n.py"]
    end
    CLI -- RunConfig --> RUN
    GUI -- "RunConfig (+ UI actions)" --> RUN
    RUN -- "Event stream" --> CLI
    RUN -- "Event stream (Qt signal)" --> GUI
    RUN --> IN & H & AN & AU & REP
    REP --> I18N
```

## Modules

| Module | Responsibility | Replace when building a new tool? |
| --- | --- | --- |
| `inputs.py` | Files, folders, list files → sorted, de-duplicated, absolute paths. Symlinks not followed. | No |
| `hashing.py` | One read loop (1 MiB chunks) feeding 1–2 digests; known-answer self-test. | No |
| `analyzer.py` | Signature detection and per-item findings. | **Yes — this is the domain logic** |
| `audit.py` | Append-only hash-chained `audit.jsonl` + `audit.log`; `verify`. | No |
| `report.py` | View models → Jinja2 HTML, ReportLab PDF, schema-versioned JSON. | Adapt wording/fields |
| `events.py` | Event dicts (same JSON as the Rust profile); ETA computation. | No |
| `envinfo.py` | `environment.json` (versions, OS, host, user, command line). | No |
| `run.py` | Orchestration, cancellation, duplicates, `hashes.csv`. | Small changes |

## One run, step by step

```mermaid
sequenceDiagram
    autonumber
    participant UI as CLI / GUI
    participant R as run.py
    participant A as audit.jsonl
    participant FS as Evidence (read-only)
    participant O as reports/
    UI->>R: run(config, sink, cancel)
    R->>A: run_started, UI actions, environment_recorded
    R->>R: collect inputs
    R->>A: inputs_resolved
    R-->>UI: RunStarted{total_items,total_bytes}
    loop each item
        R->>A: item_started
        R->>FS: open read-only, read 1 MiB chunks
        R-->>UI: Progress{elapsed_ms, eta_ms} (≤ every 150 ms)
        R->>A: item_hashed{digests, mtime_unchanged}
        R->>A: item_analyzed{findings, status}
        R-->>UI: ItemFinished
    end
    R->>A: duplicate_group(s), hash_register_written
    R->>O: per-item technical + summary (JSON/HTML/PDF)
    R->>A: item_reports_written{file digests}
    R->>O: statistics (JSON/HTML/PDF)
    R->>A: statistics_report_written, run_finished
    R-->>UI: RunFinished
```

## Run states (as the GUI sees them)

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Running: Start (inputs ≥ 1, algorithms 1–2)
    Running --> Finished: RunFinished
    Running --> Cancelled: Cancel → partial reports
    Running --> Failed: error (e.g. output not writable)
    Finished --> Running: Start again (new run ID)
    Cancelled --> Running
    Failed --> Running
```

## Concurrency and cancellation

- The GUI runs the engine on a `QThread` and receives events as Qt signals, so the window stays
  responsive; the elapsed-time label is refreshed every 200 ms by a `QTimer`.
- Cancellation is a `threading.Event` checked after every 1 MiB chunk: large images stop within milliseconds.
  The engine still writes `hashes.csv`, partial reports and `run_cancelled` to the audit log.
- Files are processed sequentially on purpose: the order of audit entries equals the order of work, which is
  easier to explain in court. `hashlib` and `blake3` release the GIL and run at native speed; hashing is
  I/O-bound on typical evidence drives.

## Why Python

See [ADR 0001](adr/0001-language.md).
