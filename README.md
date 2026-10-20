# RV HashInv

<!-- forge:description -->
**Evidence inventory for digital forensics.** RV HashInv hashes every file you give it (one file, a folder
or a list), detects each file's real type, flags anomalies, and writes court-ready reports — with every
action recorded in a tamper-evident audit log.
<!-- /forge:description -->

[![CI](https://github.com/rakvor/rv-hashinv/actions/workflows/ci.yml/badge.svg)](https://github.com/rakvor/rv-hashinv/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Windows 10/11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6)

```mermaid
flowchart LR
    A[/"File, folder<br/>or list"/] --> B["Hash<br/>1–2 algorithms, one read"]
    B --> C["Detect real type<br/>(signatures)"]
    C --> D["Findings<br/>mismatch · executable · empty · duplicate"]
    D --> E[["Reports<br/>statistics + per item"]]
    B -.-> L[("Audit log<br/>hash-chained")]
    C -.-> L
    D -.-> L
    E -.-> L
```

## Contents

- [What you get](#what-you-get)
- [Install](#install)
- [Quick start](#quick-start)
- [Outputs](#outputs)
- [Documentation](#documentation)
- [Project layout](#project-layout)
- [Contributing, security, licence](#contributing-security-licence)

## What you get

| | |
| --- | --- |
| **Two ways to use it** | `rv-hashinv` (command line) and `rv-hashinv-gui` (Windows 10/11 desktop app). Same engine, same results. |
| **Single or bulk** | One file, many files, whole folders (`--recursive`) or a list file (`--input-list`). |
| **Hashing** | Choose 1 or 2 of md5, sha1, sha256, sha512, sha3-256, blake3. Both are computed in the same read. |
| **Progress** | Progress bar, elapsed time, throughput and estimated time remaining (CLI and GUI). Cancel at any time. |
| **Auditable** | Every action goes to `logs/<RUN-ID>/audit.jsonl`, where each entry carries the hash of the previous one. `verify-log` detects any edit. |
| **Reports** | A statistics report per run, and for **each file** a technical review and a customer summary — HTML, PDF and JSON, in English, Spanish or French. |

## Install

**Windows 10/11** — download from the [Releases](https://github.com/rakvor/rv-hashinv/releases) page:

- `rv-hashinv-<version>-windows-x64-setup.exe` — installer (Start-menu shortcut, adds the CLI to PATH), or
- `rv-hashinv-<version>-windows-x64.zip` — portable: unzip and run, nothing is installed.

Check the download before use (see [SECURITY.md](SECURITY.md#verifying-a-release)).

**From source** (any OS, Rust 1.85+):

```bash
cargo build --release
# binaries: target/release/rv-hashinv and target/release/rv-hashinv-gui
```

## Quick start

```powershell
# Check the build first: every algorithm against published test vectors
rv-hashinv self-test

# Review a folder with SHA-256 + MD5, reports in Spanish, for case CASE-2026-014
rv-hashinv scan -i D:\evidence -r --hash sha256,md5 --lang es --case CASE-2026-014 --actor "Ana Ruiz"

# French case: custody form in French + English, every PDF signed with your certificate
$env:RV_SIGN_PASSWORD = Read-Host -AsSecureString | ConvertFrom-SecureString -AsPlainText
rv-hashinv scan -i D:\evidence -r --jurisdiction fr --sign-cert C:\certs\examiner.p12 --lang fr

# Later, prove the log was not altered (also checks the RFC 3161 timestamp)
rv-hashinv verify-log rakvor-out\logs\<RUN-ID>

# The run was offline? Add the trusted timestamp once the network is back
rv-hashinv timestamp rakvor-out\logs\<RUN-ID>
```

Every option, example and exit code: [docs/usage-cli.md](docs/usage-cli.md) (generated from `--help`).
The desktop app: [docs/usage-gui.md](docs/usage-gui.md). A ready-made sample: [examples/](examples/README.md).

## Outputs

```mermaid
flowchart TB
    OUT["&lt;OUT&gt;/"] --> LOGS["logs/&lt;RUN-ID&gt;/"]
    OUT --> REP["reports/&lt;RUN-ID&gt;/"]
    LOGS --> L1["audit.jsonl — chained actions"]
    LOGS --> L2["audit.log — same, readable"]
    LOGS --> L3["hashes.csv — hash register"]
    LOGS --> L4["environment.json — versions, OS, host"]
    REP --> R1["statistics.json / .LANG.html / .LANG.pdf"]
    REP --> IT["items/NNNNN-name/"]
    IT --> T["technical.json / .LANG.html / .LANG.pdf"]
    IT --> S["summary.json / .LANG.html / .LANG.pdf"]
    IT --> K["custody.json / custody.es|fr + .en .html/.pdf"]
    LOGS --> L5["timestamp-N.tsr — RFC 3161 token"]
```

| Exit code | Meaning |
| :-: | --- |
| 0 | Completed, no high-severity finding |
| 1 | Runtime error |
| 2 | Usage error (e.g. three hash algorithms) |
| 3 | Completed with high-severity findings / broken audit chain |
| 130 | Cancelled (partial reports written) |

## Documentation

| Page | For |
| --- | --- |
| [docs/usage-cli.md](docs/usage-cli.md) | Every command and option (generated from `--help`) |
| [docs/usage-gui.md](docs/usage-gui.md) | Using the desktop app |
| [docs/architecture.md](docs/architecture.md) | How the engine, CLI and GUI fit together |
| [docs/forensic-audit.md](docs/forensic-audit.md) | Audit trail, hash chain, evidence handling, ISO/IEC 27037 mapping |
| [docs/reports.md](docs/reports.md) | Report kinds, fields, JSON schemas, languages |
| [docs/development.md](docs/development.md) | Building, testing, CI/CD and releasing |
| [docs/adr/](docs/adr/) | Architecture decisions (e.g. why Rust) |

## Project layout

```text
rv-hashinv/
├── src/
│   ├── core/      engine library: input, hashing, analysis, audit log, reports (never prints)
│   ├── cli/       rv-hashinv command line (clap)
│   └── gui/       rv-hashinv-gui desktop app (egui); state.rs holds all testable rules
├── templates/     HTML report templates + CSS (Jinja2/minijinja compatible)
├── i18n/          report wording: en.json, es.json, fr.json
├── schemas/       JSON Schemas of the three report kinds
├── docs/          documentation (Mermaid diagrams render on GitHub)
├── tests/         cross-language checks (Python verifier of the audit chain)
├── examples/      sample evidence + run scripts + expected hashes
├── packaging/     Windows installer (Inno Setup)
└── .github/       CI and release workflows
```

## Contributing, security, licence

- How to contribute: [CONTRIBUTING.md](CONTRIBUTING.md) · Changes: [CHANGELOG.md](CHANGELOG.md)
- Report a vulnerability privately: [SECURITY.md](SECURITY.md)
- Licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE).
