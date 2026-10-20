# Development, CI/CD and releases

## Build and test locally

```bash
uv sync --extra gui                         # .venv from uv.lock (hashes pinned)
uv run pytest                               # core, CLI (subprocess), GUI state, GUI window (offscreen)
uv run ruff format --check src tests && uv run ruff check src tests
uv run rv-hashinv scan -i examples/sample/evidence --lang all
uv run rv-hashinv-gui
```

GUI tests set `QT_QPA_PLATFORM=offscreen` (see `tests/conftest.py`), so they run in CI without a display.

## Test pyramid

```mermaid
flowchart BT
    U["Unit tests (core)<br/>known-answer hashes · chain tamper · i18n keys · inputs · analyzer"] --> I
    I["CLI tests (subprocess)<br/>help sections · exit codes · bulk run · verify-log · evidence untouched · docs drift"] --> G
    G["GUI tests<br/>state rules without Qt · real window offscreen: add, pick 2 hashes, run, open report"] --> X
    X["Standalone checks<br/>tests/verify_chain.py · tests/validate_reports.py (JSON Schemas)"] --> M
    M["Manual release check<br/>Windows 10 VM + Windows 11: install, GUI run, open report"]
```

## Continuous integration

```mermaid
flowchart LR
    PR["Push / PR"] --> L["lint<br/>ruff format · ruff check · actionlint"]
    L --> T1["test ubuntu-latest<br/>py 3.11 + 3.13"]
    L --> T2["test windows-latest<br/>py 3.13"]
    T1 --> X["sample run → verify_chain.py · validate_reports.py"]
    T2 --> B["Nuitka build smoke test"]
```

## Freezing for Windows (Nuitka)

`packaging/build_windows.py` compiles both entry points with Nuitka in **standalone** (folder) mode:

| Output | Why |
| --- | --- |
| `dist/rv-hashinv/rv-hashinv.exe` (console) and `rv-hashinv-gui.exe` (no console) | One folder, shared runtime |
| Standalone, not onefile | Onefile unpacks to `%TEMP%` at every start: slower and a classic antivirus false positive |
| PySide6 as separate DLLs | LGPL-3.0 compliance: users can replace the Qt libraries |

## Releasing

```mermaid
sequenceDiagram
    participant Dev
    participant RP as release-please
    participant GH as GitHub
    participant W as release.yml (windows-latest)
    Dev->>GH: merge Conventional Commits to main
    RP->>GH: opens "chore(main): release x.y.z" PR (CHANGELOG + version)
    Dev->>GH: review & merge release PR
    RP->>GH: tag vX.Y.Z + GitHub Release
    GH->>W: build with Nuitka, self-test, sample run
    W->>W: portable zip + Inno Setup installer
    W->>W: SHA256SUMS + CycloneDX SBOM (from uv.lock)
    W->>GH: build-provenance attestation, upload assets
```

> One-time repository setting for release-please: *Settings → Actions → General → Workflow permissions →
> Allow GitHub Actions to create and approve pull requests*.

### Code signing

| Option | Notes |
| --- | --- |
| Azure Artifact Signing (Trusted Signing) | Low cost, GitHub Actions integration; eligible for the French entity, not currently for the Colombian one. |
| OV code-signing certificate (HSM/cloud key) | Works for either entity. |

### Release checklist (manual)

- [ ] `rv-hashinv self-test` on the released exe passes on Windows 10 **and** Windows 11
- [ ] GUI opens, runs the sample, *Open report* works
- [ ] `SHA256SUMS` matches; `gh attestation verify` passes
- [ ] CHANGELOG entry reviewed by a human
