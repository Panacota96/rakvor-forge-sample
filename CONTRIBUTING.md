# Contributing to RV HashInv

Thank you for helping. This is a forensic tool: results may be presented in court, so every change
must keep results **correct, reproducible and explainable**.

## Workflow

```mermaid
gitGraph
    commit id: "main"
    branch feat/sqlite-signature
    checkout feat/sqlite-signature
    commit id: "feat(core): detect WAL files"
    commit id: "test: WAL sample"
    checkout main
    merge feat/sqlite-signature id: "PR + green CI"
    commit id: "chore(main): release 0.2.0" tag: "v0.2.0"
```

1. Open an issue first for anything bigger than a typo.
2. Branch from `main`: `feat/…`, `fix/…`, `docs/…`.
3. Commit with [Conventional Commits](https://www.conventionalcommits.org/): `feat(core): …`, `fix(cli): …`,
   `docs: …`, `test: …`, `ci: …`. A `!` or `BREAKING CHANGE:` footer marks breaking changes. The changelog and
   version numbers are generated from these messages.
4. Open a pull request. CI must be green on Linux **and** Windows.
5. A maintainer reviews. Changes to hashing, the audit chain or report wording need two approvals.

## Before you push

```bash
uv sync --extra gui
uv run ruff format src tests && uv run ruff check src tests
uv run pytest                                          # GUI tests run offscreen
uv run rv-hashinv docs-cli > docs/usage-cli.md         # if you changed any --help text
python tests/verify_chain.py <some run>/logs/<RUN-ID>  # standalone check (stdlib + blake3)
```

## Rules that keep the tool defensible

| Area | Rule |
| --- | --- |
| Evidence | Never open evidence for writing. Never follow symbolic links. |
| Core | The core never prints. Front-ends only render events (dicts with an `event` key). |
| Hashing | Any change needs known-answer tests (`hashing.KNOWN_ANSWERS`). |
| Audit | Do not change the chain algorithm without bumping the log format and keeping `verify-log` able to read old logs. |
| Findings | Every finding has `shows` **and** `does_not_prove` wording in **all three** languages (`i18n/*.json`; a test checks the keys match). |
| Reports | Adding a field to a JSON report: update `schemas/` and `docs/reports.md`. Removing one is a breaking change. |
| Docs | Each page under `docs/` keeps at least one Mermaid diagram that renders on GitHub. |
| Dependencies | New packages need a reason in the PR, an Apache-2.0-compatible licence, and `uv lock`. PySide6 is LGPL: ship it as separate DLLs (Nuitka standalone does), never statically. |

## Adding a new finding

```mermaid
sequenceDiagram
    participant Dev
    participant analyzer as core/analyzer.py
    participant i18n as i18n/*.json
    participant tests
    Dev->>analyzer: append Finding("CODE", severity, params)
    Dev->>i18n: title / shows / does_not_prove in en, es, fr
    Dev->>tests: unit test in analyzer + CLI test if exit code changes
    Dev->>Dev: CHANGELOG via commit message, docs/reports.md table
```

## Code of conduct

Be respectful and precise. Assume good faith. Harassment is not tolerated.
