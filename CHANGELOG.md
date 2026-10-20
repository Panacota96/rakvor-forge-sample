# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries are generated from
[Conventional Commits](https://www.conventionalcommits.org/) by release-please and reviewed by a human.

## [Unreleased]

### Added
- RFC 3161 trusted timestamp of the audit chain head on every run (`--tsa-url`, `--no-timestamp`); offline runs log
  `timestamp_pending` and `rv-hashinv timestamp <log folder>` adds the token later; `verify-log` checks tokens.
- PDF reports signed with the examiner's certificate (`--sign-cert`, `--sign-pass-env`); password never logged.
- Chain-of-custody form per item for Colombia (ES) or France (FR) plus English (`--jurisdiction co|fr`).
- Rakvor brand on reports, GUI and installer; GUI interface language ES/EN/FR switchable in the window.
- Code-signing step in the release workflow (runs when the signing secrets are set).

### Fixed
- Item reports no longer list every duplicate partner (capped at 10), keeping 50k-file runs small.

## [0.1.0] - 2026-10-19

### Added
- `rv-hashinv scan`: single-file, folder (bulk, `--recursive`) and list-file (`--input-list`) review.
- One or two hash algorithms per run (md5, sha1, sha256, sha512, sha3-256, blake3) computed in one read.
- File-type detection from signatures; findings EMPTY_FILE, EXTENSION_MISMATCH, EXECUTABLE_CONTENT, DUPLICATE, UNREADABLE.
- Hash-chained audit log (`audit.jsonl` + `audit.log`), `hashes.csv`, `environment.json` per run.
- Statistics report and, per item, a technical review and a customer summary in JSON, HTML and PDF (EN/ES/FR).
- `rv-hashinv verify-log` and `rv-hashinv self-test`.
- Desktop GUI (PySide6) for Windows 10/11 with progress, elapsed time, ETA and cancel.
- CI on Linux and Windows; release workflow with Nuitka-built portable zip, installer, SHA256SUMS, SBOM and build provenance.

[Unreleased]: https://github.com/rakvor/rv-hashinv/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rakvor/rv-hashinv/releases/tag/v0.1.0
