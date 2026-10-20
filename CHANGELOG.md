# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries are generated from
[Conventional Commits](https://www.conventionalcommits.org/) by release-please and reviewed by a human.

## [Unreleased]

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
