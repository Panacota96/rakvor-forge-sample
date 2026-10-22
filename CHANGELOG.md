# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries are generated from
[Conventional Commits](https://www.conventionalcommits.org/) by release-please and reviewed by a human.

## [Unreleased]

### Added
- `verify-log` checks truncation against the records kept outside the log: the RFC 3161 timestamp (`covers_seq`)
  and, for a run in a case folder, the audit head recorded at `run_finished` in the case log; it names the anchor
  or prints `truncation not detectable without a timestamp or case record`.
- `verify-case --rehash`: re-hashes every registered item still reachable and compares it with the registry (exit 3
  on a difference).
- Reports print the signer's certificate SHA-256 fingerprint next to the subject (`run.pdf_signer_certificate_sha256`
  in the JSON).
- `tests/golden/`: a case folder written by the other profile, verified in CI (`regenerate.py` rebuilds it).
- The trust test validates every signed PDF with pyHanko (`tests/validate_pdf_signature.py`).
- Shared case folder (`--case-dir DIR`, `--evidence E0001,…`): the run writes to `<CASE>/runs/rv-hashinv/<RUN-ID>/`,
  registers every hashed file in `evidence/registry.json` (evidence ids E0001…, intake role) and records
  `run_started` / `evidence_registered` / `run_finished` in the hash-chained `case-log.jsonl` under `case-log.lock`.
  Analysis role (for scaffolded tools, `CASE_ROLE`): verifies every item against the registry with findings
  `EVIDENCE_HASH_MISMATCH_WITH_CASE` (high) and `EVIDENCE_NOT_IN_CASE_REGISTRY` (medium). See docs/case-folder.md.
- `rv-hashinv verify-case <CASE>`: case log, registry digest, every run's audit chain and the cross-links (exit 0/3).
- Reports show the evidence id per item; custody forms use the case id and intake date; schemas for `case.json`
  and `registry.json`. GUI: "Case folder" field (output folder derived and locked) and evidence ids in the result.
- RFC 3161 trusted timestamp of the audit chain head on every run (`--tsa-url`, `--no-timestamp`); offline runs log
  `timestamp_pending` and `rv-hashinv timestamp <log folder>` adds the token later; `verify-log` checks tokens.
- PDF reports signed with the examiner's certificate (`--sign-cert`, `--sign-pass-env`); password never logged.
- Chain-of-custody form per item for Colombia (ES) or France (FR) plus English (`--jurisdiction co|fr`).
- Rakvor brand on reports, GUI and installer; GUI interface language ES/EN/FR switchable in the window.
- Code-signing step in the release workflow (runs when the signing secrets are set).

### Fixed
- `verify-log` help no longer claims it detects truncation on its own.
- Items are numbered identically in both profiles: sorted by the normalised path, bytewise (UTF-8).
- `timestamp` on a folder without `audit.jsonl` exits 3 with a clear message.
- `examples/sample/run.sh` and `run.ps1` compare the tool's `hashes.csv` with `expected_hashes.csv` and fail on a
  difference; `tests/verify_chain.py` reports a missing `hashes.csv` and still checks the chain.
- The certificate password prompt no longer echoes (rpassword).
- An `--input-list` file starting with a UTF-8 BOM is read correctly.
- The PDF signer locates its placeholder inside its own signature dictionary, never in page text.
- CI and release install the toolchain pinned in `rust-toolchain.toml` instead of `stable`.
- Item reports no longer list every duplicate partner (capped at 10), keeping 50k-file runs small.

### Documentation
- `docs/theory.md` (plain-language Part A, expert Part B with real computed values: dual hashing, magic bytes,
  duplicates, hash chain, case folder cross-links, RFC 3161 request layout, signed PDF byte range, custody forms,
  determinism), `docs/admissibility.md` (Colombia, France/EU, ISO/IEC, US/UK mapping from research pass 2, gap list G1–G26, examiner
  checklist), `docs/installation.md` (release verification, build from source for auditors) and `docs/usage.md`
  (case walkthrough from intake to `verify-case`). Domain sections are marked `<!-- forge:domain -->` for tools
  scaffolded from this template.

## [0.1.0] - 2026-10-19

### Added
- `rv-hashinv scan`: single-file, folder (bulk, `--recursive`) and list-file (`--input-list`) review.
- One or two hash algorithms per run (md5, sha1, sha256, sha512, sha3-256, blake3) computed in one read.
- File-type detection from signatures; findings EMPTY_FILE, EXTENSION_MISMATCH, EXECUTABLE_CONTENT, DUPLICATE, UNREADABLE.
- Hash-chained audit log (`audit.jsonl` + `audit.log`), `hashes.csv`, `environment.json` per run.
- Statistics report and, per item, a technical review and a customer summary in JSON, HTML and PDF (EN/ES/FR).
- `rv-hashinv verify-log` and `rv-hashinv self-test`.
- Desktop GUI for Windows 10/11 with progress, elapsed time, ETA and cancel.
- CI on Linux and Windows; release workflow with portable zip, installer, SHA256SUMS, SBOM and build provenance.

[Unreleased]: https://github.com/rakvor/rv-hashinv/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rakvor/rv-hashinv/releases/tag/v0.1.0
