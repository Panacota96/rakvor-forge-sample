# Forensic audit trail

Everything RV HashInv does is written to `<OUT>/logs/<RUN-ID>/`. The folder is designed so that a second
examiner, months later, can check **what was done, to which files, by whom, with which tool version**, and
that the record was not altered.

| File | Content |
| --- | --- |
| `audit.jsonl` | One JSON object per action, hash-chained (authoritative) |
| `audit.log` | The same actions as readable text (convenience copy) |
| `hashes.csv` | Hash register: `index,path,size,<algo1>[,<algo2>],status,error` |
| `environment.json` | Tool version, compiler, target, every dependency version, OS, host, OS user, working folder, command line |

## The hash chain

```mermaid
flowchart LR
    G["GENESIS<br/>000…000"] --> E1
    E1["#1 run_started<br/>prev = GENESIS<br/>entry_hash = H1"] --> E2
    E2["#2 environment_recorded<br/>prev = H1<br/>entry_hash = H2"] --> E3
    E3["#3 inputs_resolved<br/>prev = H2<br/>entry_hash = H3"] --> EN["… #N run_finished"]
```

Each entry has: `seq`, `ts_utc`, `run_id`, `actor`, `action`, optional `item`, `details`,
`prev_entry_hash`, `entry_hash`.

```text
entry_hash = SHA-256( canonical JSON of the entry without "entry_hash" )
canonical  = keys sorted at every level, no spaces, UTF-8, integers only
             (Python: json.dumps(e, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
```

Editing a value changes that entry's hash; deleting or re-ordering breaks `seq` and `prev_entry_hash`.
Verify with either implementation:

```bash
rv-hashinv verify-log rakvor-out/logs/<RUN-ID>          # exit 0 intact, 3 broken
python tests/verify_chain.py rakvor-out/logs/<RUN-ID>   # independent re-implementation
```

> The chain proves the log is **internally consistent**. On its own it does not prove *when* it was written —
> that is what the trusted timestamp below adds. Storing the final `entry_hash` (printed in the statistics report)
> in your case management system remains good practice.

## Trusted timestamp (RFC 3161)

Every run asks a Time-Stamp Authority (TSA) to sign the chain head **just before the statistics report** is
written, so the report can show the result. Default TSA: `http://timestamp.digicert.com` (`--tsa-url` to change).

```mermaid
sequenceDiagram
    participant T as rv-hashinv
    participant L as audit.jsonl
    participant A as TSA (RFC 3161)
    T->>L: … item_reports_written (entry #N)
    T->>A: SHA-256 of entry #N hash + nonce
    alt reachable
        A-->>T: signed token (genTime)
        T->>L: timestamp_obtained (covers_seq N, gen_time, tsa, token_sha256)
    else offline
        T->>L: timestamp_pending (reason) — warning on the statistics report
        Note over T: later: rv-hashinv timestamp logs/RUN-ID
    end
    T->>L: statistics_report_written · run_finished
```

- The token is stored next to the log: `timestamp-<N>.tsr` (DER) and `timestamp-<N>.json` (readable summary).
- Offline or air-gapped: the run still completes. When the network is back, `rv-hashinv timestamp <log folder>`
  re-verifies the chain and appends `timestamp_obtained` — earlier entries are never rewritten.
- `verify-log` checks each token: imprint = stored head, and entry `#N` still has that hash.
- Independent check: `openssl ts -verify -digest <head> -in timestamp-<N>.tsr -CAfile <TSA chain>`.
- `--no-timestamp` (or `RV_NO_TIMESTAMP=1`) disables it; tests use a local TSA (`tests/fake_tsa.py`).
- **Limitation:** a timestamp proves the log existed at that time, not that its content is true.

## Signed PDF reports

`--sign-cert examiner.p12` (GUI: *4. Trust → Certificate*) signs every PDF — statistics, technical, summary and
custody — with **your own** certificate. The password comes from the environment variable named by
`--sign-pass-env` (default `RV_SIGN_PASSWORD`) or an interactive prompt; it is never written to any log.
The log records `signing_certificate_loaded` with the certificate subject and SHA-256 fingerprint; a wrong password
stops the run (`run_failed`, exit 1) before any evidence is read. HTML and JSON reports are not signed: their
digests are in the audit chain, which is timestamped.

## Chain-of-custody form per item

`--jurisdiction co` (default) writes, for each item, a Colombian *registro de cadena de custodia* in Spanish
(fields of the Fiscalía manual, Ley 906 de 2004); `--jurisdiction fr` a French *fiche de scellé / suivi* in French
(Code de procédure pénale art. 156 ff.). An English version is always added. The form is pre-filled from the run
(case, item, size, both digests, UTC times, tool, examiner, audit entries) and leaves signature lines for the
physical transfers. This is a working aid, not legal advice: check it against the current official form.

## Actions recorded

| Action | When | Key details |
| --- | --- | --- |
| `run_started` | first | tool, version, frontend, algorithms, langs, inputs, case |
| `ui_*` | GUI only, before the run | input added/removed, hash selection, language, recursive, start clicked |
| `environment_recorded` | | digests of `environment.json` |
| `inputs_resolved` | | number of items and bytes |
| `item_started` | each item | index, size, modified time |
| `item_hashed` | each item | digests, bytes read, `mtime_unchanged` |
| `item_error` | unreadable item | error message |
| `item_analyzed` | each item | detected type, extension, findings, status |
| `item_cancelled` / `run_cancelled` | on cancel | processed count |
| `duplicate_group` | after the loop | hash, item indexes |
| `hash_register_written` | | digests of `hashes.csv` |
| `item_reports_written` | each item | digests of every report file |
| `statistics_report_written` | | digests of statistics files |
| `run_finished` / `run_failed` | last | totals, severities, elapsed |

## Evidence handling

```mermaid
flowchart LR
    O[("Original media")] -->|write blocker + imaging tool| C[("Verified working copy")]
    C -->|read-only open| T["RV HashInv"]
    T --> L["logs/"]
    T --> R["reports/"]
    L & R --> K["Case file<br/>(keep together)"]
```

- Files are opened with read-only access; modification times are compared before and after hashing
  (`mtime_unchanged` in `item_hashed`).
- Symbolic links are never followed (no escape outside the selected folders).
- The tool does not replace imaging tools or write blockers: run it on a verified copy.

## Mapping to ISO/IEC 27037:2012

| 27037 principle / activity | How RV HashInv supports it |
| --- | --- |
| Auditability (5.3.3) | Every action logged with actor, UTC time and chain hash |
| Repeatability (5.3.3) | `environment.json` records exact tool and dependency versions; same input → same hashes |
| Reproducibility | Independent verifier (`tests/verify_chain.py`) and standard algorithms |
| Justifiability | Every finding states what it shows and what it does **not** prove; limitations in every report |
| Preservation (7.1.4) | Read-only access; hashes of every file and of every report produced |
| Documentation / chain of custody | Hash register, reports, and log folder form the record of the examination |

Colombian practice (Ley 906 de 2004, Manual de cadena de custodia) and French practice (Code de procédure
pénale, art. 156 ff. for expertise) both expect the examiner to document the method and preserve integrity;
the log folder plus the reports are that documentation for this step of the examination.
