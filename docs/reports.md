# Reports

Every run produces one **statistics report**. Every reviewed file produces **two separate reviews**:
a hyper-detailed **technical review** for examiners and lawyers, and a concise **customer summary** in plain
language. Each exists as JSON (machine-readable, language-neutral) plus HTML and PDF in each selected language.

```mermaid
flowchart TB
    RUN["Run"] --> S["statistics.json<br/>statistics.LANG.html · .pdf"]
    RUN --> I1["items/00001-acta.txt/"]
    RUN --> I2["items/00002-…/"]
    I1 --> T1["technical.json<br/>technical.LANG.html · .pdf"]
    I1 --> C1["summary.json<br/>summary.LANG.html · .pdf"]
```

## What each report contains

| Section | Statistics | Technical review | Customer summary |
| --- | :-: | :-: | :-: |
| Run ID, case, examiner, start/end, duration, interface | ✔ | ✔ (run ID, case) | case, date |
| Hash algorithms, totals, throughput | ✔ | | |
| Findings by severity and type, items by detected type | ✔ | | |
| Duplicate groups | ✔ | as finding | as finding |
| Full path, size, modified time, extension, detected type | | ✔ | file name |
| All digests | | ✔ | primary only ("digital fingerprint") |
| Findings with **what it shows / what it does not prove** | | ✔ | plain sentence |
| Method | | ✔ | "What we did" |
| Audit entries covering the item | | ✔ (`#first – #last`) | |
| Limitations | ✔ | ✔ | |
| Status and next step | | ✔ | ✔ |

## Status and severity

```mermaid
pie showData
    title Example run: findings by severity
    "High" : 1
    "Medium" : 3
    "Informational" : 6
```

| Severity | Examples | Item status |
| --- | --- | --- |
| High | UNREADABLE, EXECUTABLE_CONTENT | `problem` (exit code 3) |
| Medium | EXTENSION_MISMATCH | `attention` |
| Low | — | `attention` |
| Informational | EMPTY_FILE, DUPLICATE | `ok` |

## Findings catalogue

| Code | Shows | Does not prove |
| --- | --- | --- |
| `EMPTY_FILE` | The file has 0 bytes | Whether it was emptied on purpose |
| `EXTENSION_MISMATCH` | Name and content signature disagree | Intent to hide anything |
| `EXECUTABLE_CONTENT` | A program is stored under a non-program name | That the program is malicious |
| `DUPLICATE` | Identical content (same primary hash) in several files | Who copied it or when |
| `UNREADABLE` | Reading failed, with the OS error | That the file is damaged |

Wording lives in `i18n/en.json`, `es.json`, `fr.json` (same keys in all three — enforced by a test).

## JSON schemas

| File | `schema` value | Schema |
| --- | --- | --- |
| `statistics.json` | `rakvor.statistics/1` | [schemas/statistics.schema.json](../schemas/statistics.schema.json) |
| `technical.json` | `rakvor.item-technical/1` | [schemas/item-technical.schema.json](../schemas/item-technical.schema.json) |
| `summary.json` | `rakvor.item-summary/1` | [schemas/item-summary.schema.json](../schemas/item-summary.schema.json) |

Adding a field is a minor change; removing or renaming one bumps the `/N` version.

## PDF notes

PDFs are generated with ReportLab (A4, Helvetica/Courier), so no external program is needed on the examiner's PC.
The standard fonts cover English, Spanish and French; other scripts need an embedded TrueType font
(`reportlab.pdfbase.ttfonts`). Every report file's digest is recorded in the audit log
(`item_reports_written`, `statistics_report_written`), so a report altered after the run can be detected.
