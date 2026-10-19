//! The pipeline both front-ends call: intake → hash + analyze each item → duplicates →
//! hashes.csv → per-item reports → statistics report. Every step is written to the audit log.

use crate::analyzer::{Finding, Severity, analyze};
use crate::audit::AuditLog;
use crate::events::{Event, eta_ms};
use crate::hash::{HashAlgo, hash_bytes, hash_reader, validate_selection};
use crate::input::collect;
use crate::report::{self, AuditRef, ItemResult, RunInfo, RunTotals};
use crate::time::{utc_compact, utc_from, utc_now};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct RunConfig {
    pub inputs: Vec<PathBuf>,
    pub input_list: Option<PathBuf>,
    pub recursive: bool,
    pub algorithms: Vec<HashAlgo>,
    pub out_dir: PathBuf,
    pub langs: Vec<String>,
    pub actor: String,
    pub case_id: Option<String>,
    /// "cli" or "gui"
    pub frontend: String,
    /// Front-end actions to audit before the run starts (e.g. GUI setting changes): (action, details).
    pub preamble: Vec<(String, Value)>,
    /// Command line (CLI) or equivalent settings (GUI), stored in environment.json.
    pub command_line: Vec<String>,
    pub tool_name: String,
    pub tool_version: String,
}

#[derive(Clone, Debug, Default)]
pub struct RunSummary {
    pub run_id: String,
    pub items: u64,
    pub bytes: u64,
    pub errors: u64,
    pub elapsed_ms: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub info: u64,
    pub cancelled: bool,
    pub report_dir: PathBuf,
    pub log_dir: PathBuf,
    pub audit_head: String,
}

const PROGRESS_EVERY: Duration = Duration::from_millis(150);

fn new_run_id() -> String {
    let seed = format!(
        "{:?}-{}-{}",
        std::time::SystemTime::now(),
        std::process::id(),
        crate::env::hostname()
    );
    format!(
        "{}-{}",
        utc_compact(),
        &hash_bytes(seed.as_bytes(), HashAlgo::Sha256)[..6]
    )
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Runs the whole pipeline. Events go to `sink`; set `cancel` to stop after the current chunk
/// (partial reports are still written and the cancellation is audited).
pub fn run(
    cfg: &RunConfig,
    sink: &mut dyn FnMut(&Event),
    cancel: &AtomicBool,
) -> Result<RunSummary, String> {
    validate_selection(&cfg.algorithms)?;
    if cfg.langs.is_empty() {
        return Err("select at least one report language".into());
    }
    let started = Instant::now();
    let started_utc = utc_now();
    let run_id = new_run_id();
    let log_dir = cfg.out_dir.join("logs").join(&run_id);
    let report_dir = cfg.out_dir.join("reports").join(&run_id);
    let mut log = AuditLog::create(&log_dir, &run_id, &cfg.actor)
        .map_err(|e| format!("cannot create audit log in {}: {}", log_dir.display(), e))?;
    let io = |e: std::io::Error| format!("audit log write failed: {}", e);

    log.record(
        "run_started",
        None,
        json!({
            "tool": cfg.tool_name, "version": cfg.tool_version, "frontend": cfg.frontend,
            "algorithms": cfg.algorithms, "langs": cfg.langs, "case_id": cfg.case_id,
            "inputs": cfg.inputs.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "input_list": cfg.input_list.as_ref().map(|p| p.display().to_string()),
            "recursive": cfg.recursive, "out_dir": cfg.out_dir.display().to_string(),
        }),
    )
    .map_err(io)?;
    for (action, details) in &cfg.preamble {
        log.record(action, None, details.clone()).map_err(io)?;
    }

    let env_json = report::pretty(&crate::env::describe(
        &cfg.tool_name,
        &cfg.tool_version,
        &cfg.frontend,
        &cfg.command_line,
    ));
    let (_, env_digest) =
        report::write_hashed(&log_dir, "environment.json", &env_json, &cfg.algorithms)?;
    log.record("environment_recorded", Some("environment.json"), env_digest)
        .map_err(io)?;

    let items = match collect(&cfg.inputs, cfg.input_list.as_deref(), cfg.recursive) {
        Ok(i) => i,
        Err(e) => {
            log.record("error", None, json!({"stage": "input", "message": e}))
                .map_err(io)?;
            log.record("run_failed", None, json!({"reason": e}))
                .map_err(io)?;
            return Err(e);
        }
    };
    let total_items = items.len() as u64;
    let total_bytes: u64 = items.iter().map(|i| i.size).sum();
    log.record(
        "inputs_resolved",
        None,
        json!({"items": total_items, "bytes": total_bytes}),
    )
    .map_err(io)?;
    sink(&Event::RunStarted {
        run_id: run_id.clone(),
        tool: cfg.tool_name.clone(),
        version: cfg.tool_version.clone(),
        frontend: cfg.frontend.clone(),
        algorithms: cfg.algorithms.clone(),
        langs: cfg.langs.clone(),
        total_items,
        total_bytes,
    });

    let mut results: Vec<ItemResult> = Vec::with_capacity(items.len());
    let mut bytes_before = 0u64;
    let mut errors = 0u64;
    let mut cancelled = false;
    let mut last_progress = Instant::now() - PROGRESS_EVERY;

    for item in &items {
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }
        let path_s = item.path.display().to_string();
        let modified = std::fs::metadata(&item.path)
            .and_then(|m| m.modified())
            .ok();
        let modified_utc = modified.map(utc_from);
        sink(&Event::ItemStarted {
            index: item.index,
            path: path_s.clone(),
            size: item.size,
        });
        let first_seq = log
            .record(
                "item_started",
                Some(&path_s),
                json!({"index": item.index, "size": item.size, "modified_utc": modified_utc}),
            )
            .map_err(io)?;

        let mut on_chunk = |n: u64| {
            if last_progress.elapsed() >= PROGRESS_EVERY {
                last_progress = Instant::now();
                let elapsed = started.elapsed().as_millis() as u64;
                let done_bytes = bytes_before + n;
                sink(&Event::Progress {
                    done: item.index - 1,
                    total: total_items,
                    bytes_done: done_bytes,
                    bytes_total: total_bytes,
                    elapsed_ms: elapsed,
                    eta_ms: eta_ms(elapsed, done_bytes, total_bytes),
                });
            }
            !cancel.load(Ordering::Relaxed)
        };
        // File::open is read-only: the evidence is never opened for writing.
        let outcome = std::fs::File::open(&item.path)
            .and_then(|f| hash_reader(f, &cfg.algorithms, &mut on_chunk));
        let mut result = ItemResult {
            index: item.index,
            path: item.path.clone(),
            size: item.size,
            modified_utc,
            hashes: vec![],
            detected_type: None,
            extension: None,
            findings: vec![],
            error: None,
            audit_first_seq: first_seq,
            audit_last_seq: first_seq,
        };
        match outcome {
            Ok(None) => {
                log.record(
                    "item_cancelled",
                    Some(&path_s),
                    json!({"index": item.index}),
                )
                .map_err(io)?;
                cancelled = true;
                break;
            }
            Ok(Some(out)) => {
                let after = std::fs::metadata(&item.path)
                    .and_then(|m| m.modified())
                    .ok();
                let hashes: BTreeMap<String, String> = out
                    .digests
                    .iter()
                    .map(|(a, h)| (a.name().to_string(), h.clone()))
                    .collect();
                log.record("item_hashed", Some(&path_s), json!({"index": item.index, "bytes_read": out.bytes, "hashes": hashes, "mtime_unchanged": modified == after})).map_err(io)?;
                sink(&Event::ItemHashed {
                    index: item.index,
                    path: path_s.clone(),
                    hashes,
                });
                let a = analyze(&result.file_name(), out.bytes, &out.head);
                result.size = out.bytes;
                result.hashes = out.digests;
                result.detected_type = a.detected_type;
                result.extension = a.extension;
                result.findings = a.findings;
            }
            Err(e) => {
                errors += 1;
                result.error = Some(e.to_string());
                result
                    .findings
                    .push(Finding::new("UNREADABLE", Severity::High).with("error", e.to_string()));
                sink(&Event::Error {
                    path: Some(path_s.clone()),
                    message: e.to_string(),
                });
                log.record(
                    "item_error",
                    Some(&path_s),
                    json!({"index": item.index, "message": e.to_string()}),
                )
                .map_err(io)?;
            }
        }
        let codes: Vec<String> = result.findings.iter().map(|f| f.code.clone()).collect();
        result.audit_last_seq = log.record("item_analyzed", Some(&path_s), json!({"index": item.index, "detected_type": result.detected_type, "extension": result.extension, "findings": result.findings, "status": result.status()})).map_err(io)?;
        sink(&Event::ItemFinished {
            index: item.index,
            path: path_s,
            status: result.status().into(),
            findings: codes,
        });
        bytes_before += item.size;
        let elapsed = started.elapsed().as_millis() as u64;
        sink(&Event::Progress {
            done: item.index,
            total: total_items,
            bytes_done: bytes_before,
            bytes_total: total_bytes,
            elapsed_ms: elapsed,
            eta_ms: eta_ms(elapsed, bytes_before, total_bytes),
        });
        results.push(result);
    }
    if cancelled {
        log.record(
            "run_cancelled",
            None,
            json!({"processed": results.len(), "of": total_items}),
        )
        .map_err(io)?;
        sink(&Event::Cancelled {
            done: results.len() as u64,
            elapsed_ms: started.elapsed().as_millis() as u64,
        });
    }

    // Duplicates (cross-item finding).
    let primary = cfg.algorithms[0];
    for (hash, idx) in report::duplicate_groups(&results) {
        let names: Vec<String> = idx.iter().map(|&i| results[i].file_name()).collect();
        log.record("duplicate_group", None, json!({"algorithm": primary, "hash": hash, "items": idx.iter().map(|&i| results[i].index).collect::<Vec<_>>()})).map_err(io)?;
        for &i in &idx {
            let others: Vec<String> = names
                .iter()
                .enumerate()
                .filter(|(j, _)| idx[*j] != i)
                .map(|(_, n)| n.clone())
                .collect();
            results[i].findings.push(
                Finding::new("DUPLICATE", Severity::Info)
                    .with("algorithm", primary.name())
                    .with("count", idx.len().to_string())
                    .with("others", others.join(", ")),
            );
        }
    }

    // hashes.csv: the hash register of every reviewed file.
    let mut csv = format!(
        "index,path,size,{},status,error\n",
        cfg.algorithms
            .iter()
            .map(|a| a.name())
            .collect::<Vec<_>>()
            .join(",")
    );
    for r in &results {
        let hashes: Vec<String> = cfg
            .algorithms
            .iter()
            .map(|a| {
                r.hashes
                    .iter()
                    .find(|(x, _)| x == a)
                    .map(|(_, h)| h.clone())
                    .unwrap_or_default()
            })
            .collect();
        csv.push_str(&format!(
            "{},{},{},{},{},{}\n",
            r.index,
            csv_field(&r.path.display().to_string()),
            r.size,
            hashes.join(","),
            r.status(),
            csv_field(r.error.as_deref().unwrap_or(""))
        ));
    }
    let (_, csv_digest) =
        report::write_hashed(&log_dir, "hashes.csv", csv.as_bytes(), &cfg.algorithms)?;
    log.record("hash_register_written", Some("hashes.csv"), csv_digest)
        .map_err(io)?;

    // Reports.
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let info = RunInfo {
        tool_name: cfg.tool_name.clone(),
        tool_version: cfg.tool_version.clone(),
        run_id: run_id.clone(),
        case_id: cfg.case_id.clone(),
        actor: cfg.actor.clone(),
        frontend: cfg.frontend.clone(),
        algorithms: cfg.algorithms.clone(),
        langs: cfg.langs.clone(),
        started_utc,
        finished_utc: utc_now(),
        elapsed_ms,
        cancelled,
    };
    let log_dir_s = log_dir.display().to_string();
    for r in &results {
        let audit = AuditRef {
            head: log.head().to_string(),
            entries: log.entries(),
            log_dir: log_dir_s.clone(),
        };
        let dir = report_dir.join("items").join(r.folder());
        let files = report::write_item_reports(&dir, &info, r, &audit)?;
        log.record(
            "item_reports_written",
            Some(&r.path.display().to_string()),
            json!({"folder": format!("items/{}", r.folder()), "files": files}),
        )
        .map_err(io)?;
    }
    if !results.is_empty() {
        sink(&Event::ReportWritten {
            kind: "items".into(),
            path: report_dir.join("items").display().to_string(),
        });
    }
    let totals = RunTotals {
        items: results.len() as u64,
        bytes: results.iter().map(|r| r.size).sum(),
        errors,
    };
    let audit = AuditRef {
        head: log.head().to_string(),
        entries: log.entries(),
        log_dir: log_dir_s,
    };
    let files = report::write_statistics(&report_dir, &info, &results, &totals, &audit)?;
    log.record("statistics_report_written", None, json!({"files": files}))
        .map_err(io)?;
    let main_report = report_dir.join(format!("statistics.{}.html", cfg.langs[0]));
    sink(&Event::ReportWritten {
        kind: "statistics".into(),
        path: main_report.display().to_string(),
    });

    let mut sev: BTreeMap<Severity, u64> = BTreeMap::new();
    for f in results.iter().flat_map(|r| &r.findings) {
        *sev.entry(f.severity).or_default() += 1;
    }
    let summary = RunSummary {
        run_id,
        items: totals.items,
        bytes: totals.bytes,
        errors,
        elapsed_ms: started.elapsed().as_millis() as u64,
        high: sev.get(&Severity::High).copied().unwrap_or(0),
        medium: sev.get(&Severity::Medium).copied().unwrap_or(0),
        low: sev.get(&Severity::Low).copied().unwrap_or(0),
        info: sev.get(&Severity::Info).copied().unwrap_or(0),
        cancelled,
        report_dir: report_dir.clone(),
        log_dir: log_dir.clone(),
        audit_head: String::new(),
    };
    log.record("run_finished", None, json!({"items": summary.items, "bytes": summary.bytes, "errors": errors, "elapsed_ms": summary.elapsed_ms, "high": summary.high, "medium": summary.medium, "low": summary.low, "info": summary.info, "cancelled": cancelled})).map_err(io)?;
    sink(&Event::RunFinished {
        items: summary.items,
        bytes: summary.bytes,
        errors,
        elapsed_ms: summary.elapsed_ms,
        high: summary.high,
        medium: summary.medium,
        low: summary.low,
        info: summary.info,
        report_dir: report_dir.display().to_string(),
        log_dir: log_dir.display().to_string(),
        cancelled,
    });
    Ok(RunSummary {
        audit_head: log.head().to_string(),
        ..summary
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(input: PathBuf, out: PathBuf) -> RunConfig {
        RunConfig {
            inputs: vec![input],
            input_list: None,
            recursive: true,
            algorithms: vec![HashAlgo::Sha256, HashAlgo::Md5],
            out_dir: out,
            langs: vec!["es".into(), "en".into()],
            actor: "tester".into(),
            case_id: Some("CASE-1".into()),
            frontend: "test".into(),
            preamble: vec![("ui_setting_changed".into(), json!({"lang": "es"}))],
            command_line: vec![],
            tool_name: "rv-hashinv".into(),
            tool_version: "0.0.0".into(),
        }
    }

    #[test]
    fn full_run_writes_logs_and_reports() {
        let ev = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(ev.path().join("a.txt"), "same").unwrap();
        std::fs::write(ev.path().join("b.txt"), "same").unwrap();
        std::fs::write(ev.path().join("photo.jpg"), b"%PDF-1.7\n...").unwrap();
        let mut events = Vec::new();
        let s = run(
            &cfg(ev.path().into(), out.path().into()),
            &mut |e| events.push(e.clone()),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(s.items, 3);
        assert_eq!(s.medium, 1); // extension mismatch
        assert_eq!(s.info, 2); // duplicate pair
        assert!(crate::audit::verify(&s.log_dir.join("audit.jsonl")).is_ok());
        for f in ["audit.log", "hashes.csv", "environment.json"] {
            assert!(s.log_dir.join(f).exists(), "{}", f);
        }
        for f in ["statistics.json", "statistics.es.html", "statistics.en.pdf"] {
            assert!(s.report_dir.join(f).exists(), "{}", f);
        }
        let item = s.report_dir.join("items/00003-photo.jpg");
        for f in [
            "technical.json",
            "summary.json",
            "technical.es.html",
            "summary.en.pdf",
            "technical.en.pdf",
            "summary.es.html",
        ] {
            assert!(item.join(f).exists(), "{}", f);
        }
        let es = std::fs::read_to_string(s.report_dir.join("statistics.es.html")).unwrap();
        let en = std::fs::read_to_string(s.report_dir.join("statistics.en.html")).unwrap();
        assert_ne!(es, en);
        assert!(matches!(events.first(), Some(Event::RunStarted { .. })));
        assert!(matches!(events.last(), Some(Event::RunFinished { .. })));
        let csv = std::fs::read_to_string(s.log_dir.join("hashes.csv")).unwrap();
        assert!(csv.starts_with("index,path,size,sha256,md5,"));
    }

    #[test]
    fn cancel_before_start_writes_partial_reports() {
        let ev = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        std::fs::write(ev.path().join("a.txt"), "x").unwrap();
        let s = run(
            &cfg(ev.path().into(), out.path().into()),
            &mut |_| {},
            &AtomicBool::new(true),
        )
        .unwrap();
        assert!(s.cancelled);
        assert_eq!(s.items, 0);
        let log = std::fs::read_to_string(s.log_dir.join("audit.jsonl")).unwrap();
        assert!(log.contains("\"run_cancelled\""));
    }

    #[test]
    fn three_algorithms_are_refused() {
        let mut c = cfg(PathBuf::from("."), PathBuf::from("."));
        c.algorithms = vec![HashAlgo::Md5, HashAlgo::Sha1, HashAlgo::Sha256];
        assert!(run(&c, &mut |_| {}, &AtomicBool::new(false)).is_err());
    }
}
