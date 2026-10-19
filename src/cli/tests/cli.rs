//! End-to-end tests of the rv-hashinv binary: the contract every Rakvor CLI must meet.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};

fn bin() -> Command {
    Command::cargo_bin("rv-hashinv").unwrap()
}

fn sample() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/sample/evidence")
}

fn only_dir(p: &Path) -> PathBuf {
    std::fs::read_dir(p)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
}

#[test]
fn help_has_every_required_section() {
    let out = bin().args(["scan", "--help"]).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    for section in [
        "DESCRIPTION:",
        "Options:",
        "EXAMPLES:",
        "EXIT CODES:",
        "FILES WRITTEN:",
        "FORENSIC NOTES:",
    ] {
        assert!(text.contains(section), "missing {}", section);
    }
    for flag in [
        "--input",
        "--input-list",
        "--recursive",
        "--hash",
        "--out",
        "--lang",
        "--actor",
        "--case",
        "--progress",
    ] {
        assert!(text.contains(flag), "missing {}", flag);
    }
    // every option documents a default and an example
    assert!(
        text.matches("Default:").count() >= 9,
        "each option needs a Default: line"
    );
    assert!(
        text.matches("Example:").count() >= 9,
        "each option needs an Example: line"
    );
}

#[test]
fn three_hash_algorithms_are_a_usage_error() {
    bin()
        .args(["scan", "-i", "."])
        .args(["--hash", "md5,sha1,sha256"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("at most 2"));
}

#[test]
fn unknown_language_and_algorithm_are_usage_errors() {
    bin()
        .args(["scan", "-i", ".", "--lang", "de"])
        .assert()
        .code(2);
    bin()
        .args(["scan", "-i", ".", "--hash", "crc32"])
        .assert()
        .code(2);
}

#[test]
fn missing_input_is_a_runtime_error_and_is_audited() {
    let out = tempfile::tempdir().unwrap();
    bin()
        .args(["scan", "-i", "does-not-exist", "-o"])
        .arg(out.path())
        .args(["--progress", "none"])
        .assert()
        .code(1);
    let log = only_dir(&out.path().join("logs")).join("audit.jsonl");
    let text = std::fs::read_to_string(log).unwrap();
    assert!(text.contains("\"run_failed\""));
}

#[test]
fn bulk_scan_writes_reports_logs_and_verifiable_chain() {
    let out = tempfile::tempdir().unwrap();
    bin()
        .args(["scan", "-i"])
        .arg(sample())
        .args([
            "--hash",
            "sha256,blake3",
            "--lang",
            "all",
            "--case",
            "T-1",
            "--actor",
            "ci",
            "--progress",
            "none",
            "-o",
        ])
        .arg(out.path())
        .assert()
        .code(0)
        .stdout(predicate::str::contains("items: 3"));
    let logs = only_dir(&out.path().join("logs"));
    let reports = only_dir(&out.path().join("reports"));
    for f in ["audit.jsonl", "audit.log", "hashes.csv", "environment.json"] {
        assert!(logs.join(f).is_file(), "{}", f);
    }
    for l in ["en", "es", "fr"] {
        for ext in ["html", "pdf"] {
            assert!(reports.join(format!("statistics.{}.{}", l, ext)).is_file());
        }
    }
    let items: Vec<_> = std::fs::read_dir(reports.join("items")).unwrap().collect();
    assert_eq!(items.len(), 3, "one folder per item");
    for item in items {
        let d = item.unwrap().path();
        for f in [
            "technical.json",
            "summary.json",
            "technical.es.pdf",
            "summary.fr.html",
        ] {
            assert!(d.join(f).is_file(), "{} in {}", f, d.display());
        }
        let pdf = std::fs::read(d.join("technical.en.pdf")).unwrap();
        assert!(pdf.starts_with(b"%PDF-") && pdf.ends_with(b"%%EOF\n"));
    }
    bin()
        .arg("verify-log")
        .arg(&logs)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("chain intact"));

    // Tampering with one entry is detected.
    let p = logs.join("audit.jsonl");
    let text = std::fs::read_to_string(&p).unwrap();
    std::fs::write(
        &p,
        text.replacen("\"actor\":\"ci\"", "\"actor\":\"mallory\"", 1),
    )
    .unwrap();
    bin()
        .arg("verify-log")
        .arg(&p)
        .assert()
        .code(3)
        .stdout(predicate::str::contains("BROKEN"));
}

#[test]
fn jsonl_progress_is_one_event_per_line_with_elapsed_time() {
    let out = tempfile::tempdir().unwrap();
    let o = bin()
        .args(["scan", "-i"])
        .arg(sample())
        .args(["--progress", "jsonl", "-o"])
        .arg(out.path())
        .output()
        .unwrap();
    let text = String::from_utf8(o.stdout).unwrap();
    let events: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("valid JSON line"))
        .collect();
    assert_eq!(events.first().unwrap()["event"], "run_started");
    assert_eq!(events.last().unwrap()["event"], "run_finished");
    let elapsed: Vec<u64> = events
        .iter()
        .filter(|e| e["event"] == "progress")
        .map(|e| e["elapsed_ms"].as_u64().unwrap())
        .collect();
    assert!(
        !elapsed.is_empty() && elapsed.windows(2).all(|w| w[0] <= w[1]),
        "elapsed_ms must be monotonic"
    );
}

#[test]
fn evidence_is_not_modified() {
    let ev = tempfile::tempdir().unwrap();
    let f = ev.path().join("a.bin");
    std::fs::write(&f, b"evidence").unwrap();
    let before = std::fs::metadata(&f).unwrap().modified().unwrap();
    let out = tempfile::tempdir().unwrap();
    bin()
        .args(["scan", "-i"])
        .arg(&f)
        .args(["--progress", "none", "-o"])
        .arg(out.path())
        .assert()
        .code(0);
    assert_eq!(std::fs::read(&f).unwrap(), b"evidence");
    assert_eq!(std::fs::metadata(&f).unwrap().modified().unwrap(), before);
}

#[test]
fn executable_under_another_name_exits_3() {
    let ev = tempfile::tempdir().unwrap();
    std::fs::write(ev.path().join("invoice.pdf"), b"MZ\x90\x00\x03\x00\x00\x00").unwrap();
    let out = tempfile::tempdir().unwrap();
    bin()
        .args(["scan", "-i"])
        .arg(ev.path())
        .args(["--progress", "none", "-o"])
        .arg(out.path())
        .assert()
        .code(3);
}

#[test]
fn self_test_passes() {
    bin()
        .arg("self-test")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("FAIL").not());
}

#[test]
fn usage_doc_matches_help() {
    let generated = bin().arg("docs-cli").output().unwrap().stdout;
    let doc = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/usage-cli.md");
    let committed = std::fs::read(&doc).unwrap_or_default();
    assert!(
        committed == generated,
        "docs/usage-cli.md is out of date: run `cargo run -p rv-hashinv-cli -- docs-cli > docs/usage-cli.md`"
    );
}
