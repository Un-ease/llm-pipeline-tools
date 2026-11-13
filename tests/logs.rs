use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!("tok-log-tests-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("creating fixture: {error}"),
            }
        }
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn command() -> Command { Command::new(env!("CARGO_BIN_EXE_tok-log")) }

fn run(args: &[&str], paths: &[&Path]) -> Output {
    command().args(args).args(paths).output().unwrap()
}

fn report(output: Output) -> Value {
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).unwrap()
}

fn field<'a>(report: &'a Value, row: usize, column: &str) -> &'a Value {
    let index = report["cols"].as_array().unwrap().iter().position(|v| v == column).unwrap();
    &report["rows"][row][index]
}

fn digest(text: &str) -> String { format!("{:x}", Sha256::digest(text.as_bytes())) }

#[test]
fn exact_repeats_keep_first_last_refs_and_first_seen_tie_order() {
    let fixture = Fixture::new();
    let first = fixture.file("first.log", b"error id=1\nerror id=2\nerror id=1\n    at main:7\n");
    let second = fixture.file("second.log", b"error id=2\nerror id=1\n    at main:7\nnew\n");
    let value = report(run(&["--all"], &[&first, &second]));
    assert_eq!(value["stats"]["total_lines"], 8);
    assert_eq!(value["stats"]["unique_lines"], 4);
    assert_eq!(value["stats"]["repeated_lines"], 4);
    assert_eq!(field(&value, 0, "count"), 3);
    assert_eq!(field(&value, 0, "snippet"), "error id=1");
    assert_eq!(field(&value, 0, "first"), &json!([first.to_str().unwrap(), 1]));
    assert_eq!(field(&value, 0, "last"), &json!([second.to_str().unwrap(), 2]));
    assert_eq!(field(&value, 1, "snippet"), "error id=2");
    assert_eq!(field(&value, 2, "snippet"), "    at main:7");
    assert_eq!(field(&value, 2, "count"), 2);
    assert_eq!(field(&value, 3, "snippet"), "new");
}

#[test]
fn timestamp_stripping_is_explicit_and_preserves_other_text() {
    let fixture = Fixture::new();
    let bytes = b"2026-11-13T09:10:11.123Z error id=41\n2026-11-13T09:10:12+01:00 error id=41\n[09:10:13.5] error id=41\n[09:10:14] error id=42\n[09:10:15]     at module:12\nprefix 2026-11-13T09:10:11Z error id=41\n2026-11-13T09:10:11Zsuffix\n";
    let path = fixture.file("timestamps.log", bytes);
    let raw = report(run(&["--all"], &[&path]));
    assert_eq!(raw["stats"]["unique_lines"], 7);
    assert_eq!(field(&raw, 0, "snippet"), "2026-11-13T09:10:11.123Z error id=41");
    let stripped = report(run(&["--strip-time", "--all"], &[&path]));
    assert_eq!(stripped["stats"]["unique_lines"], 5);
    assert_eq!(field(&stripped, 0, "snippet"), "error id=41");
    assert_eq!(field(&stripped, 0, "count"), 3);
    assert_eq!(field(&stripped, 0, "sha256"), &json!(digest("error id=41")));
    assert_eq!(field(&stripped, 1, "snippet"), "error id=42");
    assert_eq!(field(&stripped, 2, "snippet"), "    at module:12");
    assert_eq!(field(&stripped, 3, "snippet"), "prefix 2026-11-13T09:10:11Z error id=41");
    assert_eq!(field(&stripped, 4, "snippet"), "2026-11-13T09:10:11Zsuffix");
}

#[test]
fn identical_truncated_prefixes_do_not_merge_and_hash_full_lines() {
    let fixture = Fixture::new();
    let path = fixture.file("long.log", b"same-prefix-one\nsame-prefix-two\nsame-prefix-two\n");
    let value = report(run(&["--width", "4", "--all"], &[&path]));
    assert_eq!(value["stats"]["unique_lines"], 2);
    assert_eq!(field(&value, 0, "count"), 2);
    assert_eq!(field(&value, 1, "count"), 1);
    assert_eq!(field(&value, 0, "snippet"), "same");
    assert_eq!(field(&value, 1, "snippet"), "same");
    assert_eq!(field(&value, 0, "sha256"), &json!(digest("same-prefix-two")));
    assert_eq!(field(&value, 1, "sha256"), &json!(digest("same-prefix-one")));
    assert_eq!(field(&value, 0, "truncated_chars"), 11);
    assert_eq!(value["stats"]["display_truncations"], 2);
    assert_eq!(value["stats"]["display_truncated_chars"], 22);
}

#[test]
fn unicode_width_counts_characters_not_bytes_and_zero_suppresses_snippets() {
    let fixture = Fixture::new();
    let path = fixture.file("unicode.log", "é🦀漢z\n".as_bytes());
    let value = report(run(&["--width", "2"], &[&path]));
    assert_eq!(field(&value, 0, "snippet"), "é🦀");
    assert_eq!(field(&value, 0, "chars"), 4);
    assert_eq!(field(&value, 0, "truncated_chars"), 2);
    assert_eq!(value["stats"]["input_bytes"], 11);
    let hidden = report(run(&["--width", "0"], &[&path]));
    assert!(field(&hidden, 0, "snippet").is_null());
    assert_eq!(field(&hidden, 0, "truncated_chars"), 4);
    assert_eq!(field(&hidden, 0, "sha256"), &json!(digest("é🦀漢z")));
}

#[test]
fn crlf_counts_original_bytes_and_blank_lines_remain_distinct() {
    let fixture = Fixture::new();
    let bytes = b"same\r\nsame\n\r\n\n \r\n\t\nlast\r";
    let path = fixture.file("crlf.log", bytes);
    let value = report(run(&["--all"], &[&path]));
    assert_eq!(value["stats"]["input_bytes"], bytes.len());
    assert_eq!(value["stats"]["total_lines"], 7);
    assert_eq!(value["stats"]["blank_lines"], 4);
    assert_eq!(value["stats"]["unique_lines"], 5);
    assert_eq!(field(&value, 0, "snippet"), "same");
    assert_eq!(field(&value, 0, "count"), 2);
    assert_eq!(field(&value, 1, "snippet"), "");
    assert_eq!(field(&value, 1, "count"), 2);
    assert_eq!(field(&value, 2, "snippet"), " ");
    assert_eq!(field(&value, 3, "snippet"), "\t");
    assert_eq!(field(&value, 4, "snippet"), "last\r");
    let empty = fixture.file("empty.log", b"");
    let empty_report = report(run(&[], &[&empty]));
    assert_eq!(empty_report["stats"]["total_lines"], 0);
    assert_eq!(empty_report["rows"], json!([]));
}

#[test]
fn limits_account_for_omitted_rows_and_only_displayed_truncations() {
    let fixture = Fixture::new();
    let lines: String = (0..23).map(|i| format!("line-{i}\n")).collect();
    let path = fixture.file("many.log", lines.as_bytes());
    let value = report(run(&[], &[&path]));
    assert_eq!(value["total"], 23);
    assert_eq!(value["rows"].as_array().unwrap().len(), 20);
    assert_eq!(value["omitted"], 3);
    let limited = report(run(&["--width", "1", "--limit", "1"], &[&path]));
    assert_eq!(limited["omitted"], 22);
    assert_eq!(limited["stats"]["display_truncations"], 1);
    let zero = report(run(&["--limit", "0"], &[&path]));
    assert_eq!(zero["omitted"], 23);
    assert_eq!(zero["rows"], json!([]));
    let all = report(run(&["--limit", "1", "--all"], &[&path]));
    assert_eq!(all["omitted"], 0);
    assert_eq!(all["rows"].as_array().unwrap().len(), 23);
}

#[test]
fn malformed_options_and_failed_inputs_have_no_success_stdout() {
    let fixture = Fixture::new();
    let path = fixture.file("valid.log", b"valid\n");
    for args in [
        vec!["--width"], vec!["--width", "-1"], vec!["--width", "x"],
        vec!["--limit", "x"], vec!["--all", "--limit", "x"],
        vec!["--width", "1", "--width", "2"], vec!["--unknown"],
    ] {
        let output = command().args(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "args: {args:?}");
        assert!(output.stdout.is_empty(), "args: {args:?}");
        assert!(!output.stderr.is_empty());
    }
    let missing = fixture.0.join("missing.log");
    let output = run(&[], &[&path, &missing]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let no_inputs = command().output().unwrap();
    assert_eq!(no_inputs.status.code(), Some(2));
    assert!(no_inputs.stdout.is_empty());
    let invalid = fixture.file("invalid.log", b"valid\n\xff\n");
    let output = run(&[], &[&invalid]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn stdin_has_line_refs_and_help_warns_about_sensitive_snippets() {
    let mut child = command().arg("-").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"from stdin\r\nfrom stdin").unwrap();
    let value = report(child.wait_with_output().unwrap());
    assert_eq!(field(&value, 0, "count"), 2);
    assert_eq!(field(&value, 0, "first"), &json!(["-", 1]));
    assert_eq!(field(&value, 0, "last"), &json!(["-", 2]));
    assert_eq!(value["stats"]["input_bytes"], 22);
    let output = command().arg("--help").output().unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("sensitive data"));
    assert!(help.contains("--width 0"));
}

#[test]
fn timestamp_stripping_preserves_impossible_dates_and_accepts_leap_days() {
    let fixture = Fixture::new();
    let path = fixture.file("calendar.log", b"2026-02-29T09:10:11Z same\n2026-04-31T09:10:11Z same\n1900-02-29T09:10:11Z same\n2024-02-29T09:10:11Z same\n2000-02-29T09:10:11Z same\n2026-02-28T09:10:11Z same\n");
    let value = report(run(&["--strip-time", "--all"], &[&path]));
    assert_eq!(value["stats"]["unique_lines"], 4);
    assert_eq!(field(&value, 0, "snippet"), "same");
    assert_eq!(field(&value, 0, "count"), 3);
    assert_eq!(field(&value, 1, "snippet"), "2026-02-29T09:10:11Z same");
    assert_eq!(field(&value, 2, "snippet"), "2026-04-31T09:10:11Z same");
    assert_eq!(field(&value, 3, "snippet"), "1900-02-29T09:10:11Z same");
}
