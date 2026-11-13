use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "bbp-urls-test-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("input.txt"), bytes).unwrap();
        Self(directory)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_bbp-urls")).args(args)
            .arg(self.0.join("input.txt")).output().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn document(output: &Output) -> Value {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap()
}

fn cell<'a>(report: &'a Value, row: &'a Value, name: &str) -> &'a Value {
    let column = report["cols"].as_array().unwrap().iter().position(|item| item == name).unwrap();
    &row[column]
}

#[test]
fn groups_values_but_preserves_parameter_multiplicity() {
    let fixture = Fixture::new(b"https://EXAMPLE.com:443/Path?b=first-secret&a=1\nhttps://example.com/Path?a=2&b=second-secret\nhttps://example.com/Path?a=3&a=4&b=5\n");
    let output = fixture.run(&["--all"]);
    let report = document(&output);
    assert_eq!(report["total"], 2);
    let rows = report["rows"].as_array().unwrap();
    let grouped = rows.iter().find(|row| cell(&report, row, "count") == 2).unwrap();
    assert_eq!(cell(&report, grouped, "host"), "example.com");
    assert_eq!(cell(&report, grouped, "port"), &Value::Null);
    assert_eq!(cell(&report, grouped, "params"), &serde_json::json!(["a", "b"]));
    assert_eq!(cell(&report, grouped, "line"), 1);
    assert_eq!(cell(&report, grouped, "byte"), 0);
    let repeated = rows.iter().find(|row| cell(&report, row, "count") == 1).unwrap();
    assert_eq!(cell(&report, repeated, "params"), &serde_json::json!(["a", "a", "b"]));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("first-secret"));
    assert!(!text.contains("second-secret"));
}

#[test]
fn preserves_security_relevant_path_spellings_and_ports() {
    let fixture = Fixture::new(b"https://example.com/A\nhttps://example.com/a\nhttps://example.com/a%2Fb\nhttps://example.com/a/b\nhttps://example.com/a//b\nhttps://example.com/a;b\nhttps://example.com/a;b;\nhttps://example.com/a/../b\nhttps://example.com:8443/a\n");
    let report = document(&fixture.run(&["--all"]));
    assert_eq!(report["total"], 9);
    let rows = report["rows"].as_array().unwrap();
    for path in ["/A", "/a", "/a%2Fb", "/a/b", "/a//b", "/a;b", "/a;b;", "/a/../b"] {
        assert!(rows.iter().any(|row| cell(&report, row, "path") == path), "missing {path}");
    }
    assert!(rows.iter().any(|row| cell(&report, row, "port") == 8443));
}

#[test]
fn redacts_userinfo_fragment_values_and_extracts_escaped_literals() {
    let fixture = Fixture::new(br#"const api = "https:\/\/alice:password-secret@EXAMPLE.com\/Api?token=value-secret&token=other-secret#fragment-secret";
"#);
    let output = fixture.run(&[]);
    let report = document(&output);
    assert_eq!(report["total"], 1);
    let row = &report["rows"][0];
    assert_eq!(cell(&report, row, "host"), "example.com");
    assert_eq!(cell(&report, row, "path"), "/Api");
    assert_eq!(cell(&report, row, "params"), &serde_json::json!(["token", "token"]));
    assert_eq!(cell(&report, row, "byte"), 13);
    let text = String::from_utf8(output.stdout).unwrap();
    for secret in ["alice", "password-secret", "value-secret", "other-secret", "fragment-secret"] {
        assert!(!text.contains(secret), "leaked {secret}");
    }
}

#[test]
fn trims_sentence_boundaries_without_losing_balanced_parentheses_or_semicolons() {
    let fixture = Fixture::new(b"See (https://example.com/a), https://example.com/b.\nUse https://example.com/a_(b).\nhttps://example.com/c;\n");
    let report = document(&fixture.run(&["--all"]));
    assert_eq!(report["total"], 4);
    let paths: Vec<_> = report["rows"].as_array().unwrap().iter()
        .map(|row| cell(&report, row, "path").as_str().unwrap()).collect();
    assert_eq!(paths, ["/a", "/a_(b)", "/b", "/c;"]);
}

#[test]
fn exact_host_filter_handles_bare_names_and_accounts_for_invalid_input() {
    let input = b"EXAMPLE.com\nhttps://example.com/a\nhttps://example.com.evil/a\nhttps://sub.example.com/a\nhttp://\nhttps://example.com:99999/a\nordinary prose\n";
    let fixture = Fixture::new(input);
    let report = document(&fixture.run(&["--host", "example.com", "--all"]));
    assert_eq!(report["total"], 2);
    assert_eq!(report["stats"]["candidates"], 6);
    assert_eq!(report["stats"]["rejected"], 2);
    assert_eq!(report["stats"]["filtered"], 2);
    assert_eq!(report["stats"]["occurrences"], 2);
    assert_eq!(report["stats"]["ignored_lines"], 1);
    assert_eq!(report["stats"]["input_bytes"], input.len());
    for row in report["rows"].as_array().unwrap() {
        assert_eq!(cell(&report, row, "host"), "example.com");
    }
}

#[test]
fn stdin_anchors_are_byte_offsets_and_invalid_utf8_is_rejected() {
    let bytes = b"\xc3\xa9 prefix https://example.com/path?x=private\r\nhttps://\xff.example/a\n";
    let mut child = Command::new(env!("CARGO_BIN_EXE_bbp-urls"))
        .arg("-").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let report = document(&child.wait_with_output().unwrap());
    assert_eq!(report["total"], 1);
    assert_eq!(report["stats"]["input_bytes"], bytes.len());
    assert_eq!(report["stats"]["rejected"], 1);
    let row = &report["rows"][0];
    assert_eq!(cell(&report, row, "source"), "-");
    assert_eq!(cell(&report, row, "line"), 1);
    assert_eq!(cell(&report, row, "byte"), 10);
}

#[test]
fn bounds_output_and_accounts_for_oversized_literals() {
    let mut text = String::new();
    for index in 0..23 { text.push_str(&format!("https://example.com/{index:02}\n")); }
    text.push_str("https://example.com/");
    text.push_str(&"x".repeat(9000));
    text.push('\n');
    let fixture = Fixture::new(text.as_bytes());
    let report = document(&fixture.run(&[]));
    assert_eq!(report["total"], 23);
    assert_eq!(report["rows"].as_array().unwrap().len(), 20);
    assert_eq!(report["omitted"], 3);
    assert_eq!(report["stats"]["rejected"], 1);
    assert_eq!(report["stats"]["overlong"], 1);
    let limited = document(&fixture.run(&["--limit", "1"]));
    assert_eq!(limited["rows"].as_array().unwrap().len(), 1);
    assert_eq!(limited["omitted"], 22);
    let all = document(&fixture.run(&["--all"]));
    assert_eq!(all["rows"].as_array().unwrap().len(), 23);
}

#[test]
fn invalid_host_option_fails_without_echoing_input() {
    let fixture = Fixture::new(b"https://example.com/\n");
    let output = fixture.run(&["--host", "https://example.com/private-secret"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-secret"));
}

#[test]
fn site_filter_uses_dns_label_boundaries_not_substrings() {
    let fixture = Fixture::new(b"https://example.com/a\nhttps://a.example.com/a\nhttps://example.com.evil/a\nhttps://notexample.com/a\nhttps://example.com@evil.test/a\nhttps://EXAMPLE.COM./b\n");
    let report = document(&fixture.run(&["--site", "EXAMPLE.com.", "--all"]));
    assert_eq!(report["total"], 3);
    assert_eq!(report["stats"]["filtered"], 3);
    for invalid in ["https://example.com/path-secret", "127.0.0.1", "[::1]", "example..com", "-bad.test"] {
        let output = fixture.run(&["--site", invalid]);
        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("path-secret"));
    }
    assert_eq!(fixture.run(&["--host", "example.com", "--site", "example.com"]).status.code(), Some(2));
}

#[test]
fn since_compares_endpoint_sets_not_counts_sources_or_query_values() {
    let fixture = Fixture::new(b"https://example.com/kept?a=old-secret&b=1\nhttps://example.com/gone\nhttps://example.com/kept?a=other&b=2\n");
    let old = fixture.run(&["--all"]);
    let baseline = fixture.0.join("prior.json");
    fs::write(&baseline, &old.stdout).unwrap();
    fs::write(fixture.0.join("input.txt"), b"\nhttps://example.com/kept?b=changed-secret&a=3\nhttps://example.com/new?token=hidden-secret\nhttps://example.com/new?token=other\n").unwrap();
    let output = fixture.run(&["--all", "--since", baseline.to_str().unwrap()]);
    let report = document(&output);
    assert_eq!(report["stats"]["delta"], serde_json::json!({
        "new":1,"gone":1,"unchanged":1,"previous_total":2,"current_total":2
    }));
    assert_eq!(report["stats"]["inventory_total"], 2);
    assert_eq!(report["stats"]["occurrences"], 3);
    assert_eq!(report["total"], 1);
    assert_eq!(cell(&report, &report["rows"][0], "path"), "/new");
    assert_eq!(cell(&report, &report["rows"][0], "count"), 2);
    assert_eq!(cell(&report, &report["rows"][0], "line"), 3);
    let text = String::from_utf8(output.stdout).unwrap();
    for secret in ["old-secret", "changed-secret", "hidden-secret"] { assert!(!text.contains(secret)); }
    let limited = document(&fixture.run(&["--limit", "0", "--since", baseline.to_str().unwrap()]));
    assert_eq!(limited["total"], 1);
    assert_eq!(limited["omitted"], 1);
    assert_eq!(limited["stats"]["inventory_total"], 2);
}

#[test]
fn since_preserves_scheme_ports_path_and_parameter_multiplicity() {
    let fixture = Fixture::new(b"https://example.com/a?x=1\nhttp://example.com/a\nhttps://example.com:8443/a\nhttps://[::1]/a\n");
    let baseline = fixture.0.join("prior.json");
    fs::write(&baseline, fixture.run(&["--all"]).stdout).unwrap();
    fs::write(fixture.0.join("input.txt"), b"https://example.com/a?x=2&x=3\nhttps://example.com/A?x=1\nhttp://example.com/a\nhttps://example.com:8443/a\nhttps://[::1]/a\n").unwrap();
    let report = document(&fixture.run(&["--all", "--since", baseline.to_str().unwrap()]));
    assert_eq!(report["stats"]["delta"]["new"], 2);
    assert_eq!(report["stats"]["delta"]["gone"], 1);
    assert_eq!(report["stats"]["delta"]["unchanged"], 3);
}

#[test]
fn since_rejects_partial_projected_missing_and_malformed_baselines() {
    let fixture = Fixture::new(b"https://example.com/a\nhttps://example.com/b\n");
    let original = document(&fixture.run(&["--all"]));
    let mut invalid = Vec::new();
    invalid.push(document(&fixture.run(&["--limit", "1"])));
    let mut value = original.clone(); value["partial"] = serde_json::json!({"error":"cutoff"}); invalid.push(value);
    let mut value = original.clone(); value["stats"]["delta"] = serde_json::json!({"new":2}); invalid.push(value);
    let mut value = original.clone(); value["rows"][0][4] = serde_json::json!("not-array"); invalid.push(value);
    let mut value = original.clone(); value["rows"][0][5] = serde_json::json!(0); invalid.push(value);
    let mut value = original.clone(); value["total"] = serde_json::json!(3); invalid.push(value);
    let mut value = original.clone(); value["stats"]["inventory_total"] = serde_json::json!(3); invalid.push(value);
    let mut value = original.clone(); value["completeness"] = serde_json::json!("partial"); invalid.push(value);
    let mut value = original.clone(); value["rows"][1] = value["rows"][0].clone(); invalid.push(value);
    let mut value = original.clone(); value.as_object_mut().unwrap().remove("omitted"); invalid.push(value);
    invalid.push(serde_json::json!([]));
    let baseline = fixture.0.join("prior.json");
    for value in invalid {
        fs::write(&baseline, serde_json::to_vec(&value).unwrap()).unwrap();
        let output = fixture.run(&["--since", baseline.to_str().unwrap()]);
        assert_eq!(output.status.code(), Some(2), "accepted {value}");
        assert!(output.stdout.is_empty());
    }
    fs::write(&baseline, b"{\"tool\":").unwrap();
    assert_eq!(fixture.run(&["--since", baseline.to_str().unwrap()]).status.code(), Some(2));
    assert_eq!(fixture.run(&["--since", "-"]).status.code(), Some(2));
    assert_eq!(fixture.run(&["--since", fixture.0.join("absent").to_str().unwrap()]).status.code(), Some(2));
}

#[test]
fn since_can_report_only_gone_observations_or_compare_empty_inventories() {
    let fixture = Fixture::new(b"https://example.com/a\n");
    let baseline = fixture.0.join("prior.json");
    fs::write(&baseline, fixture.run(&["--all"]).stdout).unwrap();
    fs::write(fixture.0.join("input.txt"), b"").unwrap();
    let report = document(&fixture.run(&["--all", "--since", baseline.to_str().unwrap()]));
    assert_eq!(report["total"], 0);
    assert_eq!(report["stats"]["delta"], serde_json::json!({
        "new":0,"gone":1,"unchanged":0,"previous_total":1,"current_total":0
    }));
    fs::write(&baseline, fixture.run(&["--all"]).stdout).unwrap();
    fs::write(fixture.0.join("input.txt"), b"https://example.com/new\n").unwrap();
    let report = document(&fixture.run(&["--all", "--since", baseline.to_str().unwrap()]));
    assert_eq!(report["stats"]["delta"]["new"], 1);
    assert_eq!(report["stats"]["delta"]["gone"], 0);
}
