use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new(bytes: &[u8]) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "bbp-routes-test-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("input.txt"), bytes).unwrap();
        Self(directory)
    }

    fn json(value: Value) -> Self { Self::new(&serde_json::to_vec(&value).unwrap()) }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_bbp-routes")).args(args)
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
fn locales_and_identifiers_collapse_without_merging_real_leaf_operations() {
    let fixture = Fixture::json(json!([
        "https://example.com/en-US/accounts/123/change-password?mode=one-secret",
        "https://example.com/fr/accounts/456/change-password?mode=two-secret",
        "https://example.com/{locale}/accounts/{id}/change-password?mode=three-secret",
        "https://example.com/[locale]/accounts/[accountId]/change-password?mode=four-secret",
        "https://example.com/:locale/accounts/:accountId/change-password?mode=five-secret",
        "https://example.com/${locale}/accounts/${id}/change-password?mode=six-secret",
        "https://example.com/de/accounts/550e8400-e29b-41d4-a716-446655440000/change-password?mode=seven-secret",
        "https://example.com/pt_BR/accounts/0123456789abcdef0123456789abcdef/change-password?mode=eight-secret",
        "https://example.com/accounts/%7Bid%7D/change-password?mode=nine-secret",
        "https://example.com/accounts/123/delete-account?mode=ten-secret",
        "https://example.com/accounts/123/settings?mode=eleven-secret"
    ]));
    let output = fixture.run(&["--all"]);
    let report = document(&output);
    assert_eq!(report["total"], 3);
    let rows = report["rows"].as_array().unwrap();
    for (route, count) in [("/accounts/:param/change-password", 9), ("/accounts/:param/delete-account", 1), ("/accounts/:param/settings", 1)] {
        let row = rows.iter().find(|row| cell(&report, row, "route") == route).unwrap();
        assert_eq!(cell(&report, row, "count"), count);
        assert_eq!(cell(&report, row, "params"), &json!(["mode"]));
    }
    assert!(!String::from_utf8(output.stdout).unwrap().contains("secret"));
}

#[test]
fn keep_locale_retains_literal_languages_and_normalizes_locale_placeholders() {
    let fixture = Fixture::json(json!([
        "https://example.com/en/accounts/1", "https://example.com/fr/accounts/2",
        "https://example.com/{locale}/accounts/3", "https://example.com/[locale]/accounts/4"
    ]));
    assert_eq!(document(&fixture.run(&["--all"]))["total"], 1);
    let report = document(&fixture.run(&["--keep-locale", "--all"]));
    assert_eq!(report["total"], 3);
    let routes: Vec<_> = report["rows"].as_array().unwrap().iter().map(|row| cell(&report, row, "route").as_str().unwrap()).collect();
    assert_eq!(routes, ["/:locale/accounts/:param", "/en/accounts/:param", "/fr/accounts/:param"]);
}

#[test]
fn scheme_host_ip_and_nondefault_port_remain_distinct() {
    let fixture = Fixture::new(b"https://example.com/accounts/1\nhttps://EXAMPLE.com:443/accounts/2\nhttp://example.com/accounts/3\nhttps://other.example.com/accounts/4\nhttps://example.com:8443/accounts/5\nhttps://127.0.0.1/accounts/6\nhttp://127.0.0.1/accounts/7\nhttps://[::1]/accounts/8\nhttps://[::1]:8443/accounts/9\n");
    let report = document(&fixture.run(&["--all"]));
    assert_eq!(report["total"], 8);
    let rows = report["rows"].as_array().unwrap();
    for origin in ["https://example.com", "http://example.com", "https://other.example.com", "https://example.com:8443", "https://127.0.0.1", "http://127.0.0.1", "https://[::1]", "https://[::1]:8443"] {
        assert!(rows.iter().any(|row| cell(&report, row, "origin") == origin), "missing {origin}");
    }
    let row = rows.iter().find(|row| cell(&report, row, "origin") == "https://example.com").unwrap();
    assert_eq!(cell(&report, row, "count"), 2);
}

#[test]
fn query_names_preserve_multiplicity_but_never_values_or_userinfo() {
    let fixture = Fixture::json(json!([
        "https://alice:password-secret@example.com/accounts/1?b=first-secret&a=second-secret#fragment-secret",
        "https://example.com/accounts/2?a=third-secret&b=fourth-secret",
        "https://example.com/accounts/3?a=another-secret&a=repeat-secret&b=last-secret"
    ]));
    let output = fixture.run(&["--all"]);
    let report = document(&output);
    assert_eq!(report["total"], 2);
    let rows = report["rows"].as_array().unwrap();
    assert!(rows.iter().any(|row| cell(&report, row, "params") == &json!(["a", "a", "b"])));
    assert!(rows.iter().any(|row| cell(&report, row, "params") == &json!(["a", "b"]) && cell(&report, row, "count") == 2));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("secret"));
    assert!(!text.contains("alice"));
}

#[test]
fn variants_and_provenance_are_bounded_with_counts_and_unverified_live_assertions() {
    let mut candidates = Vec::new();
    for index in 0..8 {
        candidates.push(json!({"url":format!("https://example.com/accounts/{index}/settings?token=secret-{index}"),
            "source":format!("bundle-{index}.js"),"kind":"template","asserted_live":index == 0}));
    }
    candidates.push(json!({"url":"https://example.com/accounts/0/settings?token=changed-secret",
        "source":"traffic.har","kind":"observed_live"}));
    let fixture = Fixture::json(json!(candidates));
    let output = fixture.run(&["--all"]);
    let report = document(&output);
    assert_eq!(report["total"], 1);
    let row = &report["rows"][0];
    assert_eq!(cell(&report, row, "count"), 9);
    assert_eq!(cell(&report, row, "inferred_count"), 7);
    assert_eq!(cell(&report, row, "asserted_live_count"), 2);
    assert_eq!(cell(&report, row, "variants").as_array().unwrap().len(), 5);
    assert_eq!(cell(&report, row, "variants_total"), 8);
    assert_eq!(cell(&report, row, "variants_omitted"), 3);
    assert_eq!(cell(&report, row, "variants")[0]["path"], "/accounts/0/settings");
    assert_eq!(cell(&report, row, "variants")[0]["count"], 2);
    assert_eq!(cell(&report, row, "provenance").as_array().unwrap().len(), 5);
    assert_eq!(cell(&report, row, "provenance_total"), 9);
    assert_eq!(cell(&report, row, "provenance_omitted"), 4);
    assert_eq!(report["stats"]["live_assertions_verified"], false);
    let samples = cell(&report, row, "provenance").as_array().unwrap();
    assert!(samples.iter().all(|sample| sample["count"] == 1 && sample["source"]["tag"].is_string()));
    assert!(!String::from_utf8(output.stdout).unwrap().contains("secret"));
}

#[test]
fn inventory_reports_preserve_names_counts_and_source_anchors() {
    let fixture = Fixture::new(b"https://example.com/en/accounts/1/settings?x=secret-one&x=secret-two\nhttps://example.com/en/accounts/1/settings?x=other&x=again\nhttps://example.com/fr/accounts/2/settings?x=a&x=b\n");
    let inventory = Command::new(env!("CARGO_BIN_EXE_bbp-urls")).arg("--all")
        .arg(fixture.0.join("input.txt")).output().unwrap();
    assert!(inventory.status.success());
    fs::write(fixture.0.join("input.txt"), &inventory.stdout).unwrap();
    let report = document(&fixture.run(&["--all"]));
    assert_eq!(report["total"], 1);
    let row = &report["rows"][0];
    assert_eq!(cell(&report, row, "count"), 3);
    assert_eq!(cell(&report, row, "params"), &json!(["x", "x"]));
    assert_eq!(cell(&report, row, "provenance_total"), 2);
    let samples = cell(&report, row, "provenance").as_array().unwrap();
    assert!(samples.iter().any(|sample| sample["source"]["line"] == 1 && sample["source"]["byte"] == 0 && sample["count"] == 2));
    assert!(samples.iter().all(|sample| sample["kind"] == "url_inventory" && sample["asserted_live"] == false));
}

#[test]
fn report_omissions_and_route_classes_are_explicit() {
    let fixture = Fixture::json(json!([
        "https://example.com/account/settings", "https://example.com/account/delete-account",
        "https://example.com/assets/app.js", "https://example.com/image.png",
        "https://example.com/undefined", {"url":"https://example.com/literal-expression","kind":"noise"}
    ]));
    let report = document(&fixture.run(&["--all"]));
    assert_eq!(report["stats"]["route"], 2);
    assert_eq!(report["stats"]["static_asset"], 2);
    assert_eq!(report["stats"]["noise"], 2);
    assert_eq!(report["stats"]["class_families"], json!({"route":2,"static_asset":2,"noise":2}));
    assert_eq!(report["total"], 6);
    let limited = document(&fixture.run(&["--limit", "1"]));
    assert_eq!(limited["total"], 6);
    assert_eq!(limited["omitted"], 5);
    let upstream = json!({"v":1,"tool":"bbp-urls","total":3,"omitted":2,
        "cols":["scheme","host","port","path","params","count","source","line","byte"],
        "rows":[["https","example.com",null,"/settings",[],1,"input.txt",1,0]],"stats":{}});
    let upstream_fixture = Fixture::json(upstream);
    let report = document(&upstream_fixture.run(&["--all"]));
    assert_eq!(report["stats"]["upstream_omitted"], 2);
    assert_eq!(report["total"], 1);
}

#[test]
fn site_boundary_filters_without_confusing_hosts_or_authorities() {
    let fixture = Fixture::new(b"https://example.com/a\nhttps://sub.example.com/b\nhttps://EXAMPLE.COM./c\nhttps://notexample.com/d\nhttps://example.com.evil/e\nhttps://example.com@evil.test/f\n");
    let report = document(&fixture.run(&["--site", "EXAMPLE.COM.", "--all"]));
    assert_eq!(report["total"], 3);
    assert_eq!(report["stats"]["filtered"], 3);
    for value in ["127.0.0.1", "[::1]", "https://example.com/secret", "example..com"] {
        let output = fixture.run(&["--site", value]);
        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("secret"));
    }
}

#[test]
fn malformed_json_reports_and_nonboolean_live_tags_are_errors() {
    for value in [json!({"tool":"bbp-urls","rows":[]}),
        json!({"url":"https://example.com/settings","asserted_live":"true"}),
        json!([42]), json!({"source":"bundle.js"})] {
        let fixture = Fixture::json(value);
        let output = fixture.run(&[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    let fixture = Fixture::new(b"[\"https://example.com/a\"");
    assert_eq!(fixture.run(&[]).status.code(), Some(2));
}

#[test]
fn raw_lists_reject_nonabsolute_and_invalid_urls_without_panicking() {
    let fixture = Fixture::new(b"https:example.com/a\nnot a url\nftp://example.com/a\nhttps://example.com:99999/a\nhttps://example.com/a\\b\nhttps://example.com/accounts/1/settings\n");
    let report = document(&fixture.run(&["--all"]));
    assert_eq!(report["total"], 1);
    assert_eq!(report["stats"]["candidates"], 6);
    assert_eq!(report["stats"]["rejected"], 5);
    let row = &report["rows"][0];
    assert_eq!(cell(&report, row, "provenance")[0]["source"]["line"], 6);
}

#[test]
fn concatenated_json_arrays_keep_unique_record_and_pointer_anchors() {
    let fixture = Fixture::new(br#"[["https://example.com/accounts/1/settings"]]
[{"url":"https://example.com/accounts/2/settings","kind":"template","confidence":"low","source":"bundle.js"}]
"#);
    let report = document(&fixture.run(&["--all"]));
    assert_eq!(report["total"], 1);
    let row = &report["rows"][0];
    assert_eq!(cell(&report, row, "provenance_total"), 2);
    let samples = cell(&report, row, "provenance").as_array().unwrap();
    assert!(samples.iter().any(|sample| sample["source"]["record"] == 1 && sample["source"]["pointer"] == "/0/0"));
    assert!(samples.iter().any(|sample| sample["source"]["record"] == 2 && sample["source"]["pointer"] == "/0"
        && sample["source"]["confidence"] == "low" && sample["source"]["tag"] == "bundle.js"));
}

#[test]
fn regional_locales_and_parameter_spellings_are_equivalent() {
    let fixture = Fixture::json(json!([
        "https://example.com/es-419/accounts/12/settings",
        "https://example.com/zh-Hans-CN/accounts/<id>/settings",
        "https://example.com/en/accounts/%5Bid%5D/settings",
        "https://example.com/accounts/[...accountId]/settings"
    ]));
    let report = document(&fixture.run(&["--all"]));
    assert_eq!(report["total"], 1);
    let row = &report["rows"][0];
    assert_eq!(cell(&report, row, "route"), "/accounts/:param/settings");
    assert_eq!(cell(&report, row, "count"), 4);
}

#[test]
fn trailing_slash_families_keep_original_variants_and_do_not_imply_live_equality() {
    let fixture=Fixture::json(json!([
        "https://example.test/account/settings",
        "https://example.test/en-US/account/settings/",
        "https://example.test/fr-FR/account/settings///"
    ]));
    let report=document(&fixture.run(&["--all"]));
    assert_eq!(report["total"],1);
    let row=&report["rows"][0];
    assert_eq!(cell(&report,row,"route"),"/account/settings");
    assert_eq!(cell(&report,row,"count"),3);
    assert_eq!(cell(&report,row,"inferred_count"),3);
    assert_eq!(cell(&report,row,"asserted_live_count"),0);
    let paths:Vec<_>=cell(&report,row,"variants").as_array().unwrap().iter().map(|variant|variant["path"].as_str().unwrap()).collect();
    assert!(paths.contains(&"/en-US/account/settings/"));
    assert!(paths.contains(&"/fr-FR/account/settings///"));
}

#[test]
fn symbol_only_literals_do_not_hide_numeric_ids_or_supported_navigation() {
    let fixture=Fixture::json(json!([
        "https://example.test/$", "https://example.test/&",
        "https://example.test/123",
        {"url":"https://example.test/$","kind":"observed_live"},
        {"url":"https://example.test/&","kind":"html_anchor"},
        {"url":"https://example.test/undefined","kind":"observed_live"}
    ]));
    let report=document(&fixture.run(&["--all"]));
    assert_eq!(report["stats"]["noise"],2);
    assert_eq!(report["stats"]["route"],4);
    let rows=report["rows"].as_array().unwrap();
    for route in ["/$","/&","/:param","/undefined"] {
        assert!(rows.iter().any(|row|cell(&report,row,"class")=="route" && cell(&report,row,"route")==route));
    }
}
