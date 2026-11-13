use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new(value: &Value) -> Self {
        let path = std::env::temp_dir().join(format!("llm-gql-{}-{}.json", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let mut file = fs::OpenOptions::new().create_new(true).write(true).open(&path).unwrap();
        serde_json::to_writer(&mut file, value).unwrap();
        Self(path)
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_bbp-gql")).args(args).arg(&self.0).output().unwrap()
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_file(&self.0); } }

fn scalar(name: &str) -> Value { json!({"kind":"SCALAR", "name":name}) }
fn schema() -> Value {
    json!({"data":{"__schema":{"queryType":{"name":"RootQuery"}, "types":[
        {"name":"RootQuery","kind":"OBJECT","fields":[
            {"name":"users","type":{"kind":"NON_NULL","ofType":{"kind":"LIST","ofType":{"kind":"NON_NULL","ofType":{"kind":"OBJECT","name":"User"}}}},
             "args":[{"name":"limit","type":{"kind":"NON_NULL","ofType":scalar("Int")},"defaultValue":null},
                     {"name":"token","type":scalar("String"),"defaultValue":"VERY_SECRET_DEFAULT"}],"isDeprecated":false},
            {"name":"id","type":scalar("ID"),"args":[],"isDeprecated":true}],},
        {"name":"User","kind":"OBJECT","fields":[]},
        {"name":"Int","kind":"SCALAR"}
    ]}}})
}

#[test]
fn preserves_wrappers_required_arguments_and_omits_default_values() {
    let fixture = Fixture::new(&schema());
    let out = fixture.run(&["--type", "RootQuery", "--field", "users"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["rows"][0][2], "[User!]!");
    assert_eq!(report["rows"][0][3][0], json!(["limit", "Int!", true, false]));
    assert_eq!(report["rows"][0][3][1], json!(["token", "String", false, true]));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("VERY_SECRET_DEFAULT"));
}

#[test]
fn overview_counts_all_types_even_with_bounded_output() {
    let fixture = Fixture::new(&schema());
    let out = fixture.run(&["--limit", "1"]);
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["total"], 3);
    assert_eq!(report["omitted"], 2);
    assert_eq!(report["stats"]["query_root"], "RootQuery");
    assert_eq!(report["rows"][0][2], Value::Null);
}

#[test]
fn missing_saved_field_and_incomplete_wrappers_are_errors_without_stdout() {
    let fixture = Fixture::new(&schema());
    let out = fixture.run(&["--type", "RootQuery", "--field", "missing"]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let mut bad = schema();
    bad["data"]["__schema"]["types"][0]["fields"][0]["type"] = json!({"kind":"NON_NULL", "ofType":null});
    let fixture = Fixture::new(&bad);
    let out = fixture.run(&["--type", "RootQuery"]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn stdin_handles_input_objects_and_enums_without_echoing_defaults() {
    let doc = json!({"types":[
        {"name":"Filter","kind":"INPUT_OBJECT","inputFields":[{"name":"text","type":scalar("String"),"defaultValue":"PRIVATE"}]},
        {"name":"Order","kind":"ENUM","enumValues":[{"name":"ASC","isDeprecated":false}]}
    ]});
    for name in ["Filter", "Order"] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bbp-gql")).args(["--type", name, "-"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(serde_json::to_string(&doc).unwrap().as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["rows"][0][0], if name == "Filter" { "text" } else { "ASC" });
        assert!(!String::from_utf8_lossy(&out.stdout).contains("PRIVATE"));
    }
}

#[test]
fn incomplete_or_malformed_argument_defaults_do_not_claim_optional_arguments() {
    for default in [None, Some(json!(false)), Some(json!(123))] {
        let mut doc = schema();
        let arg = doc["data"]["__schema"]["types"][0]["fields"][0]["args"][0].as_object_mut().unwrap();
        match default {
            Some(value) => { arg.insert("defaultValue".into(), value); }
            None => { arg.remove("defaultValue"); }
        }
        let fixture = Fixture::new(&doc);
        let out = fixture.run(&["--type", "RootQuery", "--field", "users"]);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("defaultValue"));
    }
}

#[test]
fn non_null_argument_with_saved_default_is_not_required() {
    let mut doc = schema();
    doc["data"]["__schema"]["types"][0]["fields"][0]["args"][0]["defaultValue"] = json!("123456");
    let fixture = Fixture::new(&doc);
    let out = fixture.run(&["--type", "RootQuery", "--field", "users"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["rows"][0][3][0], json!(["limit", "Int!", false, true]));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("123456"));
}

#[test]
fn incomplete_or_malformed_input_defaults_do_not_claim_no_default() {
    for default in [None, Some(json!(false)), Some(json!(123))] {
        let mut field = json!({"name":"text","type":scalar("String")});
        if let Some(value) = default { field["defaultValue"] = value; }
        let fixture = Fixture::new(&json!({"types":[{"name":"Filter","kind":"INPUT_OBJECT","inputFields":[field]}]}));
        let out = fixture.run(&["--type", "Filter"]);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("defaultValue"));
    }
}
