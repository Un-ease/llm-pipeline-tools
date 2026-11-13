use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Files(PathBuf);
impl Files {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("bbp-http-test-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn put(&self, name: &str, text: &str) -> String {
        let path = self.0.join(name);
        fs::write(&path, text).unwrap();
        path.to_str().unwrap().to_owned()
    }
}
impl Drop for Files { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bbp-http")).args(args).output().unwrap()
}
fn parsed(output: &Output) -> Value {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap()
}
fn field<'a>(report: &'a Value, row: &'a Value, key: &str) -> &'a Value {
    let index = report["cols"].as_array().unwrap().iter().position(|v| v == key).unwrap();
    &row[index]
}
fn probe(body: &str) -> Value {
    json!({"label":"saved probe", "method":"GET", "url":"https://example.test/Case%2fPath?z=QUERY_SECRET&a=OTHER_SECRET", "params":null,"data":null,
        "status":200,"request_url":"https://example.test/Case%2fPath?z=QUERY_SECRET&a=OTHER_SECRET", "headers":{"Content-Type":"text/plain; charset=utf-8","Set-Cookie":"COOKIE_SECRET"},"body":body})
}

#[test]
fn full_body_identity_and_bounded_variants() {
    let files = Files::new();
    let prefix = "x".repeat(450);
    let first = probe(&format!("{prefix}a"));
    let second = probe(&format!("{prefix}b"));
    let input = files.put("probes.json", &json!([first.clone(),second,first.clone(),first.clone(),first.clone(),first.clone(),first]).to_string());
    let output = run(&["--all", &input]);
    let report = parsed(&output);
    assert_eq!(report["total"], 2);
    assert_eq!(report["stats"]["records"], 7);
    let rows = report["rows"].as_array().unwrap();
    assert_ne!(field(&report, &rows[0], "identity"), field(&report, &rows[1], "identity"));
    let duplicate = rows.iter().find(|row| field(&report,row,"count") == 6).unwrap();
    assert_eq!(field(&report,duplicate,"variants").as_array().unwrap().len(),3);
    assert_eq!(field(&report,duplicate,"variants_omitted"),2);
    assert_eq!(field(&report,duplicate,"bytes"), &json!([451]));
    assert_eq!(field(&report,duplicate,"path"), "/Case%2fPath");
    assert_eq!(field(&report,duplicate,"query_names"), &json!(["a","z"]));
    let text = String::from_utf8(output.stdout).unwrap();
    for secret in ["QUERY_SECRET","OTHER_SECRET","COOKIE_SECRET", &prefix] { assert!(!text.contains(secret)); }
}

#[test]
fn accepts_jsonl_arrays_maps_and_never_equates_metadata_lengths() {
    let files = Files::new();
    let digest = "a".repeat(64);
    let input = files.put("mixed.jsonl", &format!("{}\n{}\n{}\n{}\n",
        json!({"url":"https://example.test/s/", "status_code":200,"content_type":"text/html","content_length":10,"method":"GET"}),
        json!([{ "url":"https://example.test/s/", "status_code":200,"content_type":"text/html","content_length":10,"method":"GET"}]),
        json!({"/s/?token=SECRET_MAP_VALUE":{"status":200,"content_type":"text/html","bytes":10,"sha256":digest}}),
        json!({"url":"https://example.test/not-a-record", "notes":"metadata only"})));
    let output = run(&["--all", &input]);
    let report = parsed(&output);
    assert_eq!(report["total"],3);
    assert_eq!(report["stats"]["records"],4);
    assert_eq!(report["stats"]["accepted"],3);
    assert_eq!(report["stats"]["unsupported"],1);
    assert_eq!(report["stats"]["metadata_only"],2);
    assert!(!String::from_utf8(output.stdout).unwrap().contains("SECRET_MAP_VALUE"));
}

#[test]
fn burp_parses_final_interim_response_and_redacts_headers_and_userinfo() {
    let files = Files::new();
    let input = files.put("burp.json", &json!({
        "request":"POST https://USER_SECRET:PASS_SECRET@example.test/Keep%2FCase?a=QUERY_SECRET HTTP/1.1\r\nAuthorization: Bearer AUTH_SECRET\r\nCookie: COOKIE_SECRET\r\n\r\nREQUEST_BODY_SECRET",
        "response":"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\nLink: /x\n\nHTTP/1.1 201 Created\r\nCoNtEnT-TyPe: Text/Plain; charset=utf-8\r\nSet-Cookie: RESPONSE_COOKIE_SECRET\r\nContent-Length: 3\r\n\r\n雪",
        "notes":"NOTE_SECRET"
    }).to_string());
    let output = run(&[&input]);
    let report = parsed(&output);
    let row = &report["rows"][0];
    assert_eq!(field(&report,row,"status"),201);
    assert_eq!(field(&report,row,"host"),"example.test");
    assert_eq!(field(&report,row,"path"),"/Keep%2FCase");
    assert_eq!(field(&report,row,"mime"),"text/plain");
    assert_eq!(field(&report,row,"bytes"),&json!([3]));
    let text = String::from_utf8(output.stdout).unwrap();
    for secret in ["USER_SECRET","PASS_SECRET","AUTH_SECRET","COOKIE_SECRET","QUERY_SECRET","REQUEST_BODY_SECRET","RESPONSE_COOKIE_SECRET","NOTE_SECRET"] { assert!(!text.contains(secret)); }
}

#[test]
fn malformed_input_has_no_partial_stdout() {
    let files = Files::new();
    let valid = probe("valid").to_string();
    let cases = [
        format!("{valid}\n{{broken"),
        format!("{valid}\n{}",json!({"request":"GET / HTTP/1.1\nHost: a.test\nHost: b.test\n\n","response":"HTTP/1.1 200 OK\n\nbody"})),
        format!("{valid}\n{}",json!({"request":"GET / HTTP/1.1\n\n","response":"HTTP/1.1 200 OK\n\nbody"})),
        format!("{valid}\n{}",json!({"url":"https://example.test/","status":200,"body": {"not":"captured bytes"}})),
    ];
    for (index,input) in cases.iter().enumerate() {
        let path = files.put(&format!("malformed{index}.json"),input);
        let output = run(&[&path]);
        assert_eq!(output.status.code(),Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn aura_distinguishes_success_failure_and_explicit_skips() {
    let files = Files::new();
    let mut success = probe(&format!("while(1);{}", json!({"actions":[{"id":"1;a","state":"SUCCESS","returnValue":{"token":"RETURN_SECRET","items":[{"price":12345}]}}]})));
    success["headers"]["Content-Type"] = json!("application/json");
    let failure = probe(&format!("while(1);{}", json!({"actions":[{"id":"2;a","state":"ERROR","error":[{"message":"ERROR_SECRET"}]}]})));
    let input = files.put("aura.json",&json!([success,failure,probe("not Aura"),probe("while(1);{\"actions\":[]}"),probe("while(1);{\"other\":true}"),probe("while(1);broken")]).to_string());
    let output = run(&["--aura","--all",&input]);
    let report = parsed(&output);
    assert_eq!(report["total"],2);
    assert_eq!(report["stats"]["aura_responses"],2);
    assert_eq!(report["stats"]["aura_failures"],1);
    assert_eq!(report["stats"]["skipped_non_aura"],1);
    assert_eq!(report["stats"]["skipped_no_actions"],2);
    assert_eq!(report["stats"]["skipped_invalid_aura"],1);
    for row in report["rows"].as_array().unwrap() {
        assert_eq!(field(&report,row,"direction"),"response");
        if field(&report,row,"state") == "SUCCESS" {
            assert_eq!(field(&report,row,"errors"),0);
            assert_eq!(field(&report,row,"return_shape")["token"],"string");
        } else { assert_eq!(field(&report,row,"errors"),1); }
    }
    let text = String::from_utf8(output.stdout).unwrap();
    for secret in ["RETURN_SECRET","ERROR_SECRET","12345"] { assert!(!text.contains(secret)); }
}

#[test]
fn saved_aura_request_prefers_msg_and_never_infers_success() {
    let files = Files::new();
    let message = json!({"actions":[{"id":"1;a","descriptor":"serviceComponent://example.Controller/ACTION$navigate","callingDescriptor":"UNKNOWN","params":{"request":{"target":"PARAM_SECRET","enabled":true}}}]}).to_string();
    let input = files.put("nav.json",&json!({"msg":message,"pd":"message=SHOULD_NOT_PARSE_OR_PRINT","ctx":"CTX_SECRET","pageuri":"/s/Page?token=PAGE_SECRET"}).to_string());
    let output = run(&["--aura",&input]);
    let report = parsed(&output);
    assert_eq!(report["total"],1);
    assert_eq!(report["stats"]["aura_requests"],1);
    assert_eq!(report["stats"]["aura_responses"],0);
    assert_eq!(report["stats"]["aura_failures"],0);
    let row = &report["rows"][0];
    assert_eq!(field(&report,row,"direction"),"request");
    assert!(field(&report,row,"state").is_null());
    assert!(field(&report,row,"errors").is_null());
    assert_eq!(field(&report,row,"params_shape")["request"]["target"],"string");
    assert_eq!(field(&report,row,"params_shape")["request"]["enabled"],"boolean");
    assert_eq!(field(&report,row,"query_names"),&json!(["token"]));
    let text = String::from_utf8(output.stdout).unwrap();
    for secret in ["PARAM_SECRET","CTX_SECRET","PAGE_SECRET","SHOULD_NOT_PARSE_OR_PRINT"] { assert!(!text.contains(secret)); }
}

#[test]
fn stdin_help_limits_and_stable_order() {
    let help = run(&["--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8(help.stdout).unwrap().contains("--aura"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_bbp-http")).args(["--limit","1","-"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let records = json!([probe("z"),probe("a"),probe("b")]);
    child.stdin.take().unwrap().write_all(records.to_string().as_bytes()).unwrap();
    let report = parsed(&child.wait_with_output().unwrap());
    assert_eq!(report["total"],3);
    assert_eq!(report["omitted"],2);
    assert_eq!(report["rows"].as_array().unwrap().len(),1);
    let files = Files::new();
    let input = files.put("order.json",&records.to_string());
    let first = run(&["--all",&input]);
    let second = run(&["--all",&input]);
    assert!(first.status.success());
    assert_eq!(first.stdout,second.stdout);
    let invalid_limit = run(&["--limit","-1",&input]);
    assert!(!invalid_limit.status.success());
    assert!(invalid_limit.stdout.is_empty());
}

#[test]
fn aura_request_descriptor_joins_response_by_action_id() {
    let files = Files::new();
    let message = json!({"actions":[{"id":"7;a","descriptor":"serviceComponent://example.Controller/ACTION$get","params":{"secret":"REQUEST_SECRET"}}]}).to_string();
    let form = url::form_urlencoded::Serializer::new(String::new()).append_pair("message",&message).finish();
    let input = files.put("burp-aura.json",&json!({"request":format!("POST /s/sfsites/aura HTTP/1.1\nHOST: example.test\n\n{form}"),"response":format!("HTTP/1.1 200 OK\nContent-Type: application/json\n\nwhile(1);{}",json!({"actions":[{"id":"7;a","state":"SUCCESS","returnValue":null}]}))}).to_string());
    let output = run(&["--aura",&input]);
    let report = parsed(&output);
    assert_eq!(field(&report,&report["rows"][0],"descriptor"),"serviceComponent://example.Controller/ACTION$get");
    assert!(!String::from_utf8(output.stdout).unwrap().contains("REQUEST_SECRET"));
}

#[test]
fn path_map_arrays_and_status_code_records_keep_their_endpoints() {
    let files = Files::new();
    let input = files.put("map-arrays.json", &json!([
        {"/Case%2FPath?token=SECRET_MAP_QUERY":[
            {"status":200,"body":"first"},
            {"status_code":201,"body":"second"}
        ]},
        {"request_url":"https://example.test/Request?key=SECRET_REQUEST_QUERY","status_code":202,"body":"third"}
    ]).to_string());
    let output = run(&["--all", &input]);
    let report = parsed(&output);
    assert_eq!(report["total"], 3);
    assert_eq!(report["stats"]["accepted"], 3);
    assert_eq!(report["stats"]["unsupported"], 0);
    let rows = report["rows"].as_array().unwrap();
    for status in [200, 201] {
        let row = rows.iter().find(|row| field(&report, row, "status") == status).unwrap();
        assert_eq!(field(&report, row, "path"), "/Case%2FPath");
        assert_eq!(field(&report, row, "query_names"), &json!(["token"]));
    }
    let row = rows.iter().find(|row| field(&report, row, "status") == 202).unwrap();
    assert_eq!(field(&report, row, "host"), "example.test");
    assert_eq!(field(&report, row, "path"), "/Request");
    assert_eq!(field(&report, row, "query_names"), &json!(["key"]));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("SECRET_MAP_QUERY"));
    assert!(!text.contains("SECRET_REQUEST_QUERY"));
}

#[test]
fn aura_response_metadata_does_not_override_captured_http_body() {
    let files = Files::new();
    let mut record = probe(&json!({"actions":[{"id":"1;a","state":"SUCCESS","returnValue":true}]}).to_string());
    record["msg"] = json!("ordinary response metadata, not a saved request");
    record["pd"] = json!(false);
    let input = files.put("aura-metadata.json", &record.to_string());
    let report = parsed(&run(&["--aura", &input]));
    assert_eq!(report["total"], 1);
    assert_eq!(report["stats"]["aura_requests"], 0);
    assert_eq!(report["stats"]["aura_responses"], 1);
    assert_eq!(field(&report, &report["rows"][0], "direction"), "response");
    assert_eq!(field(&report, &report["rows"][0], "state"), "SUCCESS");
}

#[test]
fn metadata_only_array_records_do_not_claim_identical_bodies() {
    let files = Files::new();
    let record = json!({"url":"https://example.test/","status_code":200,"content_length":12});
    let input = files.put("metadata-array.json", &json!([record.clone(),record]).to_string());
    let report = parsed(&run(&["--all",&input]));
    assert_eq!(report["total"],2);
    assert_eq!(report["stats"]["metadata_only"],2);
    let rows = report["rows"].as_array().unwrap();
    assert!(rows.iter().all(|row|field(&report,row,"count")==1));
    assert_ne!(field(&report,&rows[0],"identity"),field(&report,&rows[1],"identity"));
}

#[test]
fn explicit_metadata_grouping_collapses_across_urls_without_claiming_equal_bodies() {
    let files = Files::new();
    let first = json!({"method":"GET","url":"https://USER_SECRET:PASS_SECRET@example.test/Case%2fPath?token=QUERY_SECRET",
        "status_code":200,"content_length":12,"content_type":"Text/Plain; charset=utf-8"});
    let second = json!({"method":"POST","url":"https://other.test/Other?other=OTHER_SECRET",
        "status":200,"bytes":12,"headers":{"Content-Type":"text/plain"},"body":null});
    let input = files.put("metadata-group.json", &json!([first.clone(),second,first.clone(),first.clone(),first.clone(),first]).to_string());
    let output = run(&["--group-metadata","--all",&input]);
    let report = parsed(&output);
    assert_eq!(report["total"],1);
    assert_eq!(report["stats"]["metadata_only"],6);
    let row = &report["rows"][0];
    assert_eq!(field(&report,row,"identity"), &json!(format!("meta:{}", llm_pipeline_tools::sha256(b"[200,12,\"text/plain\"]"))));
    assert_eq!(field(&report,row,"equal_bodies"),false);
    assert_eq!(field(&report,row,"count"),6);
    assert_eq!(field(&report,row,"bytes"), &json!([12]));
    assert_eq!(field(&report,row,"method"),"GET");
    assert_eq!(field(&report,row,"host"),"example.test");
    assert_eq!(field(&report,row,"path"),"/Case%2fPath");
    assert_eq!(field(&report,row,"query_names"), &json!(["token"]));
    assert_eq!(field(&report,row,"source"), &json!(format!("{input}#1/1")));
    assert_eq!(field(&report,row,"variants"), &json!([format!("{input}#1/2"),format!("{input}#1/3"),format!("{input}#1/4")]));
    assert_eq!(field(&report,row,"variants_omitted"),2);
    let repeated = run(&["--group-metadata","--all",&input]);
    assert!(repeated.status.success());
    assert_eq!(output.stdout,repeated.stdout);
    let text = String::from_utf8(output.stdout).unwrap();
    for secret in ["USER_SECRET","PASS_SECRET","QUERY_SECRET","OTHER_SECRET"] { assert!(!text.contains(secret)); }
    let default = parsed(&run(&["--all",&input]));
    assert_eq!(default["total"],6);
    assert!(!default["cols"].as_array().unwrap().iter().any(|column| column == "equal_bodies"));
}

#[test]
fn metadata_groups_distinguish_status_length_mime_and_unknown_values() {
    let files = Files::new();
    let records = json!([
        {"url":"https://example.test/","status":200,"content_length":12,"content_type":"text/plain"},
        {"url":"https://example.test/","status":201,"content_length":12,"content_type":"text/plain"},
        {"url":"https://example.test/","status":200,"content_length":13,"content_type":"text/plain"},
        {"url":"https://example.test/","status":200,"content_length":12,"content_type":"text/html"},
        {"url":"https://example.test/","status":200,"content_type":"text/plain"},
        {"url":"https://example.test/","status":200,"content_length":0,"content_type":"text/plain"},
        {"url":"https://example.test/","status":200,"content_length":12}
    ]);
    let input = files.put("metadata-distinctions.json", &records.to_string());
    let report = parsed(&run(&["--group-metadata","--all",&input]));
    assert_eq!(report["total"],7);
    let rows = report["rows"].as_array().unwrap();
    let identities: std::collections::BTreeSet<&str> = rows.iter().map(|row| field(&report,row,"identity").as_str().unwrap()).collect();
    assert_eq!(identities.len(),7);
    for row in rows {
        assert!(field(&report,row,"identity").as_str().unwrap().starts_with("meta:"));
        assert_eq!(field(&report,row,"equal_bodies"),false);
        assert_eq!(field(&report,row,"count"),1);
    }
}

#[test]
fn metadata_groups_never_absorb_partial_full_empty_or_digest_only_bodies() {
    let files = Files::new();
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let records = json!([
        {"url":"https://example.test/","status":200,"content_length":3,"content_type":"text/plain"},
        {"url":"https://example.test/","status":200,"content_length":3,"content_type":"text/plain","body":null},
        {"url":"https://example.test/","status":200,"content_length":3,"content_type":"text/plain","body":"a"},
        {"url":"https://example.test/","status":200,"content_length":3,"content_type":"text/plain","body":"abc"},
        {"url":"https://example.test/","status":200,"content_length":3,"content_type":"text/plain","sha256":digest},
        {"url":"https://example.test/","status":200,"content_length":3,"content_type":"text/plain","body":""}
    ]);
    let input = files.put("metadata-versus-bodies.json", &records.to_string());
    let grouped = parsed(&run(&["--group-metadata","--all",&input]));
    let default = parsed(&run(&["--all",&input]));
    assert_eq!(grouped["total"],4);
    assert_eq!(default["total"],5);
    let rows = grouped["rows"].as_array().unwrap();
    let metadata = rows.iter().find(|row| field(&grouped,row,"identity").as_str().unwrap().starts_with("meta:")).unwrap();
    assert_eq!(field(&grouped,metadata,"count"),2);
    assert_eq!(field(&grouped,metadata,"equal_bodies"),false);
    assert_eq!(field(&grouped,metadata,"bytes"), &json!([3]));
    for (body, count) in [("a",1),("abc",2),("",1)] {
        let identity = format!("sha256:{}",llm_pipeline_tools::sha256(body.as_bytes()));
        let row = rows.iter().find(|row| field(&grouped,row,"identity") == &json!(identity)).unwrap();
        assert_eq!(field(&grouped,row,"count"),count);
        assert!(field(&grouped,row,"equal_bodies").is_null());
        assert_eq!(field(&grouped,row,"bytes"), &json!([body.len()]));
        let original = default["rows"].as_array().unwrap().iter().find(|row| field(&default,row,"identity") == &json!(identity)).unwrap();
        for column in default["cols"].as_array().unwrap() {
            let column = column.as_str().unwrap();
            assert_eq!(field(&grouped,row,column),field(&default,original,column));
        }
    }
    assert!(rows.iter().any(|row| field(&grouped,row,"identity") == &json!(format!("sha256:{digest}"))));
}

#[test]
fn metadata_grouping_rejects_aura_mode_and_is_documented_in_help() {
    let files = Files::new();
    let input = files.put("incompatible.json", &probe("body").to_string());
    for args in [
        vec!["--group-metadata","--aura",input.as_str()],
        vec!["--aura","--group-metadata",input.as_str()],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(),Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
    let help = run(&["--help"]);
    assert!(help.status.success());
    let text = String::from_utf8(help.stdout).unwrap();
    assert!(text.contains("--group-metadata"));
    assert!(text.contains("equal_bodies:false"));
}
