use base64::{Engine, engine::general_purpose::STANDARD};
use llm_pipeline_tools::{recon::{audit::projected_records, saved::{decode_projection, load, load_surface}, types::ReadInput}, sha256};
use serde_json::{Value, json};

const RUN: &str = "0123456789abcdef0123456789abcdef";
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const TOOL: &str = "recon_urls";

fn result(tool: &str, rows: Value) -> Value {
    json!({"v":2,"tool":tool,"total":rows.as_array().unwrap().len(),"omitted":0,"rows":rows,
        "cols":[],"coverage":{"historical_and_link_discovery_is_not_live_verification":true},
        "completeness":"complete","queue":null})
}

fn partial() -> Value {
    json!({"error":"fixture backend interrupted","cutoff_reason":"timeout","captured_bytes":37,
        "parsed_bytes":23,"discarded_tail_bytes":9,"backend_exit":null,"backend_signal":15})
}

// These are caller-owned native-journal-shaped fixtures. Neither this helper nor
// the pure decoder authenticates storage/sender origin; production must use Audit::read.
fn records(tool: &str, payload: Value, status: &str, compact: bool) -> Vec<Value> {
    let mut entries = vec![("request", "request", json!({"tool":tool,"input":{"domain":"fixture.invalid","mode":"archive","seeds":[]},"source":"typed_tool_request"}))];
    // A body capture is verified but deliberately excluded from the source projection.
    entries.push(("http_response", "tool_observation", json!({"url":"https://fixture.invalid/private?token=body-secret","body":"raw-body-secret"})));
    if compact {
        entries.push(("crawl_live_response", "tool_observation", json!({"url":"https://fixture.invalid/observed?token=never-in-metadata","status":403,"depth":1,"kind":"navigation","body_truncated":false,"evidence_type":"observed_live_http_response"})));
        entries.push(("crawl_link_discovery", "tool_observation", json!({"from":"https://fixture.invalid/observed","asserted_live":false,
            "discovered":[{"url":"https://fixture.invalid/account/7?token=retained-original","candidate":"/account/7?token=retained-original","source":"html_anchor","class":"navigation","queue_status":"queued","asserted_live":false},"https://fixture.invalid/legacy"],"discarded":[]})));
    }
    let terminal = if status == "failure" {
        json!({"error":payload["partial"]["error"],"partial":payload["partial"],"unrecorded_observation":false})
    } else if payload["v"] == 2 {
        json!({"v":2,"tool":tool,"total":payload["total"],"completeness":payload["completeness"],"coverage":payload["coverage"]})
    } else { payload["items"].clone() };
    entries.push(("workflow_result", "tool_observation", payload));
    entries.push((status, status, terminal));
    let mut output = Vec::new();
    let mut previous = ZERO.to_owned();
    for (index, (kind, class, data)) in entries.into_iter().enumerate() {
        let event = json!({"v":1,"run":RUN,"seq":index+1,"prev":previous,"kind":kind,"class":class,"data":data});
        let bytes = serde_json::to_vec(&event).unwrap();
        previous = sha256(&bytes);
        let count = bytes.len().div_ceil(24 * 1024);
        for (part, chunk) in bytes.chunks(24 * 1024).enumerate() {
            output.push(json!({"_UID":"1000","_PID":"1234","_EXE":"/usr/bin/recon_mcp",
                "_BOOT_ID":"fedcba9876543210fedcba9876543210","_TRANSPORT":"journal","__CURSOR":format!("s=fixture;i={}",output.len()+1),
                "RECON_VERSION":"1","RECON_RUN":RUN,"RECON_SEQ":(index+1).to_string(),"RECON_INDEX":part.to_string(),
                "RECON_PARTS":count.to_string(),"RECON_HASH":previous,"RECON_SIZE":bytes.len().to_string(),
                "RECON_CHUNK_HASH":sha256(chunk),"RECON_DATA":STANDARD.encode(chunk)}));
        }
    }
    output
}

fn input(compact: bool) -> ReadInput {
    let mut input = ReadInput::full(RUN.into());
    input.select.kind = ["request", "workflow_result", "complete", "failure"].into_iter().map(str::to_owned).collect();
    if compact { input.select.kind.extend(["crawl_live_response".into(), "crawl_link_discovery".into()]); }
    input.select.class = ["request", "tool_observation", "complete", "failure"].into_iter().map(str::to_owned).collect();
    input
}

fn projection(tool: &str, payload: Value, status: &str, compact: bool) -> Value {
    projected_records(&input(compact), &records(tool, payload, status, compact)).unwrap()
}

fn complete() -> Value {
    projection(TOOL, result(TOOL, json!(["https://fixture.invalid/account/7?secret=original"])), "complete", false)
}

fn event_mut<'a>(projection: &'a mut Value, kind: &str) -> &'a mut Value {
    projection["events"].as_array_mut().unwrap().iter_mut().find(|event| event["kind"] == kind).unwrap()
}

#[test]
fn completed_legacy_versions_move_original_strings_into_rows() {
    for version in [None, Some(1)] {
        let originals = json!(["HTTPS://Api.Fixture.Invalid:443/a?secret=preserved#original"]);
        let mut legacy = json!({"tool":TOOL,"items":originals});
        if let Some(version) = version { legacy["v"] = json!(version); }
        let saved = decode_projection(RUN, TOOL, projection(TOOL, legacy, "complete", false)).unwrap();
        assert_eq!(saved.payload["rows"], originals);
        assert!(saved.payload.get("items").is_none());
        assert_eq!(saved.completeness, "complete");
        assert!(saved.partial.is_none());
        saved.require_complete().unwrap();
    }
}

#[test]
fn completed_v2_preserves_source_head_request_and_compact_facts() {
    let payload = result(TOOL, json!(["https://fixture.invalid/account/7?secret=original"]));
    let projected = projection(TOOL, payload.clone(), "complete", true);
    let expected_hash = projected["hash"].clone();
    let expected_cursor = projected["cursor"].clone();
    let saved = decode_projection(RUN, TOOL, projected).unwrap();
    assert_eq!(saved.payload, payload);
    assert_eq!(saved.request["input"]["domain"], "fixture.invalid");
    assert_eq!(saved.request["source"], "typed_tool_request");
    assert_eq!(saved.domain.as_str(), "fixture.invalid");
    assert_eq!(saved.result_seq, 5);
    assert_eq!(saved.observations.len(), 2);
    assert_eq!(saved.observations[0].seq, 3);
    assert_eq!(saved.observations[0].data["status"], 403);
    assert_eq!(saved.observations[1].data["discovered"][0]["source"], "html_anchor");
    assert_eq!(saved.observations[1].data["discovered"][1], "https://fixture.invalid/legacy");
    let metadata = saved.metadata();
    assert_eq!(metadata["source_run"], RUN);
    assert_eq!(metadata["source_hash"], expected_hash);
    assert_eq!(metadata["source_cursor"], expected_cursor);
    assert_eq!(metadata["source_result_seq"], 5);
    assert_eq!(metadata["source_status"], "complete");
    assert_eq!(metadata["source_completeness"], "complete");
    assert!(!metadata.to_string().contains("secret"));
    assert!(!metadata.to_string().contains("token"));
    assert!(!format!("{saved:?}").contains("raw-body-secret"));
    saved.require_complete().unwrap();
}

#[test]
fn verified_projection_checks_excluded_body_records_before_filtering() {
    let payload = result(TOOL, json!([]));
    let mut chain = records(TOOL, payload, "complete", false);
    let projected = projected_records(&input(false), &chain).unwrap();
    assert_eq!(projected["run_events"], 4);
    assert_eq!(projected["events_total"], 3);
    assert!(!projected.to_string().contains("raw-body-secret"));
    chain[1]["RECON_CHUNK_HASH"] = json!(ZERO);
    assert!(projected_records(&input(false), &chain).is_err());
}

#[test]
fn pure_decoder_validates_shape_but_does_not_authenticate_caller_json() {
    let mut caller_owned = complete();
    event_mut(&mut caller_owned, "workflow_result")["data"]["rows"][0] = json!("https://fixture.invalid/caller-replacement");
    // Deliberately accepted syntax is NOT proof of origin or a recomputed chain.
    let saved = decode_projection(RUN, TOOL, caller_owned).unwrap();
    assert_eq!(saved.payload["rows"][0], "https://fixture.invalid/caller-replacement");
}

#[test]
fn retained_partial_failure_preserves_exact_byte_facts_and_is_not_complete() {
    let mut payload = result(TOOL, json!(["https://fixture.invalid/retained"]));
    payload["completeness"] = json!("partial");
    payload["partial"] = partial();
    let saved = decode_projection(RUN, TOOL, projection(TOOL, payload.clone(), "failure", true)).unwrap();
    assert_eq!(saved.status, "failure");
    assert_eq!(saved.completeness, "partial");
    assert_eq!(serde_json::to_value(saved.partial.as_ref().unwrap()).unwrap(), partial());
    assert_eq!(saved.payload, payload);
    assert!(saved.require_complete().is_err());
    assert_eq!(saved.metadata()["source_status"], "failure");
}

#[test]
fn complete_and_retained_partial_zero_source_rows_are_honest_empty_sets() {
    for tool in ["recon_subdomains", TOOL] {
        let saved = decode_projection(RUN, tool, projection(tool, result(tool, json!([])), "complete", false)).unwrap();
        assert!(saved.payload["rows"].as_array().unwrap().is_empty());
        saved.require_complete().unwrap();
    }
    let mut payload = result(TOOL, json!([]));
    payload["completeness"] = json!("partial");
    payload["partial"] = partial();
    let saved = decode_projection(RUN, TOOL, projection(TOOL, payload, "failure", false)).unwrap();
    assert!(saved.payload["rows"].as_array().unwrap().is_empty());
    assert!(saved.require_complete().is_err());
}

#[test]
fn wrong_tools_and_model_attribution_are_not_source_facts() {
    assert!(decode_projection(RUN, "evidence_verdict", complete()).is_err());
    assert!(decode_projection(RUN, "recon_subdomains", complete()).is_err());
    for field in ["tool", "source"] {
        let mut projected = complete();
        event_mut(&mut projected, "request")["data"][field] = json!(if field == "tool" { "evidence_verdict" } else { "model_supplied" });
        assert!(decode_projection(RUN, TOOL, projected).is_err());
    }
    for replacement in ["model_supplied", "request", "complete"] {
        let mut projected = complete();
        event_mut(&mut projected, "workflow_result")["class"] = json!(replacement);
        assert!(decode_projection(RUN, TOOL, projected).is_err());
    }
    let mut projected = complete();
    event_mut(&mut projected, "workflow_result")["data"]["tool"] = json!("recon_subdomains");
    assert!(decode_projection(RUN, TOOL, projected).is_err());
}

#[test]
fn source_domains_isolate_rows_and_compact_crawl_evidence() {
    for host in ["elsewhere.invalid", "fixture.invalid.evil.invalid", "notfixture.invalid"] {
        for tool in ["recon_subdomains", TOOL] {
            let row = if tool == TOOL { format!("https://{host}/a") } else { host.into() };
            assert!(decode_projection(RUN, tool, projection(tool, result(tool, json!([row])), "complete", false)).is_err());
        }
    }
    for value in ["file:///fixture.invalid/a", "https://user:password@fixture.invalid/a", "not a URL", "https://127.0.0.1/a"] {
        assert!(decode_projection(RUN, TOOL, projection(TOOL, result(TOOL, json!([value])), "complete", false)).is_err());
    }
    let subdomains = result("recon_subdomains", json!(["Fixture.Invalid.", "a.fixture.invalid"]));
    assert!(decode_projection(RUN, "recon_subdomains", projection("recon_subdomains", subdomains, "complete", false)).is_ok());
    for (kind, key) in [("crawl_live_response", "url"), ("crawl_link_discovery", "from")] {
        let mut projected = projection(TOOL, result(TOOL, json!([])), "complete", true);
        event_mut(&mut projected, kind)["data"][key] = json!("https://elsewhere.invalid/path");
        assert!(decode_projection(RUN, TOOL, projected).is_err());
    }
    let mut projected = projection(TOOL, result(TOOL, json!([])), "complete", true);
    event_mut(&mut projected, "crawl_link_discovery")["data"]["discovered"][0]["url"] = json!("https://elsewhere.invalid/path");
    assert!(decode_projection(RUN, TOOL, projected).is_err());
}

#[test]
fn missing_duplicate_and_malformed_result_events_are_rejected() {
    let mut missing = complete();
    missing["events"].as_array_mut().unwrap().retain(|event| event["kind"] != "workflow_result");
    missing["events_total"] = json!(2);
    assert!(decode_projection(RUN, TOOL, missing).is_err());
    let mut duplicate = complete();
    let mut extra = event_mut(&mut duplicate, "workflow_result").clone();
    extra["seq"] = json!(2);
    duplicate["events"].as_array_mut().unwrap().insert(1, extra);
    duplicate["events_total"] = json!(4);
    assert!(decode_projection(RUN, TOOL, duplicate).is_err());
    for payload in [json!(null), json!({"tool":TOOL,"items":"not-an-array"}),
        json!({"v":3,"tool":TOOL,"rows":[]}), json!({"v":"2","tool":TOOL,"rows":[]}),
        json!({"v":2,"tool":TOOL,"rows":[{}],"total":1,"omitted":0,"completeness":"complete"})] {
        let mut projected = complete();
        event_mut(&mut projected, "workflow_result")["data"] = payload;
        assert!(decode_projection(RUN, TOOL, projected).is_err());
    }
    for domain in [json!(null), json!("https://fixture.invalid"), json!("*.fixture.invalid")] {
        let mut projected = complete();
        event_mut(&mut projected, "request")["data"]["input"]["domain"] = domain;
        assert!(decode_projection(RUN, TOOL, projected).is_err());
    }
}

#[test]
fn omitted_projection_payloads_and_inconsistent_head_metadata_are_rejected() {
    for (field, value) in [("events_omitted", json!(1)), ("events_total", json!(7)), ("offset", json!(1)),
        ("next_offset", json!(3)), ("run_events", json!(4097)), ("run", json!("fedcba9876543210fedcba9876543210")),
        ("hash", json!("invalid")), ("cursor", json!("")), ("status", json!("incomplete"))] {
        let mut projected = complete();
        projected[field] = value;
        assert!(decode_projection(RUN, TOOL, projected).is_err(), "{field}");
    }
    for key in ["data", "hash", "cursor"] {
        let mut projected = complete();
        event_mut(&mut projected, "workflow_result").as_object_mut().unwrap().remove(key);
        assert!(decode_projection(RUN, TOOL, projected).is_err(), "{key}");
    }
    let mut projected = complete();
    projected["hash"] = json!(ZERO);
    assert!(decode_projection(RUN, TOOL, projected).is_err());
    let mut projected = complete();
    projected["cursor"] = json!("different-terminal-cursor");
    assert!(decode_projection(RUN, TOOL, projected).is_err());
}

#[test]
fn incomplete_or_contradictory_terminals_and_result_totals_are_rejected() {
    let mut no_terminal = complete();
    no_terminal["events"].as_array_mut().unwrap().pop();
    no_terminal["events_total"] = json!(2);
    assert!(decode_projection(RUN, TOOL, no_terminal).is_err());
    for (key, value) in [("total", json!(2)), ("omitted", json!(1)), ("completeness", json!("partial")),
        ("completeness", json!("unknown")), ("partial", partial()), ("items", json!([]))] {
        let mut projected = complete();
        event_mut(&mut projected, "workflow_result")["data"][key] = value;
        assert!(decode_projection(RUN, TOOL, projected).is_err(), "result {key}");
    }
    for key in ["total", "omitted", "completeness"] {
        let mut projected = complete();
        event_mut(&mut projected, "workflow_result")["data"].as_object_mut().unwrap().remove(key);
        assert!(decode_projection(RUN, TOOL, projected).is_err(), "missing {key}");
    }
    for (key, value) in [("total", json!(2)), ("tool", json!("recon_subdomains")), ("completeness", json!("partial")), ("v", json!(1))] {
        let mut projected = complete();
        event_mut(&mut projected, "complete")["data"][key] = value;
        assert!(decode_projection(RUN, TOOL, projected).is_err(), "terminal {key}");
    }
    let legacy = json!({"tool":TOOL,"items":[]});
    assert!(decode_projection(RUN, TOOL, projection(TOOL, legacy, "failure", false)).is_err());
    assert!(decode_projection(RUN, TOOL, projection(TOOL, result(TOOL, json!([])), "failure", false)).is_err());
}

#[test]
fn malformed_or_unretained_partial_information_is_never_invented() {
    let mut payload = result(TOOL, json!([]));
    payload["completeness"] = json!("partial");
    payload["partial"] = partial();
    for key in ["error", "cutoff_reason", "captured_bytes", "parsed_bytes", "discarded_tail_bytes", "backend_exit", "backend_signal"] {
        let mut malformed = payload.clone();
        malformed["partial"].as_object_mut().unwrap().remove(key);
        assert!(decode_projection(RUN, TOOL, projection(TOOL, malformed, "failure", false)).is_err(), "missing {key}");
    }
    for (key, value) in [("captured_bytes", json!(1)), ("error", json!("")), ("cutoff_reason", json!("")),
        ("backend_signal", json!(0)), ("backend_exit", json!(2)), ("parsed_bytes", json!("23"))] {
        let mut malformed = payload.clone();
        malformed["partial"][key] = value;
        assert!(decode_projection(RUN, TOOL, projection(TOOL, malformed, "failure", false)).is_err(), "invalid {key}");
    }
    for key in ["partial", "unrecorded_observation"] {
        let mut projected = projection(TOOL, payload.clone(), "failure", false);
        event_mut(&mut projected, "failure")["data"].as_object_mut().unwrap().remove(key);
        assert!(decode_projection(RUN, TOOL, projected).is_err());
    }
    let mut projected = projection(TOOL, payload.clone(), "failure", false);
    event_mut(&mut projected, "failure")["data"]["unrecorded_observation"] = json!(true);
    assert!(decode_projection(RUN, TOOL, projected).is_err());
    let mut projected = projection(TOOL, payload.clone(), "failure", false);
    event_mut(&mut projected, "failure")["data"]["partial"]["captured_bytes"] = json!(38);
    assert!(decode_projection(RUN, TOOL, projected).is_err());
    let mut projected = projection(TOOL, payload, "failure", false);
    event_mut(&mut projected, "failure")["data"]["error"] = json!("different error");
    assert!(decode_projection(RUN, TOOL, projected).is_err());
}

#[test]
fn filesystem_paths_never_become_loader_sources() {
    for path in ["/tmp/caller-selected.json", "../source.json", "file:///tmp/source.json"] {
        assert!(load(path, TOOL).is_err());
        assert!(load_surface(path).is_err());
    }
}

#[test]
fn legacy_completion_snapshots_must_match_and_cannot_replace_v2_summaries() {
    let legacy=json!({"tool":TOOL,"items":["https://fixture.invalid/account"]});
    for terminal in [
        json!([]),
        json!(["https://fixture.invalid/other"]),
        json!({"items":[]}),
        json!({"items":"not-an-array"})
    ] {
        let mut projected=projection(TOOL,legacy.clone(),"complete",false);
        event_mut(&mut projected,"complete")["data"]=terminal;
        assert!(decode_projection(RUN,TOOL,projected).is_err());
    }
    let mut v2=complete();
    event_mut(&mut v2,"complete")["data"]=json!(["https://fixture.invalid/account/7?secret=original"]);
    assert!(decode_projection(RUN,TOOL,v2).is_err());
}
