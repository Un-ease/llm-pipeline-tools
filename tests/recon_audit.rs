use base64::{Engine, engine::general_purpose::STANDARD};
use llm_pipeline_tools::recon::audit::{Audit, projected_records, verify_acknowledged, verify_records, verify_verdict_references};
use llm_pipeline_tools::recon::types::{ReadInput, VerdictInput};
use llm_pipeline_tools::sha256;
use serde_json::{Value, json};

const RUN: &str = "0123456789abcdef0123456789abcdef";
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const CHUNK: usize = 24 * 1024;

// Saved native-journal-shaped records, never a production journal fallback.
fn transport(event: &Value, cursor_start: usize) -> Vec<Value> {
    let bytes = serde_json::to_vec(event).unwrap();
    let hash = sha256(&bytes);
    bytes.chunks(CHUNK).enumerate().map(|(i, part)| json!({
        "_UID":"1000", "_PID":"1234", "_EXE":"/usr/bin/recon_mcp",
        "_BOOT_ID":"fedcba9876543210fedcba9876543210", "_TRANSPORT":"journal",
        "__CURSOR":format!("s=fixture;i={}", cursor_start+i),
        "RECON_VERSION":"1", "RECON_RUN":RUN,
        "RECON_SEQ":event["seq"].as_u64().unwrap().to_string(),
        "RECON_INDEX":i.to_string(), "RECON_PARTS":bytes.len().div_ceil(CHUNK).to_string(),
        "RECON_HASH":hash, "RECON_SIZE":bytes.len().to_string(),
        "RECON_CHUNK_HASH":sha256(part), "RECON_DATA":STANDARD.encode(part),
    })).collect()
}
fn event(seq: u64, prev: &str, kind: &str, class: &str, data: Value) -> Value {
    json!({"v":1,"run":RUN,"seq":seq,"prev":prev,"kind":kind,"class":class,"data":data})
}
fn fixture(observation: Value) -> Vec<Value> {
    let request = event(1, ZERO, "request", "request", json!({"tool":"recon_ports","input":{"hosts":["fixture.invalid"],"ports":[443]},"source":"typed_tool_request"}));
    let first = transport(&request, 1);
    let observed = event(2, first[0]["RECON_HASH"].as_str().unwrap(), "tcp_attempt", "tool_observation", observation);
    let second = transport(&observed, 1 + first.len());
    let complete = event(3, second[0]["RECON_HASH"].as_str().unwrap(), "complete", "complete", json!({"items":[]}));
    let third = transport(&complete, 1 + first.len() + second.len());
    first.into_iter().chain(second).chain(third).collect()
}
fn verdict(evidence: Vec<u64>) -> VerdictInput {
    VerdictInput { run: RUN.into(), verdict: "confirmed".into(), evidence, note:"model hypothesis, not a tool confirmation".into() }
}

#[test]
fn complete_chain_metadata_is_lean_and_payload_is_explicit() {
    let records = fixture(json!({"status":"open","bytes":"sensitive raw observation"}));
    let lean = verify_records(RUN, &records, false).unwrap();
    assert_eq!(lean["status"], "complete");
    assert_eq!(lean["events"].as_array().unwrap().len(), 3);
    assert_eq!(lean["attribution"]["uid"], "1000");
    assert_eq!(lean["attribution"]["pid"], "1234");
    assert_eq!(lean["attribution"]["exe"], "/usr/bin/recon_mcp");
    assert_eq!(lean["cursor"], records.last().unwrap()["__CURSOR"]);
    assert!(!lean.to_string().contains("sensitive raw observation"));
    assert!(lean["events"][1].get("data").is_none());
    let full = verify_records(RUN, &records, true).unwrap();
    assert_eq!(full["events"][1]["data"]["bytes"], "sensitive raw observation");
    assert!(full["limitations"].as_str().unwrap().contains("not an attestation boundary"));
}

#[test]
fn large_raw_payload_roundtrips_across_unicode_chunk_boundaries() {
    let raw: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    let observation = json!({"raw_base64":STANDARD.encode(&raw),"unicode":"λ🌐\u{0000}".repeat(15_000),"truncated":false});
    let records = fixture(observation.clone());
    assert!(records.len() > 6);
    let result = verify_records(RUN, &records, true).unwrap();
    assert_eq!(result["events"][1]["data"], observation);
    let decoded = STANDARD.decode(result["events"][1]["data"]["raw_base64"].as_str().unwrap()).unwrap();
    assert_eq!(decoded, raw);
}

#[test]
fn chunks_can_be_reordered_without_rewriting_event_sequence() {
    let mut records = fixture(json!({"body":"x".repeat(100_000)}));
    records.reverse();
    assert_eq!(verify_records(RUN, &records, true).unwrap()["status"], "complete");
}

#[test]
fn no_records_or_missing_initial_request_never_looks_successful() {
    assert!(verify_records(RUN, &[], false).is_err());
    let mut records = fixture(json!({}));
    records.remove(0);
    assert!(verify_records(RUN, &records, false).is_err());
}

#[test]
fn request_source_must_match_tool_or_model_classification() {
    for (tool, source) in [
        ("recon_ports", Some("model_supplied")),
        ("evidence_verdict", Some("typed_tool_request")),
        ("recon_ports", None),
        ("evidence_verdict", None),
    ] {
        let mut data = json!({"tool":tool,"input":{}});
        if let Some(source) = source { data["source"] = json!(source); }
        let request = event(1, ZERO, "request", "request", data);
        let records = transport(&request, 1);
        assert!(verify_records(RUN, &records, false).is_err(), "{tool}: {source:?}");
        assert!(verify_acknowledged(RUN, &records, records[0]["RECON_HASH"].as_str().unwrap(), 1, false).is_err());
    }
}

#[test]
fn missing_terminal_is_explicitly_incomplete_and_cannot_supply_verdict() {
    let mut records = fixture(json!({}));
    records.pop();
    assert_eq!(verify_records(RUN, &records, false).unwrap()["status"], "incomplete");
    assert!(verify_verdict_references(&verdict(vec![2]), &records).is_err());
}

#[test]
fn missing_middle_event_is_not_a_completed_chain() {
    let records: Vec<_> = fixture(json!({})).into_iter().filter(|r| r["RECON_SEQ"] != "2").collect();
    assert!(verify_records(RUN, &records, false).is_err());
}

#[test]
fn dropped_transport_chunk_cannot_be_silently_truncated() {
    let mut records = fixture(json!({"body":"x".repeat(100_000)}));
    records.remove(2);
    assert!(verify_records(RUN, &records, true).is_err());
}

#[test]
fn truncated_chunk_with_recomputed_chunk_checksum_still_fails() {
    let mut records = fixture(json!({"body":"x".repeat(100_000)}));
    let mut bytes = STANDARD.decode(records[1]["RECON_DATA"].as_str().unwrap()).unwrap();
    bytes.pop();
    records[1]["RECON_DATA"] = json!(STANDARD.encode(&bytes));
    records[1]["RECON_CHUNK_HASH"] = json!(sha256(&bytes));
    assert!(verify_records(RUN, &records, true).is_err());
}

#[test]
fn checksum_corruption_and_invalid_base64_are_rejected() {
    let mut records = fixture(json!({"status":"open"}));
    records[1]["RECON_CHUNK_HASH"] = json!(ZERO);
    assert!(verify_records(RUN, &records, true).is_err());
    records = fixture(json!({}));
    records[1]["RECON_DATA"] = json!("%%%not base64");
    assert!(verify_records(RUN, &records, true).is_err());
}

#[test]
fn duplicate_chunks_and_cursors_are_rejected() {
    let mut records = fixture(json!({"body":"x".repeat(100_000)}));
    let duplicate = records[1].clone();
    records.push(duplicate);
    assert!(verify_records(RUN, &records, false).is_err());
    records = fixture(json!({}));
    records[1]["__CURSOR"] = records[0]["__CURSOR"].clone();
    assert!(verify_records(RUN, &records, false).is_err());
}

#[test]
fn forged_transport_sequence_does_not_override_payload_sequence() {
    let mut records = fixture(json!({}));
    records[1]["RECON_SEQ"] = json!("7");
    assert!(verify_records(RUN, &records, false).is_err());
    records = fixture(json!({}));
    records[1]["RECON_SEQ"] = json!("02");
    assert!(verify_records(RUN, &records, false).is_err());
}

#[test]
fn self_consistent_changed_observation_cannot_reuse_old_completion() {
    let mut records = fixture(json!({"status":"closed"}));
    let previous = records[0]["RECON_HASH"].as_str().unwrap();
    let changed = event(2, previous, "tcp_attempt", "tool_observation", json!({"status":"open"}));
    records[1] = transport(&changed, 2).remove(0);
    assert!(verify_records(RUN, &records, false).is_err());
}

#[test]
fn forged_previous_hash_is_rejected_even_with_valid_transport_checksums() {
    let mut records = fixture(json!({}));
    let forged = event(2, ZERO, "tcp_attempt", "tool_observation", json!({}));
    records[1] = transport(&forged, 2).remove(0);
    assert!(verify_records(RUN, &records, false).is_err());
}

#[test]
fn trusted_metadata_is_mandatory_and_cannot_be_replaced_by_supplied_fields() {
    for key in ["_UID", "_PID", "_EXE", "_BOOT_ID", "_TRANSPORT", "__CURSOR"] {
        let mut records = fixture(json!({}));
        records[1].as_object_mut().unwrap().remove(key);
        records[1][key.trim_start_matches('_')] = json!("supplied forgery");
        assert!(verify_records(RUN, &records, false).is_err(), "{key}");
    }
}

#[test]
fn mixed_process_boot_or_executable_cannot_extend_a_run() {
    for (key, value) in [("_UID","1001"),("_PID","9999"),("_EXE","/tmp/forged"),("_BOOT_ID",RUN),("_TRANSPORT","stdout")] {
        let mut records = fixture(json!({}));
        records[1][key] = json!(value);
        assert!(verify_records(RUN, &records, false).is_err(), "{key}");
    }
}

#[test]
fn oversized_event_and_wrong_declared_sizes_fail_without_allocation() {
    for (key, value) in [("RECON_SIZE","33554433"),("RECON_PARTS","999999999"),("RECON_SIZE","0"),("RECON_INDEX","999999999")] {
        let mut records = fixture(json!({}));
        records[1][key] = json!(value);
        assert!(verify_records(RUN, &records, false).is_err(), "{key}");
    }
}

#[test]
fn verdict_references_only_real_unique_observations() {
    let records = fixture(json!({"status":"open"}));
    let refs = verify_verdict_references(&verdict(vec![2]), &records).unwrap();
    assert_eq!(refs[0]["seq"], 2);
    assert_eq!(refs[0]["hash"], records[1]["RECON_HASH"]);
    assert_eq!(refs[0]["cursor"], records[1]["__CURSOR"]);
    for evidence in [vec![], vec![0], vec![1], vec![3], vec![4], vec![2,2], vec![u64::MAX]] {
        assert!(verify_verdict_references(&verdict(evidence.clone()), &records).is_err(), "{evidence:?}");
    }
    let mut claim = verdict(vec![2]);
    claim.verdict = "tool_confirmed".into();
    assert!(verify_verdict_references(&claim, &records).is_err());
}

#[test]
fn records_from_another_run_cannot_back_supplied_references() {
    let records = fixture(json!({}));
    let mut claim = verdict(vec![2]);
    claim.run = "ffffffffffffffffffffffffffffffff".into();
    assert!(verify_verdict_references(&claim, &records).is_err());
}

#[test]
fn event_after_completion_is_rejected() {
    let mut records = fixture(json!({}));
    let event = event(4, records.last().unwrap()["RECON_HASH"].as_str().unwrap(), "tcp_attempt", "tool_observation", json!({}));
    records.extend(transport(&event, 4));
    assert!(verify_records(RUN, &records, false).is_err());
}

#[test]
fn model_verdict_stays_separate_and_is_never_referenceable_as_a_fact() {
    let request = event(1, ZERO, "request", "request", json!({"tool":"evidence_verdict","input":{"source_run":"ffffffffffffffffffffffffffffffff"},"source":"model_supplied"}));
    let mut records = transport(&request, 1);
    let opinion = event(2, records[0]["RECON_HASH"].as_str().unwrap(), "verdict", "model_supplied", json!({"source":"model_supplied","tool_confirmed":false,"verdict":"confirmed","evidence":[{"seq":2}]}));
    records.extend(transport(&opinion, 2));
    let complete = event(3, records[1]["RECON_HASH"].as_str().unwrap(), "complete", "complete", json!({"source":"model_supplied","tool_confirmed":false}));
    records.extend(transport(&complete, 3));
    let output = verify_records(RUN, &records, true).unwrap();
    assert_eq!(output["events"][1]["class"], "model_supplied");
    assert_eq!(output["events"][1]["data"]["tool_confirmed"], false);
    assert!(verify_verdict_references(&verdict(vec![2]), &records).is_err());
    for data in [
        json!({"source":"model_supplied","tool_confirmed":true}),
        json!({"source":"typed_tool_request","tool_confirmed":false}),
        json!({"source":"model_supplied"}),
        json!({"tool_confirmed":false}),
    ] {
        let changed = event(3, records[1]["RECON_HASH"].as_str().unwrap(), "complete", "complete", data);
        let mut changed_records = records[..2].to_vec();
        changed_records.extend(transport(&changed, 3));
        assert!(verify_records(RUN, &changed_records, true).is_err());
        assert!(verify_acknowledged(RUN, &changed_records, changed_records[2]["RECON_HASH"].as_str().unwrap(), 3, true).is_err());
    }
    let mut forged = opinion.clone();
    forged["data"]["tool_confirmed"] = json!(true);
    let forged_records: Vec<_> = transport(&request, 1).into_iter().chain(transport(&forged, 2)).collect();
    assert!(verify_records(RUN, &forged_records, false).is_err());
    forged = opinion;
    forged["class"] = json!("tool_observation");
    let forged_records: Vec<_> = transport(&request, 1).into_iter().chain(transport(&forged, 2)).collect();
    assert!(verify_records(RUN, &forged_records, false).is_err());
}

#[test]
fn failure_is_not_mislabeled_complete() {
    let mut records = fixture(json!({}));
    let failure = event(3, records[1]["RECON_HASH"].as_str().unwrap(), "failure", "failure", json!({"error":"backend failed"}));
    records[2] = transport(&failure, 3).remove(0);
    assert_eq!(verify_records(RUN, &records, false).unwrap()["status"], "failure");
}

#[test]
fn duplicate_array_journal_fields_are_not_treated_as_scalar_attribution() {
    let mut records = fixture(json!({}));
    records[1]["_PID"] = json!(["1234","9999"]);
    assert!(verify_records(RUN, &records, false).is_err());
}

#[test]
fn acknowledgement_requires_exact_writer_head_and_count_not_just_any_valid_chain() {
    let records = fixture(json!({"status":"open"}));
    let hash = records.last().unwrap()["RECON_HASH"].as_str().unwrap();
    let receipt = verify_acknowledged(RUN, &records, hash, 3, true).unwrap();
    assert_eq!(receipt.events, 3);
    assert_eq!(receipt.hash, hash);
    assert_eq!(receipt.cursor, records.last().unwrap()["__CURSOR"].as_str().unwrap());
    assert!(verify_acknowledged(RUN, &records, ZERO, 3, true).is_err());
    assert!(verify_acknowledged(RUN, &records, hash, 2, true).is_err());
    assert!(verify_acknowledged(RUN, &records, hash, 4, true).is_err());
    assert!(verify_acknowledged(RUN, &[], hash, 3, true).is_err());
}

#[test]
fn acknowledgement_does_not_accept_truncated_run_even_if_its_prefix_is_valid() {
    let records = fixture(json!({}));
    let initial_hash = records[0]["RECON_HASH"].as_str().unwrap();
    assert!(verify_acknowledged(RUN, &records[..1], initial_hash, 1, false).is_ok());
    assert!(verify_acknowledged(RUN, &records[..1], initial_hash, 1, true).is_err());
    let observation_hash = records[1]["RECON_HASH"].as_str().unwrap();
    assert!(verify_acknowledged(RUN, &records[..2], observation_hash, 2, true).is_err());
    let expected_hash = records[2]["RECON_HASH"].as_str().unwrap();
    assert!(verify_acknowledged(RUN, &records[..2], expected_hash, 3, true).is_err());
}

#[test]
fn alternate_consistent_chain_cannot_acknowledge_original_expected_hash() {
    let original = fixture(json!({"status":"closed"}));
    let forged = fixture(json!({"status":"open"}));
    assert!(verify_records(RUN, &forged, false).is_ok());
    assert!(verify_acknowledged(RUN, &forged, original.last().unwrap()["RECON_HASH"].as_str().unwrap(), 3, true).is_err());
}

#[test]
fn noncanonical_json_cannot_hide_duplicate_keys_or_whitespace() {
    let records = fixture(json!({}));
    let bytes = STANDARD.decode(records[0]["RECON_DATA"].as_str().unwrap()).unwrap();
    let original: Value = serde_json::from_slice(&bytes).unwrap();
    let pretty = serde_json::to_vec_pretty(&original).unwrap();
    let duplicate = format!("{{\"seq\":999,{}", std::str::from_utf8(&bytes).unwrap().trim_start_matches('{')).into_bytes();
    for changed in [pretty, duplicate] {
        let mut changed_records = vec![records[0].clone()];
        changed_records[0]["RECON_DATA"] = json!(STANDARD.encode(&changed));
        changed_records[0]["RECON_HASH"] = json!(sha256(&changed));
        changed_records[0]["RECON_CHUNK_HASH"] = json!(sha256(&changed));
        changed_records[0]["RECON_SIZE"] = json!(changed.len().to_string());
        assert!(verify_records(RUN, &changed_records, false).is_err());
    }
}

#[test]
fn audit_can_be_shared_by_scoped_network_workers() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Audit>();
}

fn projection_input() -> ReadInput {
    serde_json::from_value(json!({"run":RUN})).unwrap()
}

fn projection_fixture() -> Vec<Value> {
    let entries = [
        ("request", "request", json!({"tool":"recon_discover","input":{},"source":"typed_tool_request"})),
        ("http_response", "tool_observation", json!({"url":"https://fixture.invalid/ok","host":"fixture.invalid","status":200,"body_base64":"private raw body"})),
        ("http_error", "tool_observation", json!({"url":"https://fixture.invalid/timeout","error":"private backend diagnostic"})),
        ("tcp_attempt", "tool_observation", json!({"host":"fixture.invalid","status":"open"})),
        ("http_response", "tool_observation", json!({"url":"https://fixture.invalid/missing","status":404})),
        ("http_response", "tool_observation", json!({"url":"https://fixture.invalid/second","status":200,"outcome":"observed"})),
        ("complete", "complete", json!({"count":5})),
    ];
    let mut records = Vec::new();
    let mut prev = ZERO.to_owned();
    for (i, (kind, class, data)) in entries.into_iter().enumerate() {
        let chunks = transport(&event(i as u64 + 1, &prev, kind, class, data), records.len() + 1);
        prev = chunks[0]["RECON_HASH"].as_str().unwrap().into();
        records.extend(chunks);
    }
    records
}

#[test]
fn projected_metadata_keeps_run_integrity_and_useful_summaries_without_payloads() {
    let records = projection_fixture();
    let output = projected_records(&projection_input(), &records).unwrap();
    let legacy = verify_records(RUN, &records, false).unwrap();
    for field in ["run", "tool", "status", "hash", "cursor", "attribution", "limits", "limitations"] {
        assert_eq!(output[field], legacy[field], "{field}");
    }
    assert_eq!(output["run_events"], 7);
    assert_eq!(output["events_total"], 7);
    assert_eq!(output["events_omitted"], 0);
    assert_eq!(output["offset"], 0);
    assert!(output["next_offset"].is_null());
    for entry in output["events"].as_array().unwrap() {
        for field in ["hash", "cursor", "data"] { assert!(entry.get(field).is_none(), "{field}"); }
    }
    assert_eq!(output["events"][1]["url"], "https://fixture.invalid/ok");
    assert_eq!(output["events"][1]["host"], "fixture.invalid");
    assert_eq!(output["events"][1]["status"], 200);
    assert_eq!(output["events"][2]["outcome"], "error");
    assert_eq!(output["events"][3]["outcome"], "open");
    assert_eq!(output["events"][5]["outcome"], "observed");
    assert!(!output.to_string().contains("private raw body"));
    assert!(!output.to_string().contains("private backend diagnostic"));
    // The legacy fixture API retains per-event integrity even without payloads.
    assert!(legacy["events"][1]["hash"].is_string());
    assert!(legacy["events"][1]["cursor"].is_string());
    assert!(legacy.get("events_total").is_none());
}

#[test]
fn projected_payload_and_integrity_defaults_can_be_overridden_independently() {
    let records = projection_fixture();
    let legacy = verify_records(RUN, &records, true).unwrap();
    let mut input = projection_input();
    input.include_payloads = true;
    let full = projected_records(&input, &records).unwrap();
    for (entry, original) in full["events"].as_array().unwrap().iter().zip(legacy["events"].as_array().unwrap()) {
        for field in ["data", "hash", "cursor", "bytes", "seq", "kind", "class"] {
            assert_eq!(entry[field], original[field], "{field}");
        }
    }
    input.include_integrity = Some(false);
    let payload_only = projected_records(&input, &records).unwrap();
    assert_eq!(payload_only["events"][1]["data"], legacy["events"][1]["data"]);
    assert!(payload_only["events"][1].get("hash").is_none());
    assert!(payload_only["events"][1].get("cursor").is_none());
    assert_eq!(payload_only["hash"], legacy["hash"]);
    input.include_payloads = false;
    input.include_integrity = Some(true);
    let integrity_only = projected_records(&input, &records).unwrap();
    assert_eq!(integrity_only["events"][1]["hash"], legacy["events"][1]["hash"]);
    assert_eq!(integrity_only["events"][1]["cursor"], legacy["events"][1]["cursor"]);
    assert!(integrity_only["events"][1].get("data").is_none());
    let explicit_full = projected_records(&ReadInput::full(RUN.into()), &records).unwrap();
    assert_eq!(explicit_full, full);
}

#[test]
fn projected_filters_intersect_before_offsets_and_totals_reconcile() {
    let records = projection_fixture();
    let mut input = projection_input();
    input.select.kind = vec!["http_response".into(), "http_error".into()];
    input.select.class = vec!["tool_observation".into()];
    input.select.status = vec![200];
    input.select.seq = vec![2, 3, 5, 6];
    input.limit = 1;
    let first = projected_records(&input, &records).unwrap();
    assert_eq!(first["run_events"], 7);
    assert_eq!(first["events_total"], 2);
    assert_eq!(first["events_omitted"], 1);
    assert_eq!(first["events"][0]["seq"], 2);
    assert_eq!(first["next_offset"], 1);
    input.offset = first["next_offset"].as_u64().unwrap() as usize;
    let second = projected_records(&input, &records).unwrap();
    assert_eq!(second["offset"], 1);
    assert_eq!(second["events_total"], 2);
    assert_eq!(second["events_omitted"], 1);
    assert_eq!(second["events"][0]["seq"], 6);
    assert!(second["next_offset"].is_null());
    for offset in [2, 3, 4096] {
        input.offset = offset;
        let empty = projected_records(&input, &records).unwrap();
        assert_eq!(empty["offset"], offset);
        assert_eq!(empty["events_total"], 2);
        assert_eq!(empty["events_omitted"], 2);
        assert_eq!(empty["events"], json!([]));
        assert!(empty["next_offset"].is_null());
    }
    input.offset = 0;
    input.select.class = vec!["request".into()];
    let none = projected_records(&input, &records).unwrap();
    assert_eq!(none["events_total"], 0);
    assert_eq!(none["events_omitted"], 0);
    assert_eq!(none["events"], json!([]));
    input.select.class = vec!["tool_observation".into()];
    input.select.seq = vec![5];
    assert_eq!(projected_records(&input, &records).unwrap()["events_total"], 0);
}

#[test]
fn projected_http_status_filter_never_matches_absent_or_non_numeric_status() {
    let mut input = projection_input();
    input.select.status = vec![200];
    for data in [
        json!({}), json!({"status":null}), json!({"status":"200"}), json!({"status":"open"}),
        json!({"status":200.0}), json!({"status":true}), json!({"status":404}),
    ] {
        let output = projected_records(&input, &fixture(data)).unwrap();
        assert_eq!(output["events_total"], 0);
        assert_eq!(output["events"], json!([]));
    }
    let output = projected_records(&input, &fixture(json!({"status":200}))).unwrap();
    assert_eq!(output["events_total"], 1);
    assert_eq!(output["events"][0]["seq"], 2);
}

#[test]
fn projection_verifies_corrupt_records_outside_filter_and_page() {
    let mut records = projection_fixture();
    let mut input = projection_input();
    input.select.kind = vec!["request".into()];
    input.limit = 1;
    records[5]["RECON_CHUNK_HASH"] = json!(ZERO);
    assert!(projected_records(&input, &records).is_err());
    input.select.kind.clear();
    assert!(projected_records(&input, &records).is_err());
    let mut records = projection_fixture();
    records[0]["_PID"] = json!("9999");
    input.offset = 5;
    assert!(projected_records(&input, &records).is_err());
}

#[test]
fn projection_retains_terminal_state_even_when_terminal_is_filtered_out() {
    let mut input = projection_input();
    input.select.kind = vec!["http_response".into()];
    let mut records = projection_fixture();
    records.pop();
    let output = projected_records(&input, &records).unwrap();
    assert_eq!(output["status"], "incomplete");
    assert_eq!(output["run_events"], 6);
    assert_eq!(output["events_total"], 3);
    assert!(verify_verdict_references(&verdict(vec![2]), &records).is_err());
}

#[test]
fn partial_failure_preserves_raw_capture_poison_flag_and_legacy_receipt_contract() {
    let partial = json!({"error":"backend exited","cutoff_reason":"backend_exit","captured_bytes":40,
        "parsed_bytes":32,"discarded_tail_bytes":8,"backend_exit":1,"backend_signal":null});
    let mut records = fixture(json!({"raw_base64":STANDARD.encode(b"complete\nunfinished"),"partial":partial}));
    let failure = event(3, records[1]["RECON_HASH"].as_str().unwrap(), "failure", "failure",
        json!({"error":"backend exited","unrecorded_observation":true,"partial":partial}));
    records[2] = transport(&failure, 3).remove(0);
    let output = projected_records(&ReadInput::full(RUN.into()), &records).unwrap();
    assert_eq!(output["status"], "failure");
    assert_eq!(output["events"][2]["kind"], "failure");
    assert_eq!(output["events"][2]["class"], "failure");
    assert_eq!(output["events"][2]["data"]["partial"], partial);
    assert_eq!(output["events"][2]["data"]["unrecorded_observation"], true);
    assert_eq!(output["events"][1]["data"]["raw_base64"], STANDARD.encode(b"complete\nunfinished"));
    let legacy = verify_records(RUN, &records, true).unwrap();
    assert_eq!(legacy["status"], "failure");
    assert_eq!(legacy["events"][2]["data"], output["events"][2]["data"]);
    let receipt = verify_acknowledged(RUN, &records, records[2]["RECON_HASH"].as_str().unwrap(), 3, true).unwrap();
    assert_eq!(receipt.events, 3);
    let mut input = projection_input();
    input.select.class = vec!["tool_observation".into()];
    assert_eq!(projected_records(&input, &records).unwrap()["status"], "failure");
    let _: fn(&Audit, &str, &Value) -> llm_pipeline_tools::Result<llm_pipeline_tools::recon::audit::Receipt> = Audit::abort_with_partial;
}

#[test]
fn projection_validates_input_bounds_before_producing_output() {
    let records = projection_fixture();
    let mut input = projection_input();
    input.limit = 0;
    assert!(projected_records(&input, &records).is_err());
    input.limit = 4097;
    assert!(projected_records(&input, &records).is_err());
    input.limit = 1;
    input.offset = 4097;
    assert!(projected_records(&input, &records).is_err());
    input.offset = 0;
    input.select.status = vec![0];
    assert!(projected_records(&input, &records).is_err());
}
