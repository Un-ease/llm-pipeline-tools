use llm_pipeline_tools::recon::types::*;
use serde_json::{Value,json};
use std::io::Write;
use std::process::{Command,Stdio};

#[test]
fn integer_ports_reject_strings_floats_booleans_and_ranges() {
    for bad in [json!(["443"]),json!([443.5]),json!([true]),json!([-1]),json!([65536])] {
        assert!(serde_json::from_value::<PortsInput>(json!({"hosts":["127.0.0.1"],"ports":bad})).is_err());
    }
    let zero:PortsInput=serde_json::from_value(json!({"hosts":["127.0.0.1"],"ports":[0]})).unwrap();
    assert!(zero.validate().is_err());
    let proper:PortsInput=serde_json::from_value(json!({"hosts":["::1","example.test"],"ports":[80,443]})).unwrap();
    assert!(proper.validate().is_ok());
}

#[test]
fn domains_and_seed_scope_reject_flags_suffix_tricks_and_credentials() {
    for bad in ["https://example.test","-d example.test","*.example.test","a..test","127.0.0.1","a;id.test"] {
        assert!(Domain::parse(bad).is_err(),"{bad}");
    }
    let domain=Domain::parse("EXAMPLE.test.").unwrap();
    assert_eq!(domain.as_str(),"example.test");
    assert!(domain.contains_host("api.example.test"));
    assert!(!domain.contains_host("notexample.test"));
    assert!(!domain.contains_host("example.test.evil.test"));
    assert!(!domain.contains_host("🦀🦀🦀🦀🦀"));
    assert!(WebUrl::parse("https://user:password@example.test/").is_err());
    let outside:UrlsInput=serde_json::from_value(json!({"domain":"example.test","mode":"crawl","seeds":["https://example.test.evil.test/"]})).unwrap();
    assert!(outside.validate().is_err());
}

#[test]
fn discovery_prohibits_authority_paths_and_unbounded_products() {
    for path in ["//evil.test/","/x\r\nHost:evil.test","/has space","/x#fragment","/\\evil.test/"] {
        let input:DiscoverInput=serde_json::from_value(json!({"hosts":["127.0.0.1"],"paths":[path]})).unwrap();
        assert!(input.validate().is_err(),"{path}");
    }
    let input:DiscoverInput=serde_json::from_value(json!({"hosts":vec!["example.test";32],"ports":[80,443],"paths":vec!["/";5]})).unwrap();
    assert!(input.validate().is_err());
    assert!(serde_json::from_value::<DiscoverInput>(json!({"hosts":["example.test"],"flags":"-insecure"})).is_err());
}

fn mcp(messages:&[Value])->Vec<Value> {
    let mut child=Command::new(env!("CARGO_BIN_EXE_recon_mcp")).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    {
        let mut input=child.stdin.take().unwrap();
        for message in messages { writeln!(input,"{message}").unwrap(); }
    }
    let out=child.wait_with_output().unwrap();
    assert!(out.status.success(),"{}",String::from_utf8_lossy(&out.stderr));
    assert!(out.stderr.is_empty(),"{}",String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().lines().map(|s|serde_json::from_str(s).unwrap()).collect()
}

#[test]
fn mcp_advertises_workflows_and_rejects_bad_inputs_without_execution() {
    let out=mcp(&[
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"recon_ports","arguments":{"hosts":["127.0.0.1"],"ports":["443"]}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"recon_subdomains","arguments":{"domain":"example.test","shell":"id"}}})
    ]);
    assert_eq!(out.len(),4);
    assert_eq!(out[0]["result"]["protocolVersion"],"2025-03-26");
    let tools=out[1]["result"]["tools"].as_array().unwrap();
    let ports=tools.iter().find(|t|t["name"]=="recon_ports").unwrap();
    assert_eq!(ports["inputSchema"]["properties"]["ports"]["items"]["type"],"integer");
    assert_eq!(ports["inputSchema"]["additionalProperties"],false);
    for rejected in &out[2..] {
        assert_eq!(rejected["result"]["isError"],true);
        let body:Value=serde_json::from_str(rejected["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert!(body["receipt"].is_null());
        assert!(body["error"].as_str().unwrap().contains("invalid typed input"));
        assert!(rejected["result"].get("structuredContent").is_none());
    }
}

#[test]
fn oversized_mcp_frame_is_rejected_without_losing_the_next_request() {
    let out=mcp(&[
        json!({"jsonrpc":"2.0","id":1,"method":"ping","params":{"oversized":"x".repeat(65536)}}),
        json!({"jsonrpc":"2.0","id":2,"method":"ping"})
    ]);
    assert_eq!(out.len(),2);
    assert_eq!(out[0]["error"]["code"],-32600);
    assert_eq!(out[1]["id"],2);
    assert_eq!(out[1]["result"],json!({}));
}

#[test]
fn cli_invalid_request_emits_no_success_stdout_and_no_fake_receipt() {
    let mut child=Command::new(env!("CARGO_BIN_EXE_recon_ports")).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(br#"{"hosts":["127.0.0.1"],"ports":"80,443"}"#).unwrap();
    let out=child.wait_with_output().unwrap();
    assert_eq!(out.status.code(),Some(2));
    assert!(out.stdout.is_empty());
    let error:Value=serde_json::from_slice(&out.stderr).unwrap();
    assert!(error["receipt"].is_null());
}

#[test]
fn verdict_confirmed_requires_existing_fact_references_and_is_not_a_fact() {
    let mut input:VerdictInput=serde_json::from_value(json!({"run":"00000000000000000000000000000000","verdict":"confirmed","evidence":[],"note":"claim"})).unwrap();
    assert!(input.validate().is_err());
    input.evidence.push(1);
    assert!(input.validate().is_ok());
    assert!(serde_json::from_value::<VerdictInput>(json!({"run":input.run,"verdict":"confirmed","evidence":[1],"note":"claim","fact":true})).is_err());
}

#[test]
fn url_modes_do_not_silently_discard_or_invent_crawl_intent() {
    for request in [
        json!({"domain":"example.test","mode":"crawl"}),
        json!({"domain":"example.test","mode":"combined","seeds":[]}),
        json!({"domain":"example.test","mode":"archive","seeds":["https://example.test/"]})
    ] {
        let input:UrlsInput=serde_json::from_value(request).unwrap();
        assert!(input.validate().is_err());
    }
    assert!(serde_json::from_value::<UrlsInput>(json!({"domain":"example.test","mode":"--shell"})).is_err());
}

#[test]
fn invalid_json_rpc_ids_and_non_object_params_are_rejected_without_dispatch() {
    let replies=mcp(&[
        json!({"jsonrpc":"2.0","id":true,"method":"ping"}),
        json!({"jsonrpc":"2.0","id":{},"method":"ping"}),
        json!({"jsonrpc":"2.0","id":[],"method":"ping"}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":[]}),
        json!({"jsonrpc":"2.0","id":"ready","method":"ping"})
    ]);
    for reply in &replies[..3] {
        assert_eq!(reply["error"]["code"],-32600);
        assert!(reply["id"].is_null());
    }
    assert_eq!(replies[3]["error"]["code"],-32602);
    assert_eq!(replies[4]["result"],json!({}));
}

#[test]
fn localhost_names_are_case_insensitive_and_accept_a_dns_root_dot() {
    for name in ["localhost","LOCALHOST","LocalHost."] {
        let host=Host::parse(name).unwrap();
        assert_eq!(host.as_str(),"localhost");
        assert_eq!(serde_json::to_value(host).unwrap(),"localhost");
    }
}
