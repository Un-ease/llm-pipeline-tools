use llm_pipeline_tools::recon::result::{PartialInfo, WorkflowResult};
use llm_pipeline_tools::recon::saved::{SavedObservation, SavedWorkflow};
use llm_pipeline_tools::recon::surface::{self, COLUMNS};
use llm_pipeline_tools::recon::types::{Domain, SurfaceInput};
use serde_json::{Value, json};

fn source(rows: Vec<String>, observations: Vec<SavedObservation>) -> SavedWorkflow {
    SavedWorkflow {
        run:"a".repeat(32),hash:"b".repeat(64),cursor:"fixture-cursor".into(),tool:"recon_urls".into(),
        status:"completed".into(),completeness:"complete".into(),domain:Domain::parse("example.test").unwrap(),
        request:json!({"tool":"recon_urls","source":"typed_tool_request",
            "input":{"domain":"example.test","mode":"combined","seeds":["https://example.test/"]}}),
        payload:json!({"v":2,"tool":"recon_urls","rows":rows,"total":rows.len(),"omitted":0,
            "completeness":"complete","coverage":{}}),result_seq:100,observations,partial:None,
    }
}
fn input(prefix: Option<&str>) -> SurfaceInput {
    SurfaceInput { run:"a".repeat(32),site:None,prefix:prefix.map(str::to_owned) }
}
fn urls(paths: &[&str]) -> Vec<String> { paths.iter().map(|path|format!("https://example.test{path}")).collect() }
fn response(seq: u64, path: &str, status: u16) -> SavedObservation {
    SavedObservation { seq,kind:"crawl_live_response".into(),
        data:json!({"url":format!("https://example.test{path}"),"status":status,"kind":"navigation"}) }
}
fn discovery(seq: u64, discovered: Value) -> SavedObservation {
    SavedObservation { seq,kind:"crawl_link_discovery".into(),
        data:json!({"from":"https://example.test/","discovered":discovered}) }
}
fn cell<'a>(row: &'a Value, name: &str) -> &'a Value {
    &row[COLUMNS.iter().position(|column| *column == name).unwrap()]
}
fn find<'a>(result: &'a WorkflowResult, origin: &str, path: &str) -> &'a Value {
    result.rows.iter().find(|row|cell(row,"origin") == origin && cell(row,"path") == path).unwrap()
}
fn assert_bounds(value: &Value) {
    assert_eq!(value["items"].as_array().unwrap().len() as u64 + value["omitted"].as_u64().unwrap(),value["total"]);
    assert!(value["items"].as_array().unwrap().len() <= 3);
}

#[test]
fn default_clusters_expose_different_route_surfaces_without_repeated_leaves() {
    let mut paths: Vec<String> = (0..180).map(|i|format!("https://example.test/catalog/items/leaf-{i}")).collect();
    paths.extend(urls(&["/account/settings/profile","/account/settings/security","/help/topics/start"]));
    let result = surface::summarize(&input(None),source(paths,vec![])).unwrap();
    assert_eq!(result.cols,COLUMNS);
    assert_eq!(result.rows.len(),3);
    assert_eq!(cell(&result.rows[0],"path"),"/catalog/items");
    let cluster = find(&result,"https://example.test","/catalog/items");
    assert_eq!(cell(cluster,"families"),180);
    assert_eq!(cell(cluster,"candidate_occurrences"),180);
    assert_eq!(cell(cluster,"examples")["total"],180);
    assert_eq!(cell(cluster,"examples")["omitted"],177);
    find(&result,"https://example.test","/account/settings");
    find(&result,"https://example.test","/help/topics");
    assert_eq!(result.coverage["network_requests"],0);
    assert_eq!(result.coverage["source"]["source_run"],"a".repeat(32));
    assert_eq!(result.coverage["source"]["source_hash"],"b".repeat(64));
    assert_eq!(result.coverage["source"]["source_result_seq"],100);
}

#[test]
fn prefix_zoom_is_slash_bounded_and_returns_detailed_families() {
    let paths = urls(&["/account/settings","/account/settings/","/account/settings/profile",
        "/account/settingsevil","/account/settingsevil/profile","/other/account/settings"]);
    let result = surface::summarize(&input(Some("/account/settings/")),source(paths,vec![])).unwrap();
    assert_eq!(result.coverage["view"],"prefix_families");
    assert_eq!(result.rows.len(),2);
    assert!(result.rows.iter().all(|row|cell(row,"kind") == "route_family"));
    assert_eq!(cell(find(&result,"https://example.test","/account/settings"),"candidate_occurrences"),2);
    find(&result,"https://example.test","/account/settings/profile");
    assert_eq!(result.coverage["counts"]["matched_families"],2);
    assert_eq!(result.coverage["counts"]["route_families"],5);
}

#[test]
fn origins_query_name_multiplicity_and_leaf_operations_remain_distinct() {
    let values = vec![
        "https://example.test/accounts/1/settings?a=secret-one",
        "https://example.test/accounts/2/settings?b=secret-two",
        "https://example.test/accounts/3/settings?a=one&a=two",
        "https://example.test/accounts/4/change-password?a=secret-three",
        "http://example.test/accounts/5/settings?a=secret-four",
        "https://api.example.test/accounts/6/settings?a=secret-five",
        "https://example.test:8443/accounts/7/settings?a=secret-six",
    ].into_iter().map(str::to_owned).collect();
    let result = surface::summarize(&input(Some("/accounts")),source(values,vec![])).unwrap();
    assert_eq!(result.rows.len(),7);
    let origin_rows: Vec<_> = result.rows.iter().filter(|row|cell(row,"origin") == "https://example.test").collect();
    assert_eq!(origin_rows.len(),4);
    for params in [json!(["a"]),json!(["b"]),json!(["a","a"])] {
        assert!(origin_rows.iter().any(|row|cell(row,"path") == "/accounts/:param/settings" && cell(row,"examples")["items"][0]["params"] == params));
    }
    find(&result,"https://example.test","/accounts/:param/change-password");
    assert!(!serde_json::to_string(&result.into_payload("recon_surface")).unwrap().contains("secret"));
}

#[test]
fn recorded_statuses_are_historical_and_do_not_make_inferred_siblings_live() {
    let result = surface::summarize(&input(None),source(
        urls(&["/account/settings/profile","/account/settings/security"]),
        vec![response(10,"/account/settings/profile",200),response(11,"/account/settings/denied",403),
            response(12,"/account/settings/profile",302)])).unwrap();
    let row = find(&result,"https://example.test","/account/settings");
    assert_eq!(cell(row,"candidate_occurrences"),3);
    let statuses = cell(row,"captured_statuses");
    assert_eq!(statuses["responses"],3);
    assert_eq!(statuses["urls"],2);
    assert_eq!(statuses["inferred_urls"],1);
    assert_eq!(statuses["statuses"],json!({"200":1,"302":1,"403":1}));
    assert_eq!(statuses["scope"],"source_run_historical");
    assert_eq!(statuses["current_liveness"],"unknown");
    assert_eq!(result.coverage["counts"]["candidate_response_overlap"],1);
    assert_eq!(result.coverage["counts"]["unique_urls"],3);
    assert_eq!(result.coverage["counts"]["recorded_responses"],3);
    assert_eq!(cell(row,"evidence_seqs"),&json!({"items":[10,11,12],"total":4,"omitted":1}));
}

#[test]
fn repeated_candidates_and_responses_do_not_duplicate_url_counts() {
    let same = "https://example.test/account/settings?mode=secret";
    let result = surface::summarize(&input(Some("/account")),source(vec![same.into(),same.into()],vec![
        discovery(5,json!([same,same])),response(6,"/account/settings?mode=secret",200),
        response(7,"/account/settings?mode=other",404)])).unwrap();
    let row = find(&result,"https://example.test","/account/settings");
    assert_eq!(cell(row,"candidate_occurrences"),2);
    assert_eq!(cell(row,"captured_statuses")["responses"],2);
    assert_eq!(cell(row,"captured_statuses")["urls"],2);
    assert_eq!(result.coverage["counts"]["source_rows"],2);
    assert_eq!(result.coverage["counts"]["discovery_candidates"],2);
    assert_eq!(result.coverage["counts"]["candidate_response_overlap"],1);
}

#[test]
fn legacy_strings_keep_unknown_literal_provenance_and_never_assume_html_links() {
    let mut saved = source(urls(&["/catalog/items/list"]),vec![discovery(8,json!([
        "https://example.test/catalog/items/detail"
    ]))]);
    saved.payload["v"] = json!(1);
    let result = surface::summarize(&input(None),saved).unwrap();
    assert_eq!(result.coverage["counts"]["unknown_provenance_urls"],2);
    assert_eq!(cell(&result.rows[0],"captured_statuses")["inferred_urls"],2);
    assert_eq!(cell(&result.rows[0],"captured_statuses")["responses"],0);
    assert_eq!(cell(&result.rows[0],"evidence_seqs")["items"],json!([8,100]));
    assert_eq!(result.coverage["api_operations"],"unknown");
    assert_eq!(result.coverage["authentication_states"],"unknown");
    assert_eq!(result.coverage["object_graph"],"unknown");
}

#[test]
fn source_partial_and_byte_accounting_are_propagated_without_manufacturing_failures() {
    let partial = PartialInfo { error:"interrupted source".into(),cutoff_reason:"timeout".into(),
        captured_bytes:123,parsed_bytes:101,discarded_tail_bytes:22,backend_exit:None,backend_signal:Some(15) };
    let expected = serde_json::to_value(&partial).unwrap();
    let mut saved = source(urls(&["/account/settings"]),vec![]);
    saved.partial = Some(partial);
    saved.status = "failed".into();
    saved.completeness = "partial".into();
    saved.payload["completeness"] = json!("partial");
    let result = surface::summarize(&input(None),saved).unwrap();
    assert_eq!(result.coverage["partial_origin"],"source_run");
    assert_eq!(serde_json::to_value(result.partial.as_ref().unwrap()).unwrap(),expected);
    let payload = result.into_payload("recon_surface");
    assert_eq!(payload["completeness"],"partial");
    assert_eq!(payload["partial"],expected);
    let complete = surface::summarize(&input(None),source(urls(&["/account/settings"]),vec![])).unwrap();
    assert!(complete.partial.is_none());
    assert!(complete.coverage["partial_origin"].is_null());
}

#[test]
fn excluded_assets_noise_and_symbol_only_literals_are_counted_not_actionable() {
    let result = surface::summarize(&input(None),source(urls(&[
        "/account/settings","/assets/app.js","/images/logo.png","/undefined","/---","/123/settings"
    ]),vec![])).unwrap();
    assert_eq!(result.coverage["counts"]["excluded_candidates"]["static_asset"],2);
    assert_eq!(result.coverage["counts"]["excluded_candidates"]["noise"],2);
    assert_eq!(result.coverage["counts"]["route_candidates"],2);
    assert!(result.rows.iter().all(|row|cell(row,"kind") == "route_cluster"));
    find(&result,"https://example.test","/:param/settings");
}

#[test]
fn recorded_navigation_and_responses_support_symbol_paths_but_script_noise_does_not() {
    let candidates = json!([
        {"url":"https://example.test/---","source":"html_navigation","class":"navigation"},
        {"url":"https://example.test/+++","source":"javascript_literal","class":"literal_noise"},
        {"url":"https://example.test/assets/module","source":"script_src","class":"javascript_asset"},
        {"url":"https://example.test/accounts/{id}/approve","source":"javascript_literal","class":"template_candidate"}
    ]);
    let result = surface::summarize(&input(None),source(vec![],vec![discovery(5,candidates),response(6,"/~~~",404)])).unwrap();
    find(&result,"https://example.test","/---");
    find(&result,"https://example.test","/~~~");
    assert_eq!(result.coverage["counts"]["excluded_candidates"]["noise"],1);
    assert_eq!(result.coverage["counts"]["excluded_candidates"]["static_asset"],1);
    assert_eq!(result.coverage["counts"]["unknown_provenance_urls"],0);
    assert_eq!(result.coverage["api_operations"],"unknown");
    assert_eq!(result.coverage["authentication_states"],"unknown");
    assert_eq!(result.coverage["object_graph"],"unknown");
}

#[test]
fn detailed_variant_and_evidence_clipping_have_exact_totals() {
    let paths = (1..=9).map(|i|format!("https://example.test/accounts/{i}/settings?view=secret-{i}")).collect();
    let responses = (1..=9).map(|i|response(i,&format!("/accounts/{i}/settings?view=secret-{i}"),200)).collect();
    let result = surface::summarize(&input(Some("/accounts")),source(paths,responses)).unwrap();
    assert_eq!(result.rows.len(),1);
    let row = &result.rows[0];
    assert_eq!(cell(row,"examples")["total"],9);
    assert_eq!(cell(row,"examples")["omitted"],6);
    assert_eq!(cell(row,"evidence_seqs")["total"],10);
    assert_eq!(cell(row,"evidence_seqs")["omitted"],7);
    assert_bounds(cell(row,"examples"));
    assert_bounds(cell(row,"evidence_seqs"));
    assert_eq!(cell(row,"captured_statuses")["responses"],9);
    assert_eq!(cell(row,"candidate_occurrences"),9);
    assert!(!serde_json::to_string(&result.into_payload("recon_surface")).unwrap().contains("secret"));
}

#[test]
fn source_bounds_survive_without_raw_errors_bodies_or_query_values() {
    let mut saved = source(urls(&["/account/settings"]),vec![]);
    saved.payload["coverage"] = json!({"crawl":{"max_pages":32,"queue_omitted":17,
        "body_truncated_responses":2,"page_budget_exhausted":true,"discovery_complete":false,
        "operational_failures":["https://example.test/?token=secret-error"]},
        "archive":{"completed":true,"accepted":1,"error":"secret-error"}});
    saved.payload["queue"] = json!({"pending":[{"url":"https://example.test/?token=secret-queue"}],
        "visited":["https://example.test/?token=secret-history"],"omitted":17});
    let result = surface::summarize(&input(None),saved).unwrap();
    let bounds = &result.coverage["source_bounds"];
    assert_eq!(bounds["crawl"]["queue_omitted"],17);
    assert_eq!(bounds["crawl"]["body_truncated_responses"],2);
    assert_eq!(bounds["crawl"]["discovery_complete"],false);
    assert_eq!(bounds["queue"],json!({"pending":1,"visited":1,"omitted":17}));
    assert!(result.partial.is_none());
    assert!(!serde_json::to_string(&result.into_payload("recon_surface")).unwrap().contains("secret"));
}

#[test]
fn site_filter_is_host_bounded_and_keeps_scheme_and_port_identity() {
    let values = vec!["https://api.example.test/catalog/items/one","http://api.example.test/catalog/items/two",
        "https://api.example.test:8443/catalog/items/three","https://notapi.example.test/catalog/items/four"]
        .into_iter().map(str::to_owned).collect();
    let mut request = input(None);
    request.site = Some(Domain::parse("api.example.test").unwrap());
    let result = surface::summarize(&request,source(values,vec![])).unwrap();
    assert_eq!(result.rows.len(),3);
    assert_eq!(result.coverage["counts"]["site_filtered_urls"],1);
    assert!(result.rows.iter().all(|row|!cell(row,"origin").as_str().unwrap().contains("notapi")));
}

#[test]
fn deterministic_order_does_not_depend_on_candidate_input_order() {
    let values = urls(&["/zeta/routes/two","/alpha/routes/two","/alpha/routes/one","/zeta/routes/one"]);
    let first = surface::summarize(&input(None),source(values.clone(),vec![])).unwrap();
    let second = surface::summarize(&input(None),source(values.into_iter().rev().collect(),vec![])).unwrap();
    assert_eq!(first.rows,second.rows);
    assert_eq!(cell(&first.rows[0],"path"),"/alpha/routes");
    for row in &first.rows { assert_bounds(cell(row,"examples")); assert_bounds(cell(row,"evidence_seqs")); }
}

#[test]
fn empty_zoom_is_complete_and_does_not_invent_negative_http_evidence() {
    let result = surface::summarize(&input(Some("/absent")),source(urls(&["/account/settings"]),vec![])).unwrap();
    assert!(result.rows.is_empty());
    assert!(result.partial.is_none());
    assert_eq!(result.coverage["counts"]["route_candidates"],1);
    assert_eq!(result.coverage["counts"]["view_candidates"],0);
    assert_eq!(result.coverage["current_liveness"],"unknown");
    assert_eq!(result.coverage["network_requests"],0);
}

#[test]
fn malformed_compact_evidence_is_an_error_not_a_fallback() {
    for observation in [SavedObservation { seq:2,kind:"crawl_live_response".into(),data:json!({"url":"https://example.test/"}) },
        response(3,"/account",99),
        discovery(4,json!([{"candidate":"/account"}])),
        discovery(5,json!(["https://outside.test/account"]))] {
        assert!(surface::summarize(&input(None),source(urls(&["/account/settings"]),vec![observation])).is_err());
    }
    let mut saved = source(urls(&["/account/settings"]),vec![]);
    saved.tool = "evidence_verdict".into();
    assert!(surface::summarize(&input(None),saved).is_err());
}

#[test]
fn excluded_noise_does_not_contribute_evidence_to_an_identifier_shaped_route() {
    let result = surface::summarize(&input(Some("/accounts")),source(
        urls(&["/accounts/456/settings"]),vec![discovery(8,json!([
            {"url":"https://example.test/accounts/123/settings","source":"javascript_literal","class":"literal_noise"}
        ]))])).unwrap();
    assert_eq!(result.rows.len(),1);
    let row = &result.rows[0];
    assert_eq!(cell(row,"candidate_occurrences"),1);
    assert_eq!(cell(row,"evidence_seqs"),&json!({"items":[100],"total":1,"omitted":0}));
    assert_eq!(result.coverage["counts"]["excluded_candidates"]["noise"],1);
}
