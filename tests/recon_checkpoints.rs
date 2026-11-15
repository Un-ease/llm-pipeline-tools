use llm_pipeline_tools::recon::types::{CrawlCheckpoint, ResolveInput, SurfaceInput, UrlsInput};
use serde_json::json;

#[test]
fn checkpoint_cannot_escape_seed_origin_or_increase_depth() {
    for (url, origin, depth) in [
        ("https://evil.test/account", "https://evil.test", 1),
        ("http://example.test/account", "http://example.test", 1),
        ("https://example.test:8443/account", "https://example.test:8443", 1),
        ("https://example.test/account", "https://example.test", 3),
        ("https://example.test/account", "https://evil.test", 1),
    ] {
        let input: UrlsInput = serde_json::from_value(json!({"domain":"example.test","mode":"crawl","seeds":["https://example.test/"],"queue":{"v":1,"pending":[{"url":url,"origin":origin,"depth":depth}]}})).unwrap();
        assert!(input.validate().is_err());
    }
}

#[test]
fn visited_history_has_the_same_origin_boundary_as_pending_work() {
    let input: UrlsInput = serde_json::from_value(json!({"domain":"example.test","mode":"crawl","seeds":["https://example.test/"],"queue":{"v":1,"pending":[],"visited":["https://evil.test/"]}})).unwrap();
    assert!(input.validate().is_err());
}

#[test]
fn resume_reference_and_inline_checkpoint_are_unambiguous() {
    let input: UrlsInput = serde_json::from_value(json!({"domain":"example.test","mode":"crawl","seeds":["https://example.test/"],"resume":"a".repeat(32),"queue":{"v":1,"pending":[]}})).unwrap();
    assert!(input.validate().is_err());
    let queue: CrawlCheckpoint = serde_json::from_value(json!({"v":1,"pending":[{"url":"https://example.test/account","origin":"https://example.test","depth":1}],"visited":["https://example.test/"]})).unwrap();
    assert_eq!(queue.pending.len(),1);
    assert_eq!(queue.pending[0].url.as_str(),"https://example.test/account");
}

#[test]
fn resolve_rejects_cross_domain_input_and_model_policy_overrides() {
    let outside: ResolveInput = serde_json::from_value(json!({"hosts":["example.test.evil.test"],"domain":"example.test"})).unwrap();
    assert!(outside.validate().is_err());
    assert!(serde_json::from_value::<ResolveInput>(json!({"hosts":["example.test"],"scope":"arbitrary.json"})).is_err());
    let too_many: ResolveInput = serde_json::from_value(json!({"hosts":vec!["example.test";513]})).unwrap();
    assert!(too_many.validate().is_err());
}

#[test]
fn receipt_resolution_is_exclusive_and_does_not_accept_paths_as_run_ids() {
    let source:ResolveInput=serde_json::from_value(json!({"source_run":"a".repeat(32)})).unwrap();
    assert!(source.validate().is_ok());
    for request in [
        json!({"hosts":["a.example.test"],"source_run":"a".repeat(32)}),
        json!({"source_run":"../scope.json"}),
        json!({"hosts":[]})
    ] {
        let input:ResolveInput=serde_json::from_value(request).unwrap();
        assert!(input.validate().is_err());
    }
}

#[test]
fn surface_prefixes_are_paths_not_authorities_or_query_expressions() {
    for prefix in ["//other.test/","/settings?token=x","/settings#fragment","/has space","/a\\b"] {
        let input:SurfaceInput=serde_json::from_value(json!({"run":"a".repeat(32),"prefix":prefix})).unwrap();
        assert!(input.validate().is_err());
    }
}
