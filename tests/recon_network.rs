// Compile the implementation inside this integration test to access cfg(test)-only
// audit injection. Production entry points still require a real journal Audit.
use llm_pipeline_tools::recon::{audit, policy, resolve, result, types};
type Result<T, E = String> = std::result::Result<T, E>;
#[path = "../src/recon/network.rs"]
#[allow(dead_code)]
mod network;

use base64::{Engine, engine::general_purpose::STANDARD};
use network::test_support as raw_support;
mod test_support {
    use super::*;
    pub fn loopback_policy() -> policy::Policy {
        policy::Policy::from_json(br#"{"v":1,"in_scope":{"hosts":["127.0.0.1","::1","localhost"]},"deny_private_ips":false}"#).unwrap()
    }
    pub fn fetch(url: &Url, record: &(dyn Fn(&str,Value)->Result<()> + Sync)) -> Result<network::Fetch> {
        raw_support::fetch(url,record,&loopback_policy())
    }
    pub fn discover(input: &DiscoverInput, record: &(dyn Fn(&str,Value)->Result<()> + Sync)) -> Result<Value> {
        raw_support::discover(input,record,&loopback_policy()).map(|result| Value::Array(result.rows))
    }
    pub fn ports(input: &PortsInput, record: &(dyn Fn(&str,Value)->Result<()> + Sync)) -> Result<Value> {
        raw_support::ports(input,record,&loopback_policy()).map(|result| Value::Array(result.rows))
    }
    pub(crate) use super::raw_support::{headers,item,outcome,probe};
}
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use types::{DiscoverInput, Host, PortsInput};
use url::Url;

#[derive(Default)]
struct Evidence(Mutex<Vec<(String, Value)>>);
impl Evidence {
    fn record(&self, kind: &str, data: Value) -> Result<()> {
        self.0.lock().unwrap().push((kind.to_owned(), data));
        Ok(())
    }
    fn events(&self, kind: &str) -> Vec<Value> {
        self.0.lock().unwrap().iter().filter(|(name,_)| name == kind).map(|(_,value)| value.clone()).collect()
    }
}

struct HttpFixture {
    address: SocketAddr,
    handle: Option<JoinHandle<Vec<u8>>>,
}
impl HttpFixture {
    fn new(response: Vec<u8>) -> Self { Self::delayed(response, Duration::ZERO) }
    fn delayed(response: Vec<u8>, delay: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let handle = thread::spawn(move || {
            // Rate-limited tests can wait behind other tests, but never hang on failure.
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream,_)) => break stream,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                    Err(error) => panic!("loopback fixture accept: {error}"),
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(4))).unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") && request.len() < 16384 {
                match stream.read(&mut byte) {
                    Ok(0) => break,
                    Ok(_) => request.push(byte[0]),
                    Err(error) => panic!("fixture request read: {error}"),
                }
            }
            thread::sleep(delay);
            // Clients intentionally stop reading at the cap or timeout.
            let _ = stream.write_all(&response);
            request
        });
        Self { address, handle:Some(handle) }
    }
    fn url(&self, path: &str) -> Url { Url::parse(&format!("http://{}{path}",self.address)).unwrap() }
    fn finish(mut self) -> Vec<u8> { self.handle.take().unwrap().join().unwrap() }
}

fn response(status: &str, headers: &[(&str,&str)], body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",body.len()).into_bytes();
    for (name,value) in headers { bytes.extend_from_slice(format!("{name}: {value}\r\n").as_bytes()); }
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn real_http_status_headers_body_and_semantic_evidence() {
    let body = b"<html><title> Actual &amp; Observed \n Title </title></html>";
    let fixture = HttpFixture::new(response("418 I'm a teapot", &[("Content-Type","text/html"),("Server","fixture/1"),("X-Duplicate","one"),("X-Duplicate","two")], body));
    let evidence = Evidence::default();
    let url = fixture.url("/observed?a=1&b=2");
    let fetched = test_support::fetch(&url, &|kind,data| evidence.record(kind,data)).unwrap();
    assert_eq!(fetched.status,418);
    assert_eq!(fetched.body,body);
    assert!(!fetched.truncated);
    assert_eq!(fetched.headers["server"],"fixture/1");
    assert_eq!(fetched.headers["x-duplicate"],"one\ntwo");
    assert_eq!(test_support::item(&url,&fetched),json!({"url":url.as_str(),"status":418,"server":"fixture/1","title":"Actual & Observed Title"}));
    let request = String::from_utf8(fixture.finish()).unwrap().to_ascii_lowercase();
    assert!(request.starts_with("get /observed?a=1&b=2 http/1.1\r\n"));
    assert!(request.contains("accept-encoding: identity\r\n"));
    assert!(!request.contains("authorization:"));
    assert!(!request.contains("cookie:"));
    assert!(!request.contains("proxy-authorization:"));
    let observed = evidence.events("http_response");
    assert_eq!(observed.len(),1);
    assert_eq!(STANDARD.decode(observed[0]["body_base64"].as_str().unwrap()).unwrap(),body);
    let duplicate: Vec<_> = observed[0]["headers"].as_array().unwrap().iter().filter(|header| header["name"] == "x-duplicate")
        .map(|header| STANDARD.decode(header["value_base64"].as_str().unwrap()).unwrap()).collect();
    assert_eq!(duplicate,vec![b"one".to_vec(),b"two".to_vec()]);
    assert_eq!(observed[0]["evidence"],"semantic_http_not_wire_capture");
    assert_eq!(evidence.events("http_request")[0]["redirects"],false);
    for header in evidence.events("http_request")[0]["headers"].as_array().unwrap() {
        let value = String::from_utf8(STANDARD.decode(header["value_base64"].as_str().unwrap()).unwrap()).unwrap();
        assert!(request.contains(&format!("{}: {}\r\n",header["name"].as_str().unwrap(),value.to_ascii_lowercase())));
    }
    let all = evidence.0.lock().unwrap();
    assert!(all.iter().position(|(kind,_)| kind == "http_request").unwrap() < all.iter().position(|(kind,_)| kind == "http_response").unwrap());
}

#[test]
fn redirects_are_returned_without_following_another_origin() {
    let destination = TcpListener::bind("127.0.0.1:0").unwrap();
    destination.set_nonblocking(true).unwrap();
    let location = format!("http://{}/never-fetch",destination.local_addr().unwrap());
    let fixture = HttpFixture::new(response("302 Found",&[("Location",&location),("Set-Cookie","secret=never-send")],b"redirect"));
    let evidence = Evidence::default();
    let fetched = test_support::fetch(&fixture.url("/"),&|kind,data| evidence.record(kind,data)).unwrap();
    assert_eq!(fetched.status,302);
    assert_eq!(fetched.headers["location"],location);
    fixture.finish();
    assert!(matches!(destination.accept(),Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    assert_eq!(evidence.events("http_request").len(),1);
}

#[test]
fn body_cap_uses_lookahead_and_preserves_exact_bounded_bytes() {
    let body = vec![b'x';256*1024+31];
    let fixture = HttpFixture::new(response("200 OK",&[],&body));
    let evidence = Evidence::default();
    let fetched = test_support::fetch(&fixture.url("/"),&|kind,data| evidence.record(kind,data)).unwrap();
    assert_eq!(fetched.body.len(),256*1024);
    assert!(fetched.truncated);
    let observed = &evidence.events("http_response")[0];
    assert_eq!(observed["limit_exceeded"],true);
    assert_eq!(observed["lookahead_byte"],b'x');
    assert_eq!(STANDARD.decode(observed["body_base64"].as_str().unwrap()).unwrap(),body[..256*1024]);
    fixture.finish();
}

#[test]
fn exactly_at_body_cap_is_not_truncated() {
    let fixture = HttpFixture::new(response("200 OK",&[],&vec![b'a';256*1024]));
    let fetched = test_support::fetch(&fixture.url("/"),&|_,_| Ok(())).unwrap();
    assert_eq!(fetched.body.len(),256*1024);
    assert!(!fetched.truncated);
    fixture.finish();
}

#[test]
fn partial_body_failure_keeps_real_response_and_logs_error() {
    let fixture = HttpFixture::new(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort".to_vec());
    let evidence = Evidence::default();
    let fetched = test_support::fetch(&fixture.url("/"),&|kind,data| evidence.record(kind,data)).unwrap();
    assert_eq!(fetched.status,200);
    assert_eq!(fetched.body,b"short");
    assert!(fetched.truncated);
    assert_eq!(evidence.events("http_error")[0]["stage"],"body");
    assert!(evidence.events("http_response")[0]["read_error"].is_string());
    fixture.finish();
}

#[test]
fn request_deadline_logs_timeout_not_an_empty_success() {
    let fixture = HttpFixture::delayed(response("200 OK",&[],b"late"),Duration::from_millis(3250));
    let evidence = Evidence::default();
    assert!(test_support::fetch(&fixture.url("/"),&|kind,data| evidence.record(kind,data)).is_err());
    let failures = evidence.events("http_error");
    assert_eq!(failures.len(),1);
    assert_eq!(failures[0]["timeout"],true);
    assert!(evidence.events("http_response").is_empty());
    fixture.finish();
}

#[test]
fn discovery_returns_only_actual_compact_responses_and_deduplicates() {
    let fixture = HttpFixture::new(response("503 Service Unavailable",&[("Server","local/2"),("Content-Type","text/html")],b"<title>Maintenance</title>"));
    let input = DiscoverInput { hosts:vec![Host::parse("127.0.0.1").unwrap(),Host::parse("127.0.0.1").unwrap()],
        ports:vec![fixture.address.port(),fixture.address.port()],paths:vec!["/".into(),"/".into()] };
    let evidence = Evidence::default();
    let actual = test_support::discover(&input,&|kind,data| evidence.record(kind,data)).unwrap();
    assert_eq!(actual,json!([{"url":fixture.url("/").as_str(),"status":503,"title":"Maintenance","server":"local/2"}]));
    assert_eq!(evidence.events("http_request").len(),1);
    assert_eq!(evidence.events("discovery_coverage")[0]["unique_probes"],1);
    assert!(actual[0].get("body").is_none());
    assert!(actual[0].get("headers").is_none());
    fixture.finish();
}

#[test]
fn tcp_open_and_refused_are_distinct_and_every_attempt_has_evidence() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let open_port = listener.local_addr().unwrap().port();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    let input = PortsInput { hosts:vec![Host::parse("127.0.0.1").unwrap()],ports:vec![open_port,closed_port,open_port] };
    let evidence = Evidence::default();
    let actual = test_support::ports(&input,&|kind,data| evidence.record(kind,data)).unwrap();
    assert_eq!(actual,json!([{"host":"127.0.0.1","ip":"127.0.0.1","port":open_port}]));
    let outcomes = evidence.events("tcp_connect_result");
    assert_eq!(outcomes.len(),2);
    assert_eq!(evidence.events("tcp_connect_intent").len(),2);
    assert!(outcomes.iter().any(|outcome| outcome["port"] == open_port && outcome["outcome"] == "open"));
    assert!(outcomes.iter().any(|outcome| outcome["port"] == closed_port && outcome["outcome"] == "refused"));
    assert!(outcomes.iter().all(|outcome| outcome["outcome"] != "closed"));
    assert_eq!(evidence.events("ports_coverage")[0]["attempts"],2);
}

#[test]
fn all_refused_is_valid_negative_tcp_and_http_coverage() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let hosts = vec![Host::parse("127.0.0.1").unwrap()];
    let evidence = Evidence::default();
    assert_eq!(test_support::ports(&PortsInput { hosts:hosts.clone(),ports:vec![port] },&|kind,data| evidence.record(kind,data)).unwrap(),json!([]));
    assert_eq!(test_support::discover(&DiscoverInput { hosts,ports:vec![port],paths:vec!["/".into()] },&|kind,data| evidence.record(kind,data)).unwrap(),json!([]));
    assert_eq!(evidence.events("discovery_coverage")[0]["http_responses"],0);
    assert_eq!(evidence.events("discovery_coverage")[0]["negative_observations"],1);
    assert_eq!(evidence.events("discovery_coverage")[0]["failed_probes"],0);
}

#[test]
fn pure_timeout_refused_and_error_classification_never_claims_closed() {
    assert_eq!(test_support::outcome(io::Error::from(io::ErrorKind::ConnectionRefused)),"refused");
    assert_eq!(test_support::outcome(io::Error::from(io::ErrorKind::TimedOut)),"timed_out");
    assert_eq!(test_support::outcome(io::Error::from(io::ErrorKind::WouldBlock)),"timed_out");
    assert_eq!(test_support::outcome(io::Error::from(io::ErrorKind::PermissionDenied)),"error");
    assert_eq!(test_support::outcome(io::Error::other("network unavailable")),"error");
}

#[test]
fn ip_literal_resolution_is_recorded_without_dns_claims() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let evidence = Evidence::default();
    let input = PortsInput { hosts:vec![Host::parse("127.0.0.1").unwrap()],ports:vec![listener.local_addr().unwrap().port()] };
    let _ = test_support::ports(&input,&|kind,data| evidence.record(kind,data)).unwrap();
    assert!(evidence.events("resolver_intent").is_empty());
    let resolved = evidence.events("resolver_result");
    assert_eq!(resolved[0]["source"],"ip_literal");
    assert_eq!(resolved[0]["ips"],json!(["127.0.0.1"]));
}

#[test]
fn malformed_inputs_and_budget_caps_are_rejected_before_io() {
    let evidence = Evidence::default();
    let record = |kind: &str,data| evidence.record(kind,data);
    for raw in ["file:///etc/passwd","http://name:secret@127.0.0.1/","http://127.0.0.1:0/"] {
        assert!(test_support::fetch(&Url::parse(raw).unwrap(),&record).is_err());
    }
    for path in ["//elsewhere.invalid/","/x#fragment","/x\\y","/new line","relative"] {
        let input = DiscoverInput { hosts:vec![Host::parse("127.0.0.1").unwrap()],ports:vec![80],paths:vec![path.into()] };
        assert!(test_support::discover(&input,&record).is_err());
    }
    let host = Host::parse("127.0.0.1").unwrap();
    for input in [
        PortsInput { hosts:vec![host.clone();33],ports:vec![80] },
        PortsInput { hosts:vec![host.clone();32],ports:vec![80;9] },
        PortsInput { hosts:vec![host.clone()],ports:vec![0] },
        PortsInput { hosts:vec![],ports:vec![80] },
        PortsInput { hosts:vec![host.clone()],ports:vec![80;129] },
    ] { assert!(test_support::ports(&input,&record).is_err()); }
    for input in [
        DiscoverInput { hosts:vec![host.clone()],ports:vec![80],paths:vec!["/".into();65] },
        DiscoverInput { hosts:vec![host.clone();32],ports:vec![80,443],paths:vec!["/".into();5] },
    ] { assert!(test_support::discover(&input,&record).is_err()); }
    assert!(evidence.0.lock().unwrap().is_empty());
    assert!(serde_json::from_value::<PortsInput>(json!({"hosts":["127.0.0.1"],"ports":["80"]})).is_err());
    assert!(serde_json::from_value::<DiscoverInput>(json!({"hosts":["127.0.0.1"],"flags":"-k"})).is_err());
    let defaults: DiscoverInput = serde_json::from_value(json!({"hosts":["127.0.0.1"]})).unwrap();
    assert_eq!(defaults.ports,vec![80,443]);
    assert_eq!(defaults.paths,vec!["/"]);
}

#[test]
fn scheme_origin_and_lean_extraction_are_deterministic() {
    let ipv6 = Host::parse("::1").unwrap();
    assert_eq!(test_support::probe(&ipv6,8443,"/x?b=2&a=1").unwrap().as_str(),"https://[::1]:8443/x?b=2&a=1");
    assert_eq!(test_support::probe(&Host::parse("example.test").unwrap(),443,"/").unwrap().as_str(),"https://example.test/");
    assert_eq!(test_support::probe(&Host::parse("example.test").unwrap(),8080,"/").unwrap().scheme(),"http");
    let url = Url::parse("http://example.test/").unwrap();
    let mut fetch = network::Fetch { status:200,headers:BTreeMap::new(),body:b"<TITLE> &#x41; &#66; &lt;safe&gt; </TITLE>".to_vec(),truncated:false,read_error:None };
    assert_eq!(test_support::item(&url,&fetch)["title"],"A B <safe>");
    fetch.headers.insert("content-type".into(),"application/json".into());
    assert_eq!(test_support::item(&url,&fetch),json!({"url":url.as_str(),"status":200}));
    fetch.headers.clear();
    fetch.body = format!("<title>{}</title>","x".repeat(500)).into_bytes();
    assert_eq!(test_support::item(&url,&fetch)["title"].as_str().unwrap().len(),256);
}

#[test]
fn audit_failure_prevents_network_and_never_becomes_partial_success() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = Url::parse(&format!("http://{}/",listener.local_addr().unwrap())).unwrap();
    let failure = test_support::fetch(&url,&|_,_| Err("audit unavailable".into())).err().unwrap();
    assert_eq!(failure,"audit unavailable");
    assert!(matches!(listener.accept(),Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    let input = PortsInput { hosts:vec![Host::parse("127.0.0.1").unwrap()],ports:vec![listener.local_addr().unwrap().port()] };
    assert_eq!(test_support::ports(&input,&|_,_| Err("audit unavailable".into())).unwrap_err(),"audit unavailable");
    assert!(matches!(listener.accept(),Err(error) if error.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn rate_limit_is_shared_by_concurrent_fetches() {
    let first = HttpFixture::new(response("200 OK",&[],b"one"));
    let second = HttpFixture::new(response("200 OK",&[],b"two"));
    let stamps = Arc::new(Mutex::new(Vec::new()));
    thread::scope(|scope| {
        let a = scope.spawn(|| test_support::fetch(&first.url("/"),&|kind,_| {
            if kind == "http_request" { stamps.lock().unwrap().push(Instant::now()); }
            Ok(())
        }).unwrap());
        let b = scope.spawn(|| test_support::fetch(&second.url("/"),&|kind,_| {
            if kind == "http_request" { stamps.lock().unwrap().push(Instant::now()); }
            Ok(())
        }).unwrap());
        a.join().unwrap();
        b.join().unwrap();
    });
    let stamps = stamps.lock().unwrap();
    assert_eq!(stamps.len(),2);
    assert!(stamps[1].duration_since(stamps[0]) >= Duration::from_millis(500));
    first.finish();
    second.finish();
}

#[test]
fn non_utf8_header_and_binary_body_are_logged_without_loss() {
    let fixture = HttpFixture::new(b"HTTP/1.1 200 OK\r\nX-Binary: \xff\r\nContent-Length: 3\r\nConnection: close\r\n\r\n\0\xff\xfe".to_vec());
    let evidence = Evidence::default();
    let fetched = test_support::fetch(&fixture.url("/"),&|kind,data| evidence.record(kind,data)).unwrap();
    assert_eq!(fetched.body.as_slice(),b"\0\xff\xfe");
    let observed = evidence.events("http_response");
    let header = observed[0]["headers"].as_array().unwrap().iter().find(|header| header["name"] == "x-binary").unwrap();
    assert_eq!(STANDARD.decode(header["value_base64"].as_str().unwrap()).unwrap(),vec![0xff]);
    assert_eq!(STANDARD.decode(observed[0]["body_base64"].as_str().unwrap()).unwrap(),vec![0,0xff,0xfe]);
    fixture.finish();
}

#[test]
fn missing_intent_receipt_prevents_http_and_tcp_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = Url::parse(&format!("http://{}/",listener.local_addr().unwrap())).unwrap();
    assert_eq!(test_support::fetch(&url,&|kind,_| {
        if kind == "http_request" { Err("intent rejected".into()) } else { Ok(()) }
    }).err().unwrap(),"intent rejected");
    assert!(matches!(listener.accept(),Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    let input = PortsInput { hosts:vec![Host::parse("127.0.0.1").unwrap()],ports:vec![listener.local_addr().unwrap().port()] };
    assert_eq!(test_support::ports(&input,&|kind,_| {
        if kind == "tcp_connect_intent" { Err("intent rejected".into()) } else { Ok(()) }
    }).unwrap_err(),"intent rejected");
    assert!(matches!(listener.accept(),Err(error) if error.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn observed_response_with_failed_audit_does_not_escape_as_success() {
    let fixture = HttpFixture::new(response("200 OK",&[],b"observed but unlogged"));
    let input = DiscoverInput { hosts:vec![Host::parse("127.0.0.1").unwrap()],ports:vec![fixture.address.port()],paths:vec!["/".into()] };
    assert_eq!(test_support::discover(&input,&|kind,_| {
        if kind == "http_response" { Err("response audit failed".into()) } else { Ok(()) }
    }).unwrap_err(),"response audit failed");
    fixture.finish();
}

#[test]
fn operator_research_headers_parse_as_validated_http_headers() {
    let headers = test_support::headers(r#"{"X-HackerOne":"researcher-handle","User-Agent":"Research recon/1","X-Research-Id":"case-123"}"#).unwrap();
    assert_eq!(headers["x-hackerone"],"researcher-handle");
    assert_eq!(headers["user-agent"],"Research recon/1");
    assert_eq!(headers["x-research-id"],"case-123");
    assert!(test_support::headers("{}").unwrap().is_empty());
}

#[test]
fn operator_headers_reject_auth_transport_invalid_values_and_non_objects() {
    for name in ["Host","Authorization","Cookie","Proxy-Authorization","Content-Length","Transfer-Encoding","Connection"] {
        for name in [name.to_owned(),name.to_ascii_uppercase(),name.to_ascii_lowercase()] {
            assert!(test_support::headers(&json!({name:"forbidden"}).to_string()).is_err());
        }
    }
    for raw in [
        r#"{"X-Test":"one\r\nInjected: yes"}"#,
        r#"{"X-Test":"one\ninjected"}"#,
        r#"{"X-Test":"one\rinjected"}"#,
        r#"{"X-Test":"one\u0000two"}"#,
        r#"{"Bad Header":"value"}"#,
        r#"{"X-Test\r\nInjected":"value"}"#,
        r#"{"X-Test":"one","x-test":"two"}"#,
        r#"{"X-Test":12}"#,
        r#"{"X-Test":null}"#,
        r#"{"X-Test":["one"]}"#,
        "null","[]",r#""headers""#,"12","not json",
    ] {
        assert!(test_support::headers(raw).is_err(),"unexpectedly accepted {raw}");
    }
}

#[test]
fn missing_required_headers_prevents_dns_and_socket_activity() {
    use std::sync::atomic::{AtomicUsize,Ordering};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let policy = policy::Policy::from_json(br#"{"v":1,"in_scope":{"hosts":["localhost"]},"deny_private_ips":false,"required_headers":{"X-Research-Id":"not-in-diagnostics"}}"#).unwrap();
    let dns_calls = AtomicUsize::new(0);
    let lookup = |_: &str| {
        dns_calls.fetch_add(1,Ordering::SeqCst);
        Err(network::FetchError::Operational("DNS must not run".into()))
    };
    let evidence = Evidence::default();
    let record = |kind: &str,data| evidence.record(kind,data);
    let url = Url::parse(&format!("http://localhost:{}/",listener.local_addr().unwrap().port())).unwrap();
    let error = raw_support::fetch_with_dns(&url,&record,&policy,&lookup).err().unwrap();
    assert!(error.contains("x-research-id"));
    assert!(!error.contains("not-in-diagnostics"));
    let input = DiscoverInput { hosts:vec![Host::parse("localhost").unwrap()],ports:vec![listener.local_addr().unwrap().port()],paths:vec!["/".into()] };
    assert!(raw_support::discover_with_dns(&input,&record,&policy,&lookup).is_err());
    assert_eq!(dns_calls.load(Ordering::SeqCst),0);
    assert!(evidence.0.lock().unwrap().is_empty());
    assert!(matches!(listener.accept(),Err(error) if error.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn fresh_cname_and_mixed_address_policy_guard_every_network_path() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let policy = policy::Policy::from_json(br#"{"v":1,"in_scope":{"hosts":["app.example.test"]},"provider_cname_denylist":["provider.test"]}"#).unwrap();
    let host = Host::parse("app.example.test").unwrap();
    let url = Url::parse(&format!("http://app.example.test:{port}/")).unwrap();
    for resolution in [
        resolve::Resolution { ips:vec!["8.8.8.8".parse().unwrap()],cnames:vec!["tenant.provider.test".into()],status:"resolved".into() },
        resolve::Resolution { ips:vec!["8.8.8.8".parse().unwrap(),"127.0.0.1".parse().unwrap()],cnames:vec![],status:"resolved".into() },
        resolve::Resolution { ips:vec!["::ffff:127.0.0.1".parse().unwrap()],cnames:vec![],status:"resolved".into() },
    ] {
        let evidence = Evidence::default();
        let record = |kind: &str,data| evidence.record(kind,data);
        let lookup = |_: &str| Ok(resolution.clone());
        assert!(raw_support::fetch_with_dns(&url,&record,&policy,&lookup).is_err());
        assert!(raw_support::discover_with_dns(&DiscoverInput { hosts:vec![host.clone()],ports:vec![port],paths:vec!["/".into()] },&record,&policy,&lookup).is_err());
        assert!(raw_support::ports_with_dns(&PortsInput { hosts:vec![host.clone()],ports:vec![port] },&record,&policy,&lookup).is_err());
        assert!(evidence.events("http_request").is_empty());
        assert!(evidence.events("tcp_connect_intent").is_empty());
    }
    assert!(matches!(listener.accept(),Err(error) if error.kind() == io::ErrorKind::WouldBlock));
}

#[test]
fn one_resolution_is_reused_only_within_discovery_workflow() {
    use std::sync::atomic::{AtomicUsize,Ordering};
    let first = HttpFixture::new(response("404 Not Found",&[],b"missing"));
    let second = HttpFixture::new(response("200 OK",&[],b"present"));
    let policy = test_support::loopback_policy();
    let calls = AtomicUsize::new(0);
    let lookup = |_: &str| {
        calls.fetch_add(1,Ordering::SeqCst);
        Ok(resolve::Resolution { ips:vec!["127.0.0.1".parse().unwrap()],cnames:vec![],status:"resolved".into() })
    };
    let input = DiscoverInput { hosts:vec![Host::parse("localhost").unwrap()],ports:vec![first.address.port(),second.address.port()],paths:vec!["/".into()] };
    let result = raw_support::discover_with_dns(&input,&|_,_| Ok(()),&policy,&lookup).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst),1);
    assert_eq!(result.rows.len(),2);
    assert!(result.partial.is_none());
    first.finish(); second.finish();
}

#[test]
fn exact_attribution_headers_are_sent_and_recorded() {
    let fixture = HttpFixture::new(response("404 Not Found",&[],b"missing"));
    let policy = policy::Policy::from_json(br#"{"v":1,"in_scope":{"hosts":["127.0.0.1"]},"deny_private_ips":false,"required_headers":{"X-Research-Id":"case-123"}}"#).unwrap()
        .with_http_headers(r#"{"X-Research-Id":"case-123","User-Agent":"Research recon/1"}"#).unwrap();
    let evidence = Evidence::default();
    let fetched = raw_support::fetch(&fixture.url("/"),&|kind,data| evidence.record(kind,data),&policy).unwrap();
    assert_eq!(fetched.status,404);
    let sent = String::from_utf8(fixture.finish()).unwrap();
    assert!(sent.to_ascii_lowercase().contains("x-research-id: case-123\r\n"));
    assert!(sent.contains("Research recon/1"));
    let request = &evidence.events("http_request")[0];
    let attribution = request["headers"].as_array().unwrap().iter().find(|header| header["name"] == "x-research-id").unwrap();
    assert_eq!(STANDARD.decode(attribution["value_base64"].as_str().unwrap()).unwrap(),b"case-123");
}

#[test]
fn observed_partial_body_keeps_a_terminal_partial_workflow() {
    let fixture = HttpFixture::new(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort".to_vec());
    let input = DiscoverInput { hosts:vec![Host::parse("127.0.0.1").unwrap()],ports:vec![fixture.address.port()],paths:vec!["/".into()] };
    let result = raw_support::discover(&input,&|_,_| Ok(()),&test_support::loopback_policy()).unwrap();
    assert_eq!(result.rows[0]["status"],200);
    assert!(result.partial.is_some());
    assert_eq!(result.coverage["complete"],false);
    fixture.finish();
}
