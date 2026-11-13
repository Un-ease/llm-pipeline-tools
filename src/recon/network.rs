use super::audit::Audit;
use super::types::{DiscoverInput, Host, PortsInput, WebUrl};
use super::policy::Policy;
use super::resolve::{self as dns, Resolution};
use super::result::{PartialInfo, WorkflowResult};
use crate::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use regex::Regex;
use reqwest::blocking::Client;
#[cfg(test)]
use reqwest::header::HeaderMap;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use url::Url;

const BODY_LIMIT: usize = 256 * 1024;
const ATTEMPT_LIMIT: usize = 256;
const HTTP_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(300);
static HTTP_GATE: Mutex<Option<Instant>> = Mutex::new(None);
type Recorder<'a> = dyn Fn(&str, Value) -> Result<()> + Sync + 'a;

#[cfg(test)]
fn parse_operator_headers(raw: &str) -> Result<HeaderMap> { super::policy::parse_headers(raw) }
type Resolver<'a> = dyn Fn(&str) -> Result<Resolution, FetchError> + Sync + 'a;

pub struct Fetch {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub truncated: bool,
    pub read_error: Option<String>,
}

#[derive(Debug)]
pub enum FetchError {
    Operational(String),
    Negative(String),
    Audit(String),
    Invalid(String),
}
impl FetchError {
    fn message(self) -> String {
        match self { Self::Operational(e) | Self::Negative(e) | Self::Audit(e) | Self::Invalid(e) => e }
    }
}

fn record_failure(record: &Recorder<'_>, kind: &str, data: Value, error: String) -> FetchError {
    match record(kind, data) {
        Ok(()) => FetchError::Operational(error),
        Err(e) => FetchError::Audit(e),
    }
}

fn resolve(host: &str, policy: &Policy, record: &Recorder<'_>, resolver: &Resolver<'_>) -> Result<Resolution, FetchError> {
    policy.check_host(host).map_err(FetchError::Invalid)?;
    let resolution = if let Ok(ip) = host.parse::<IpAddr>() {
        record("resolver_result", json!({"host":host,"source":"ip_literal","ips":[ip.to_string()]})).map_err(FetchError::Audit)?;
        Resolution { ips:vec![ip],cnames:Vec::new(),status:"ip_literal".into() }
    } else { resolver(host)? };
    policy.check_resolution(host,&resolution.ips,&resolution.cnames).map_err(FetchError::Invalid)?;
    if resolution.ips.is_empty() {
        return Err(if matches!(resolution.status.as_str(),"nxdomain" | "nodata") {
            FetchError::Negative(format!("DNS {} for {host}",resolution.status))
        } else { FetchError::Operational(format!("no observed addresses for {host}")) });
    }
    Ok(resolution)
}

fn url_host(url: &Url) -> Result<String> {
    match url.host() {
        Some(url::Host::Domain(host)) => Ok(host.to_owned()),
        Some(url::Host::Ipv4(ip)) => Ok(ip.to_string()),
        Some(url::Host::Ipv6(ip)) => Ok(ip.to_string()),
        None => Err("HTTP URL has no host".into()),
    }
}

pub fn fetch(url: &Url, audit: &Audit) -> Result<Fetch, FetchError> {
    let policy = Policy::load().map_err(FetchError::Invalid)?;
    policy.check_http().map_err(FetchError::Invalid)?;
    policy.record(audit).map_err(FetchError::Audit)?;
    let record = |kind: &str, data| audit.record(kind,data);
    let resolver = |host: &str| dns::lookup(host,&policy,audit).map_err(FetchError::Audit);
    fetch_impl(url,&record,None,&policy,&resolver)
}

fn fetch_impl(url: &Url, record: &Recorder<'_>, resolved: Option<&Resolution>, policy: &Policy, resolver: &Resolver<'_>) -> Result<Fetch, FetchError> {
    let checked = WebUrl::parse(url.as_str()).map_err(FetchError::Invalid)?;
    let url = checked.as_url();
    let operator_headers = policy.http_headers().map_err(FetchError::Invalid)?;
    let host = url_host(url).map_err(FetchError::Invalid)?;
    policy.check_host(&host).map_err(FetchError::Invalid)?;
    let owned;
    let resolution = match resolved {
        Some(resolution) => resolution,
        None => { owned = resolve(&host,policy,record,resolver)?; &owned }
    };
    policy.check_resolution(&host,&resolution.ips,&resolution.cnames).map_err(FetchError::Invalid)?;
    let ips = &resolution.ips;
    if ips.is_empty() { return Err(FetchError::Operational(format!("no observed addresses for {host}"))); }
    let port = url.port_or_known_default().ok_or_else(|| FetchError::Invalid("HTTP URL has no port".into()))?;
    let addresses: Vec<_> = ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
    let client = Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
        .referer(false).http1_only().timeout(HTTP_TIMEOUT).connect_timeout(HTTP_TIMEOUT)
        .pool_max_idle_per_host(0).resolve_to_addrs(&host, &addresses).build()
        .map_err(|error| record_failure(record, "http_error", json!({"url":url.as_str(),"stage":"client","error":error.to_string()}), error.to_string()))?;
    let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
    let request = client.get(url.clone()).header(reqwest::header::HOST, authority)
        .headers(operator_headers).build()
        .map_err(|error| record_failure(record, "http_error", json!({"url":url.as_str(),"stage":"request_build","error":error.to_string()}), error.to_string()))?;
    let effective_headers: Vec<_> = request.headers().iter().map(|(name, value)| {
        json!({"name":name.as_str(),"value_base64":STANDARD.encode(value.as_bytes())})
    }).collect();
    // Keep the guard through I/O: concurrent workflows cannot dispatch a burst.
    let mut gate = HTTP_GATE.lock().map_err(|_| record_failure(record, "http_error",
        json!({"url":url.as_str(),"stage":"rate_limiter","error":"HTTP rate limiter poisoned"}), "HTTP rate limiter poisoned".into()))?;
    if let Some(previous) = *gate {
        let elapsed = previous.elapsed();
        let interval = policy.request_interval();
        if elapsed < interval { std::thread::sleep(interval - elapsed); }
    }
    record("http_request", json!({"method":"GET","url":url.as_str(),"evidence":"semantic_http_not_wire_capture",
        "headers":effective_headers,"operator_headers_source":"RECON_HTTP_HEADERS",
        "body_base64":"","timeout_ms":3000,"body_limit":BODY_LIMIT,"redirects":false,
        "tls_validation":true,"proxy":false,"cookies":false,"authentication":false,
        "resolved_ips":ips.iter().map(ToString::to_string).collect::<Vec<_>>()})).map_err(FetchError::Audit)?;
    *gate = Some(Instant::now());
    let mut response = client.execute(request).map_err(|error| {
        let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        let mut refused = false;
        while let Some(current) = cause {
            if current.downcast_ref::<io::Error>().is_some_and(|error| error.kind() == io::ErrorKind::ConnectionRefused) { refused = true; }
            cause = current.source();
        }
        let message = format!("GET {url}: {error}");
        match record("http_error",json!({"url":url.as_str(),"stage":"request","error":error.to_string(),
            "timeout":error.is_timeout(),"connect":error.is_connect(),"connection_refused":refused})) {
            Err(error) => FetchError::Audit(error),
            Ok(()) if refused => FetchError::Negative(message),
            Ok(()) => FetchError::Operational(message),
        }
    })?;
    let status = response.status().as_u16();
    let exact_headers: Vec<_> = response.headers().iter().map(|(name, value)| {
        json!({"name":name.as_str(),"value_base64":STANDARD.encode(value.as_bytes())})
    }).collect();
    let mut headers = BTreeMap::<String, String>::new();
    for (name, value) in response.headers() {
        let value = String::from_utf8_lossy(value.as_bytes());
        headers.entry(name.to_string()).and_modify(|old| { old.push('\n'); old.push_str(&value); })
            .or_insert_with(|| value.into_owned());
    }
    let mut body = Vec::new();
    let mut read_error = None;
    let mut buffer = [0u8; 8192];
    // One lookahead byte distinguishes an exactly-at-limit body from truncation.
    while body.len() <= BODY_LIMIT {
        let remaining = (BODY_LIMIT + 1 - body.len()).min(buffer.len());
        match response.read(&mut buffer[..remaining]) {
            Ok(0) => break,
            Ok(count) => body.extend_from_slice(&buffer[..count]),
            Err(error) => { read_error = Some(error.to_string()); break; }
        }
    }
    let limit_exceeded = body.len() > BODY_LIMIT;
    let lookahead = if limit_exceeded { Some(body[BODY_LIMIT]) } else { None };
    body.truncate(BODY_LIMIT);
    let truncated = limit_exceeded || read_error.is_some();
    record("http_response", json!({"url":url.as_str(),"evidence":"semantic_http_not_wire_capture",
        "status":status,"version":format!("{:?}",response.version()),"headers":exact_headers,
        "body_base64":STANDARD.encode(&body),"body_bytes":body.len(),"truncated":truncated,
        "body_limit":BODY_LIMIT,"limit_exceeded":limit_exceeded,"lookahead_byte":lookahead,"read_error":read_error,
        "remote_addr":response.remote_addr().map(|address| address.to_string())})).map_err(FetchError::Audit)?;
    if let Some(error) = &read_error {
        record("http_error", json!({"url":url.as_str(),"stage":"body","error":error,
            "response_observed":true,"partial_body_recorded":true})).map_err(FetchError::Audit)?;
    }
    Ok(Fetch { status, headers, body, truncated, read_error })
}

fn compact_text(text: &str, limit: usize) -> String {
    let mut result = String::new();
    let mut count = 0;
    for word in text.split_whitespace() {
        if count == limit { break; }
        if !result.is_empty() { result.push(' '); count += 1; }
        for c in word.chars().filter(|c| !c.is_control()) {
            if count == limit { break; }
            result.push(c);
            count += 1;
        }
    }
    if result.ends_with(' ') { result.pop(); }
    result
}

fn title(body: &[u8]) -> Option<String> {
    static TITLE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?is)<title(?:\s[^>]*)?>(.*?)</title\s*>").expect("constant title regex"));
    static ENTITY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"&(#x[0-9a-fA-F]+|#[0-9]+|amp|lt|gt|quot|apos|nbsp);").expect("constant entity regex"));
    let text = String::from_utf8_lossy(body);
    let capture = TITLE.captures(&text)?;
    let decoded = ENTITY.replace_all(&capture[1], |captures: &regex::Captures<'_>| {
        let entity = &captures[1];
        let code = if let Some(hex) = entity.strip_prefix("#x") { u32::from_str_radix(hex, 16).ok() }
            else if let Some(decimal) = entity.strip_prefix('#') { decimal.parse().ok() }
            else { match entity { "amp" => Some(38), "lt" => Some(60), "gt" => Some(62), "quot" => Some(34), "apos" => Some(39), "nbsp" => Some(32), _ => None } };
        code.and_then(char::from_u32).map(|c| c.to_string()).unwrap_or_else(|| captures[0].to_owned())
    });
    let text = compact_text(&decoded, 256);
    if text.is_empty() { None } else { Some(text) }
}

fn response_item(url: &Url, response: &Fetch) -> Value {
    let mut item = json!({"url":url.as_str(),"status":response.status});
    if response.headers.get("content-type").is_none_or(|value| value.to_ascii_lowercase().contains("html")) {
        if let Some(title) = title(&response.body) { item["title"] = json!(title); }
    }
    if let Some(server) = response.headers.get("server") {
        let server = compact_text(server, 256);
        if !server.is_empty() { item["server"] = json!(server); }
    }
    item
}

fn probe_url(host: &Host, port: u16, path: &str) -> Result<Url> {
    let scheme = if matches!(port, 443 | 8443) { "https" } else { "http" };
    let authority = if host.as_str().contains(':') { format!("[{}]",host.as_str()) } else { host.as_str().to_owned() };
    // Parse only after joining to the fixed authority; never join a network-path reference.
    let url = Url::parse(&format!("{scheme}://{authority}:{port}{path}")).map_err(|error| error.to_string())?;
    if url_host(&url)? != host.as_str() || url.port_or_known_default() != Some(port) {
        return Err("probe path changed target authority".into());
    }
    Ok(url)
}

pub fn discover(input: &DiscoverInput, audit: &Audit) -> Result<WorkflowResult> {
    let policy = Policy::load()?;
    policy.check_http()?;
    policy.record(audit)?;
    discover_impl(input,&|kind,data| audit.record(kind,data),&policy,
        &|host| dns::lookup(host,&policy,audit).map_err(FetchError::Audit))
}

fn incomplete(errors: &[String], reason: &str) -> Option<PartialInfo> {
    if errors.is_empty() { return None; }
    Some(PartialInfo { error:errors.join("; "),cutoff_reason:reason.into(),captured_bytes:0,parsed_bytes:0,
        discarded_tail_bytes:0,backend_exit:None,backend_signal:None })
}

fn discover_impl(input: &DiscoverInput, record: &Recorder<'_>, policy: &Policy, resolver: &Resolver<'_>) -> Result<WorkflowResult> {
    input.validate()?;
    policy.check_http()?;
    for host in &input.hosts { policy.check_host(host.as_str())?; }
    record("discovery_intent",json!({"hosts":input.hosts,"ports":input.ports,"paths":input.paths,
        "max_probes":ATTEMPT_LIMIT,"request_interval_ms":policy.request_interval().as_millis()}))?;
    let mut seen_hosts = BTreeSet::new();
    let mut seen_urls = BTreeSet::new();
    let mut results = Vec::new();
    let mut errors = Vec::new();
    let mut negatives = 0;
    for host in &input.hosts {
        if !seen_hosts.insert(host.as_str()) { continue; }
        let resolution = match resolve(host.as_str(),policy,record,resolver) {
            Ok(resolution) => resolution,
            Err(FetchError::Negative(_)) => { negatives += 1; continue; }
            Err(FetchError::Operational(error)) => { errors.push(error); continue; }
            Err(error) => return Err(error.message()),
        };
        for port in &input.ports {
            for path in &input.paths {
                let url = probe_url(host,*port,path)?;
                if !seen_urls.insert(url.to_string()) { continue; }
                match fetch_impl(&url,record,Some(&resolution),policy,resolver) {
                    Ok(response) => {
                        if let Some(error) = &response.read_error { errors.push(format!("incomplete HTTP body for {url}: {error}")); }
                        results.push(response_item(&url,&response));
                    }
                    Err(FetchError::Negative(_)) => negatives += 1,
                    Err(FetchError::Operational(error)) => errors.push(error),
                    Err(error) => return Err(error.message()),
                }
            }
        }
    }
    let coverage = json!({"unique_hosts":seen_hosts.len(),"unique_probes":seen_urls.len(),"http_responses":results.len(),
        "negative_observations":negatives,"failed_probes":errors.len(),"complete":errors.is_empty(),"deduplication":"exact_normalized_url"});
    record("discovery_coverage",coverage.clone())?;
    if results.is_empty() && negatives == 0 && !errors.is_empty() { return Err(errors.join("; ")); }
    results.sort_by(|a,b| a["url"].as_str().cmp(&b["url"].as_str()));
    let mut result = WorkflowResult::complete(results);
    result.cols = vec!["url","status","title","server"];
    result.coverage = coverage;
    result.partial = incomplete(&errors,"network_failure");
    Ok(result)
}

fn connection_outcome(result: &io::Result<TcpStream>) -> &'static str {
    match result {
        Ok(_) => "open",
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => "refused",
        Err(error) if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => "timed_out",
        Err(_) => "error",
    }
}

struct Attempt { host: String, address: SocketAddr }

fn attempt_tcp(attempt: &Attempt, record: &Recorder<'_>) -> Result<(&'static str, Option<Value>)> {
    record("tcp_connect_intent", json!({"host":attempt.host,"ip":attempt.address.ip().to_string(),
        "port":attempt.address.port(),"timeout_ms":300}))?;
    let result = TcpStream::connect_timeout(&attempt.address, CONNECT_TIMEOUT);
    let outcome = connection_outcome(&result);
    let error = result.as_ref().err();
    record("tcp_connect_result", json!({"host":attempt.host,"ip":attempt.address.ip().to_string(),
        "port":attempt.address.port(),"outcome":outcome,"error":error.map(ToString::to_string),
        "error_kind":error.map(|e| format!("{:?}",e.kind())),"os_error":error.and_then(io::Error::raw_os_error)}))?;
    let item = if result.is_ok() { Some(json!({"host":attempt.host,"ip":attempt.address.ip().to_string(),"port":attempt.address.port()})) } else { None };
    Ok((outcome, item))
}

pub fn ports(input: &PortsInput, audit: &Audit) -> Result<WorkflowResult> {
    let policy = Policy::load()?;
    policy.check_network()?;
    policy.record(audit)?;
    ports_impl(input,&|kind,data| audit.record(kind,data),&policy,
        &|host| dns::lookup(host,&policy,audit).map_err(FetchError::Audit))
}

fn ports_impl(input: &PortsInput, record: &Recorder<'_>, policy: &Policy, resolver: &Resolver<'_>) -> Result<WorkflowResult> {
    input.validate()?;
    policy.check_network()?;
    for host in &input.hosts { policy.check_host(host.as_str())?; }
    record("ports_intent", json!({"hosts":input.hosts,"ports":input.ports,"timeout_ms":300,
        "concurrency":8,"max_attempts":ATTEMPT_LIMIT}))?;
    let mut hosts = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut attempts = Vec::new();
    let mut unresolved = 0usize;
    let mut omitted = 0usize;
    let mut errors = Vec::new();
    let mut negatives = 0;
    for host in &input.hosts {
        if !hosts.insert(host.as_str()) { continue; }
        let resolution = match resolve(host.as_str(),policy,record,resolver) {
            Ok(resolution) => resolution,
            Err(FetchError::Negative(_)) => { negatives += 1; unresolved += 1; continue; }
            Err(FetchError::Operational(error)) => { errors.push(error); unresolved += 1; continue; }
            Err(error) => return Err(error.message()),
        };
        let ips = resolution.ips;
        for ip in ips {
            for port in &input.ports {
                if !targets.insert((host.as_str(), ip, *port)) { continue; }
                if attempts.len() == ATTEMPT_LIMIT { omitted += 1; continue; }
                attempts.push(Attempt { host:host.as_str().to_owned(),address:SocketAddr::new(ip,*port) });
            }
        }
    }
    if omitted > 0 { record("ports_limit", json!({"reason":"expanded_ip_attempt_budget","omitted_attempts":omitted,"limit":ATTEMPT_LIMIT}))?; }
    let mut results = Vec::new();
    let mut counts = BTreeMap::<&str,usize>::new();
    for batch in attempts.chunks(8) {
        let batch_results = std::thread::scope(|scope| {
            let handles: Vec<_> = batch.iter().map(|attempt| scope.spawn(move || attempt_tcp(attempt, record))).collect();
            // Join every started attempt even if an audit write fails; do not abandon in-flight evidence.
            handles.into_iter().map(|handle| handle.join().unwrap_or_else(|_| Err("TCP worker panicked".into()))).collect::<Vec<_>>()
        });
        let mut audit_error = None;
        for result in batch_results {
            match result {
                Ok((outcome,item)) => { *counts.entry(outcome).or_default() += 1; if let Some(item) = item { results.push(item); } }
                Err(error) => { audit_error.get_or_insert(error); }
            }
        }
        if let Some(error) = audit_error { return Err(error); }
    }
    for outcome in ["error","timed_out"] {
        if let Some(count) = counts.get(outcome) { errors.push(format!("{count} TCP attempts {outcome}")); }
    }
    if omitted > 0 { errors.push(format!("{omitted} TCP attempts omitted by budget")); }
    let coverage = json!({"attempts":attempts.len(),"outcomes":counts,"unresolved_hosts":unresolved,
        "negative_dns_observations":negatives,"omitted_attempts":omitted,"complete":errors.is_empty()});
    record("ports_coverage",coverage.clone())?;
    if !counts.contains_key("open") && !counts.contains_key("refused") && negatives == 0 && !errors.is_empty() {
        return Err(errors.join("; "));
    }
    results.sort_by(|a,b| (a["host"].as_str(),a["ip"].as_str(),a["port"].as_u64()).cmp(&(b["host"].as_str(),b["ip"].as_str(),b["port"].as_u64())));
    let mut result = WorkflowResult::complete(results);
    result.cols = vec!["host","ip","port"];
    result.coverage = coverage;
    result.partial = incomplete(&errors,"network_failure");
    Ok(result)
}

// Compiled only in test crates. Production entry points always use the real Audit.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    fn system_resolution(host: &str) -> Result<Resolution, FetchError> {
        use std::net::ToSocketAddrs;
        let ips = (host,0).to_socket_addrs().map_err(|e| FetchError::Operational(e.to_string()))?
            .map(|address| address.ip()).collect::<BTreeSet<_>>().into_iter().collect();
        Ok(Resolution { ips,cnames:Vec::new(),status:"resolved".into() })
    }
    pub(crate) fn fetch(url: &Url, record: &Recorder<'_>, policy: &Policy) -> Result<Fetch> {
        fetch_impl(url,record,None,policy,&system_resolution).map_err(FetchError::message)
    }
    pub(crate) fn discover(input: &DiscoverInput, record: &Recorder<'_>, policy: &Policy) -> Result<WorkflowResult> {
        discover_impl(input,record,policy,&system_resolution)
    }
    pub(crate) fn ports(input: &PortsInput, record: &Recorder<'_>, policy: &Policy) -> Result<WorkflowResult> {
        ports_impl(input,record,policy,&system_resolution)
    }
    pub(crate) fn fetch_with_dns(url: &Url, record: &Recorder<'_>, policy: &Policy, lookup: &Resolver<'_>) -> Result<Fetch> {
        fetch_impl(url,record,None,policy,lookup).map_err(FetchError::message)
    }
    pub(crate) fn discover_with_dns(input: &DiscoverInput, record: &Recorder<'_>, policy: &Policy, lookup: &Resolver<'_>) -> Result<WorkflowResult> {
        discover_impl(input,record,policy,lookup)
    }
    pub(crate) fn ports_with_dns(input: &PortsInput, record: &Recorder<'_>, policy: &Policy, lookup: &Resolver<'_>) -> Result<WorkflowResult> {
        ports_impl(input,record,policy,lookup)
    }
    pub(crate) fn outcome(error: io::Error) -> &'static str { connection_outcome(&Err(error)) }
    pub(crate) fn item(url: &Url, response: &Fetch) -> Value { response_item(url, response) }
    pub(crate) fn probe(host: &Host, port: u16, path: &str) -> Result<Url> { probe_url(host,port,path) }
    pub(crate) fn headers(raw: &str) -> Result<HeaderMap> { parse_operator_headers(raw) }
}
