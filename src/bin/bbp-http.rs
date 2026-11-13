use llm_pipeline_tools::{Options, Result, json_values, main_result, report, sha256};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Endpoint {
    method: String,
    host: String,
    path: String,
    query: Vec<String>,
}

struct Record {
    endpoint: Endpoint,
    status: u16,
    mime: String,
    body: Option<Vec<u8>>,
    digest: Option<String>,
    bytes: Option<u64>,
    descriptors: BTreeMap<String, String>,
}

#[derive(Default)]
struct Stats {
    records: usize,
    accepted: usize,
    unsupported: usize,
    metadata_only: usize,
    aura_responses: usize,
    aura_requests: usize,
    aura_actions: usize,
    aura_non_aura: usize,
    aura_no_actions: usize,
    aura_invalid: usize,
    aura_failures: usize,
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
struct GroupKey {
    endpoint: Option<Endpoint>,
    status: u16,
    mime: String,
    identity: String,
}

struct Group {
    count: usize,
    endpoint: Option<Endpoint>,
    source: String,
    bytes: BTreeSet<u64>,
    variants: BTreeSet<String>,
    variant_count: usize,
}

struct Index {
    aura: bool,
    group_metadata: bool,
    stats: Stats,
    groups: BTreeMap<GroupKey, Group>,
    actions: Vec<Value>,
}

fn string<'a>(obj: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    obj.get(key).and_then(Value::as_str).ok_or_else(|| format!("{key} must be a string"))
}

fn status(value: Option<&Value>) -> Result<u16> {
    let code = value.and_then(Value::as_u64).ok_or("status must be an integer")?;
    if !(100..=599).contains(&code) { return Err("status must be between 100 and 599".into()); }
    Ok(code as u16)
}

fn mime(value: &str) -> String {
    value.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

fn authority(value: &str) -> Result<String> {
    if value.is_empty() || value.contains(['@', '/', '?', '#', '\\']) || value.chars().any(char::is_whitespace) {
        return Err("invalid HTTP authority".into());
    }
    let parsed = Url::parse(&format!("http://{value}/")).map_err(|_| "invalid HTTP authority")?;
    let host = parsed.host_str().ok_or("missing HTTP host")?;
    Ok(match parsed.port() { Some(port) => format!("{host}:{port}"), None => host.to_string() })
}

fn endpoint(method: &str, target: &str, host: Option<&str>) -> Result<Endpoint> {
    if method.is_empty() || (method != "?" && !method.bytes().all(token)) { return Err("invalid HTTP method".into()); }
    if target.chars().any(|c| c.is_control() || c.is_whitespace()) || target.contains('\\') {
        return Err("invalid request target".into());
    }
    let (host, target) = if target.starts_with("http://") || target.starts_with("https://") {
        let parsed = Url::parse(target).map_err(|_| "invalid absolute HTTP URL")?;
        let hostname = parsed.host_str().ok_or("missing URL host")?;
        let parsed_host = match parsed.port() { Some(port) => format!("{hostname}:{port}"), None => hostname.to_owned() };
        if let Some(host) = host {
            authority(host)?;
            let supplied = Url::parse(&format!("{}://{host}/", parsed.scheme())).map_err(|_| "invalid HTTP authority")?;
            if supplied.host_str() != parsed.host_str() || supplied.port_or_known_default() != parsed.port_or_known_default() {
                return Err("conflicting Host and absolute request URI".into());
            }
        }
        let start = target.find("://").unwrap() + 3;
        let end = target[start..].find(['/', '?', '#']).map_or(target.len(), |n| start + n);
        (parsed_host, &target[end..])
    } else {
        if !target.starts_with('/') { return Err("request target must be an absolute URL or origin path".into()); }
        (host.map(authority).transpose()?.unwrap_or_default(), target)
    };
    let target = target.split('#').next().unwrap_or("");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let names: BTreeSet<String> = query.split('&').filter(|p| !p.is_empty())
        .map(|p| p.split('=').next().unwrap_or("").to_owned()).collect();
    Ok(Endpoint { method: method.to_owned(), host, path: if path.is_empty() { "/".into() } else { path.into() }, query: names.into_iter().collect() })
}

fn token(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

fn http_head(raw: &str) -> Result<(&str, BTreeMap<String, Vec<String>>, &str)> {
    let split = raw.find("\r\n\r\n").map(|n| (n, 4)).into_iter()
        .chain(raw.find("\n\n").map(|n| (n, 2))).min_by_key(|x| x.0)
        .ok_or("HTTP message lacks header/body separator")?;
    let mut lines = raw[..split.0].split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let first = lines.next().ok_or("empty HTTP message")?;
    if first.chars().any(char::is_control) { return Err("malformed HTTP first line".into()); }
    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("malformed HTTP header")?;
        if name.is_empty() || !name.bytes().all(token) || value.chars().any(|c| c.is_control() && c != '\t') {
            return Err("malformed HTTP header".into());
        }
        headers.entry(name.to_ascii_lowercase()).or_default().push(value.trim().to_owned());
    }
    if let Some(lengths) = headers.get("content-length") {
        if lengths.len() != 1 || lengths[0].is_empty() || !lengths[0].bytes().all(|c| c.is_ascii_digit()) || headers.contains_key("transfer-encoding") {
            return Err("ambiguous or invalid HTTP body framing headers".into());
        }
    }
    Ok((first, headers, &raw[split.0 + split.1..]))
}

fn single_header<'a>(headers: &'a BTreeMap<String, Vec<String>>, key: &str) -> Result<Option<&'a str>> {
    match headers.get(key) {
        None => Ok(None),
        Some(values) if values.len() == 1 => Ok(Some(&values[0])),
        Some(_) => Err(format!("ambiguous duplicate {key} header")),
    }
}

fn descriptors(raw: &str) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    // Aura requests are form encoded; only retain action descriptors, never parameters.
    let body = raw.split_once("\r\n\r\n").or_else(|| raw.split_once("\n\n")).map_or("", |(_, b)| b);
    let mut payloads = Vec::new();
    if let Ok(value) = serde_json::from_str::<Value>(body) { payloads.push(value); }
    for (name, value) in url::form_urlencoded::parse(body.as_bytes()) {
        if name == "message" {
            if let Ok(value) = serde_json::from_str::<Value>(&value) { payloads.push(value); }
        }
    }
    for payload in payloads {
        if let Some(actions) = payload.get("actions").and_then(Value::as_array) {
            for action in actions {
                if let (Some(id), Some(desc)) = (action.get("id").and_then(Value::as_str), action.get("descriptor").and_then(Value::as_str)) {
                    result.insert(id.into(), desc.into());
                }
            }
        }
    }
    result
}

fn burp(obj: &Map<String, Value>) -> Result<Record> {
    let request = string(obj, "request")?;
    let (line, headers, _) = http_head(request)?;
    let fields: Vec<&str> = line.split(' ').collect();
    if fields.len() != 3 || !matches!(fields[2], "HTTP/1.0" | "HTTP/1.1" | "HTTP/2" | "HTTP/2.0") || fields[1].contains('#') {
        return Err("malformed HTTP request line".into());
    }
    let host = single_header(&headers, "host")?;
    if host.is_none() && !fields[1].starts_with("http://") && !fields[1].starts_with("https://") {
        return Err("origin request URI requires Host".into());
    }
    let endpoint = endpoint(fields[0], fields[1], host)?;
    let mut response = string(obj, "response")?;
    loop {
        let (line, headers, body) = http_head(response)?;
        let mut fields = line.splitn(3, ' ');
        let version = fields.next().unwrap_or("");
        let code = fields.next().unwrap_or("");
        if !matches!(version, "HTTP/1.0" | "HTTP/1.1" | "HTTP/2" | "HTTP/2.0") || code.len() != 3 {
            return Err("malformed HTTP response line".into());
        }
        let code = code.parse::<u64>().map_err(|_| "invalid HTTP response status")?;
        let status = status(Some(&json!(code)))?;
        if (100..200).contains(&status) && status != 101 { response = body; continue; }
        let mime = mime(single_header(&headers, "content-type")?.unwrap_or(""));
        let bytes = body.as_bytes().to_vec();
        return Ok(Record { endpoint, status, mime, digest: Some(sha256(&bytes)), bytes: Some(bytes.len() as u64), body: Some(bytes), descriptors: descriptors(request) });
    }
}

fn header_mime(headers: Option<&Value>) -> Result<String> {
    let Some(headers) = headers else { return Ok(String::new()); };
    let headers = headers.as_object().ok_or("headers must be an object")?;
    let mut content_type = None;
    for (key, value) in headers {
        if key.eq_ignore_ascii_case("content-type") {
            if content_type.is_some() { return Err("ambiguous content-type headers".into()); }
            content_type = Some(value.as_str().ok_or("content-type header must be a string")?);
        }
    }
    Ok(mime(content_type.unwrap_or("")))
}

fn json_record(obj: &Map<String, Value>, path: Option<&str>) -> Result<Record> {
    let method = match obj.get("method") { Some(v) => v.as_str().ok_or("method must be a string")?, None => "?" };
    let target = match path { Some(path) => path, None => match obj.get("request_url") {
        Some(Value::String(target)) => target,
        None | Some(Value::Null) => string(obj, "url")?,
        Some(_) => return Err("request_url must be a string".into()),
    }};
    let endpoint = endpoint(method, target, None)?;
    let status = status(obj.get("status_code").or_else(|| obj.get("status")))?;
    let mime = match obj.get("content_type") { Some(value) => mime(value.as_str().ok_or("content_type must be a string")?), None => header_mime(obj.get("headers"))? };
    let body = match obj.get("body") {
        None | Some(Value::Null) => None,
        Some(Value::String(body)) => Some(body.as_bytes().to_vec()),
        Some(_) => return Err("body must be a string or null".into()),
    };
    let known_digest = match obj.get("sha256") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()) => Some(s.to_ascii_lowercase()),
        Some(_) => return Err("sha256 must be a 64-digit hexadecimal digest".into()),
    };
    let declared_bytes = match obj.get("bytes").or_else(|| obj.get("content_length")) {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.as_u64().ok_or("body length must be a nonnegative integer")?),
    };
    let digest = body.as_ref().map(|b| sha256(b)).or(known_digest.clone());
    if body.is_some() && known_digest.is_some() && digest != known_digest { return Err("body and supplied sha256 disagree".into()); }
    let bytes = body.as_ref().map(|b| b.len() as u64).or(declared_bytes);
    Ok(Record { endpoint, status, mime, body, digest, bytes, descriptors: BTreeMap::new() })
}

fn shape(value: &Value, depth: usize) -> Value {
    match value {
        Value::Null => json!("null"),
        Value::Bool(_) => json!("boolean"),
        Value::Number(_) => json!("number"),
        Value::String(_) => json!("string"),
        Value::Array(values) => {
            if depth == 0 { return json!("array"); }
            let mut kinds = BTreeMap::new();
            for value in values {
                let kind = shape(value, depth - 1);
                kinds.entry(kind.to_string()).or_insert(kind);
            }
            json!({"array": kinds.into_values().collect::<Vec<_>>()})
        }
        Value::Object(values) => {
            if depth == 0 { return json!("object"); }
            Value::Object(values.iter().map(|(key, value)| (key.clone(), shape(value, depth - 1))).collect())
        }
    }
}

impl Index {
    fn visit(&mut self, value: Value, source: String, map_path: Option<&str>) -> Result<()> {
        match value {
            Value::Array(values) => {
                for (index, value) in values.into_iter().enumerate() { self.visit(value, format!("{source}/{}", index + 1), map_path)?; }
                Ok(())
            }
            Value::Object(obj) => {
                let parsed = if obj.contains_key("request") || obj.contains_key("response") {
                    Some(burp(&obj))
                } else if (map_path.is_some() || obj.contains_key("url") || obj.contains_key("request_url")) && (obj.contains_key("status") || obj.contains_key("status_code")) {
                    Some(json_record(&obj, map_path))
                } else { None };
                if let Some(parsed) = parsed {
                    self.stats.records += 1;
                    let record = parsed.map_err(|error| format!("{source}: {error}"))?;
                    self.stats.accepted += 1;
                    self.add(record, source)
                } else if self.aura && (obj.contains_key("msg") || obj.contains_key("pd")) {
                    self.stats.records += 1;
                    self.stats.accepted += 1;
                    self.aura_request(&obj, &source).map_err(|error| format!("{source}: {error}"))
                } else {
                    let is_container = !obj.is_empty() && (obj.keys().any(|key| key.starts_with('/')) || obj.values().all(|v| v.is_array() || v.is_object()));
                    if is_container {
                        for (position, (key, value)) in obj.into_iter().enumerate() {
                            // Source pointers use positions so map keys cannot leak query values.
                            self.visit(value, format!("{source}/entry{}", position + 1), if key.starts_with('/') { Some(&key) } else { None })?;
                        }
                    } else {
                        self.stats.records += 1;
                        self.stats.unsupported += 1;
                    }
                    Ok(())
                }
            }
            _ => { self.stats.records += 1; self.stats.unsupported += 1; Ok(()) }
        }
    }

    fn add(&mut self, record: Record, source: String) -> Result<()> {
        if record.digest.is_none() { self.stats.metadata_only += 1; }
        if self.aura { self.aura(record, source); return Ok(()); }
        let metadata_group = self.group_metadata && record.body.is_none() && record.digest.is_none();
        let identity = if metadata_group {
            let metadata = serde_json::to_vec(&(record.status, record.bytes, &record.mime)).map_err(|error| error.to_string())?;
            format!("meta:{}", sha256(&metadata))
        } else {
            record.digest.as_ref().map(|s| format!("sha256:{s}")).unwrap_or_else(|| format!("metadata-only:{source}"))
        };
        let (endpoint, representative) = if metadata_group { (None, Some(record.endpoint)) } else { (Some(record.endpoint), None) };
        let key = GroupKey { endpoint, status: record.status, mime: record.mime, identity };
        let group = self.groups.entry(key).or_insert_with(|| Group { count: 0, endpoint: representative, source: source.clone(), bytes: BTreeSet::new(), variants: BTreeSet::new(), variant_count: 0 });
        group.count += 1;
        if let Some(bytes) = record.bytes { group.bytes.insert(bytes); }
        if group.count > 1 {
            group.variant_count += 1;
            if group.variants.len() < 3 { group.variants.insert(source); }
        }
        Ok(())
    }
    fn aura_request(&mut self, obj: &Map<String, Value>, source: &str) -> Result<()> {
        // Saved FanDuel exports contain both decoded msg and form-encoded pd.
        // Prefer msg, even when pd is also present, to avoid double counting.
        let message = if obj.contains_key("msg") {
            string(obj, "msg")?.to_owned()
        } else {
            let form = string(obj, "pd")?;
            let messages: Vec<String> = url::form_urlencoded::parse(form.as_bytes())
                .filter(|(name, _)| name == "message").map(|(_, value)| value.into_owned()).collect();
            if messages.len() != 1 { return Err("Aura pd requires exactly one message form field".into()); }
            messages.into_iter().next().unwrap()
        };
        let payload: Value = serde_json::from_str(&message).map_err(|_| "invalid Aura message JSON")?;
        let Some(actions) = payload.get("actions").and_then(Value::as_array) else {
            self.stats.aura_no_actions += 1;
            return Ok(());
        };
        if actions.is_empty() { self.stats.aura_no_actions += 1; return Ok(()); }
        if actions.iter().any(|a| a.get("id").and_then(Value::as_str).is_none() || a.get("descriptor").and_then(Value::as_str).is_none()) {
            self.stats.aura_invalid += 1;
            return Ok(());
        }
        let page = match obj.get("pageuri") {
            Some(Value::String(page)) => Some(endpoint("?", page, None)?),
            None | Some(Value::Null) => None,
            Some(_) => return Err("pageuri must be a string".into()),
        };
        self.stats.aura_requests += 1;
        let digest = sha256(message.as_bytes());
        for (position, action) in actions.iter().enumerate() {
            self.stats.aura_actions += 1;
            self.actions.push(json!(["request", "?", page.as_ref().map(|p| &p.host), page.as_ref().map(|p| &p.path), page.as_ref().map(|p| &p.query),
                action["id"], Value::Null, action["descriptor"], Value::Null, action.get("params").map(|v| shape(v, 3)), Value::Null, digest,
                format!("{source}/action{}", position + 1)]));
        }
        Ok(())
    }


    fn aura(&mut self, record: Record, source: String) {
        let Some(body) = record.body.as_deref() else { self.stats.aura_non_aura += 1; return; };
        let Ok(text) = std::str::from_utf8(body) else { self.stats.aura_non_aura += 1; return; };
        let text = text.trim_start();
        let prefixed = text.starts_with("while(1);");
        let text = text.strip_prefix("while(1);").unwrap_or(text).trim_start();
        let parsed = serde_json::from_str::<Value>(text);
        let payload = match parsed { Ok(payload) => payload, Err(_) => {
            if prefixed { self.stats.aura_invalid += 1; } else { self.stats.aura_non_aura += 1; }
            return;
        }};
        let Some(actions) = payload.get("actions").and_then(Value::as_array) else {
            if prefixed || payload.get("actions").is_some() { self.stats.aura_no_actions += 1; } else { self.stats.aura_non_aura += 1; }
            return;
        };
        if actions.is_empty() { self.stats.aura_no_actions += 1; return; }
        if actions.iter().any(|a| !a.is_object() || a.get("id").and_then(Value::as_str).is_none() || a.get("state").and_then(Value::as_str).is_none()) {
            self.stats.aura_invalid += 1;
            return;
        }
        self.stats.aura_responses += 1;
        for (index, action) in actions.iter().enumerate() {
            let id = action["id"].as_str().unwrap();
            let state = action["state"].as_str().unwrap();
            let errors = match action.get("error").or_else(|| action.get("errors")) {
                None | Some(Value::Null) => 0,
                Some(Value::Array(errors)) => errors.len(),
                Some(_) => 1,
            };
            self.stats.aura_actions += 1;
            if state != "SUCCESS" || errors > 0 { self.stats.aura_failures += 1; }
            let descriptor = action.get("descriptor").and_then(Value::as_str).or_else(|| record.descriptors.get(id).map(String::as_str));
            self.actions.push(json!(["response", record.endpoint.method, record.endpoint.host, record.endpoint.path, record.endpoint.query, id, state, descriptor, action.get("returnValue").map(|v| shape(v, 3)), Value::Null, errors, record.digest, format!("{source}/action{}", index + 1)]));
        }
    }
}

fn run() -> Result<()> {
    let options = Options::parse(&["--all", "--aura", "--group-metadata"], &["--limit"])?;
    if options.help() {
        println!("bbp-http [--aura | --group-metadata] [--limit N | --all] FILE...\nOffline Burp, httpx, probe-array and path-map HTTP evidence index; '-' reads stdin.\nPaths retain case/escapes; queries expose names only. Missing methods are '?'.\nIdentity uses full captured-body SHA-256 or supplied sha256; metadata-only rows never imply body equality.\n--group-metadata groups body-less, digest-less records by status/length/MIME, not URL, using meta:<sha256> identities.\nMetadata groups have equal_bodies:false and retain the first endpoint as representative; missing length/MIME stay distinct from known values.\nSHA-256 rows have equal_bodies:null: matching fingerprints do not establish complete response-body equality.\nCaptured bodies (including partial captures) and supplied SHA-256 identities are never metadata-grouped.\nSources use one-based top-level JSON record IDs and nested positions; up to three additional source variants per group.\n--aura reports response action state/return shape and saved msg/pd request descriptors/params shape, never values.\nRequest-only actions have null state/errors; no success is inferred. Shapes stop at depth three.\nUnsupported records and non-Aura/invalid/empty-action responses are counted in stats.");
        return Ok(());
    }
    if options.flag("--aura") && options.flag("--group-metadata") {
        return Err("--aura and --group-metadata are mutually exclusive".into());
    }
    options.require_inputs()?;
    let limit = options.limit()?;
    let mut index = Index { aura: options.flag("--aura"), group_metadata: options.flag("--group-metadata"), stats: Stats::default(), groups: BTreeMap::new(), actions: Vec::new() };
    for path in &options.inputs {
        json_values(path, |value, record| index.visit(value, format!("{path}#{record}"), None))?;
    }
    let stats = json!({"records": index.stats.records, "accepted": index.stats.accepted, "unsupported": index.stats.unsupported, "metadata_only": index.stats.metadata_only,
        "aura_responses": index.stats.aura_responses, "aura_requests": index.stats.aura_requests, "aura_actions": index.stats.aura_actions, "aura_failures": index.stats.aura_failures,
        "skipped_non_aura": index.stats.aura_non_aura, "skipped_no_actions": index.stats.aura_no_actions, "skipped_invalid_aura": index.stats.aura_invalid});
    if index.aura {
        index.actions.sort_by_key(Value::to_string);
        report("bbp-http-aura", &["direction", "method", "host", "path", "query_names", "id", "state", "descriptor", "return_shape", "params_shape", "errors", "sha256", "source"], index.actions, limit, stats)
    } else {
        let group_metadata = index.group_metadata;
        let rows = index.groups.into_iter().map(|(key, group)| {
            let omitted = group.variant_count.saturating_sub(group.variants.len());
            let equal_bodies = if key.identity.starts_with("meta:") { Some(false) } else { None };
            let endpoint = key.endpoint.or(group.endpoint).expect("HTTP group has a representative endpoint");
            let mut row = vec![json!(endpoint.method), json!(endpoint.host), json!(endpoint.path), json!(endpoint.query),
                json!(key.status), json!(key.mime), json!(key.identity), json!(group.bytes), json!(group.count), json!(group.source), json!(group.variants), json!(omitted)];
            if group_metadata { row.push(json!(equal_bodies)); }
            Value::Array(row)
        });
        let mut cols = vec!["method", "host", "path", "query_names", "status", "mime", "identity", "bytes", "count", "source", "variants", "variants_omitted"];
        if group_metadata { cols.push("equal_bodies"); }
        report("bbp-http", &cols, rows, limit, stats)
    }
}

fn main() { main_result(run); }
