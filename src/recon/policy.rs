use super::audit::Audit;
use super::types::Host;
use crate::Result;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Read;
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Duration;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Allow { #[serde(default)] suffixes: Vec<String>, #[serde(default)] hosts: Vec<String> }
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Deny { #[serde(default)] suffixes: Vec<String>, #[serde(default)] hosts: Vec<String>, #[serde(default)] cidrs: Vec<String> }
fn yes() -> bool { true }
fn rate() -> f64 { 2.0 }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    v: u8,
    in_scope: Allow,
    #[serde(default)] out_of_scope: Deny,
    #[serde(default)] provider_cname_denylist: Vec<String>,
    #[serde(default = "yes")] deny_private_ips: bool,
    #[serde(default)] required_headers: BTreeMap<String, String>,
    #[serde(default = "rate")] max_rps: f64,
}
struct Cidr { address: IpAddr, prefix: u32 }
impl Cidr {
    fn parse(value: &str) -> Result<Self> {
        let (address, prefix) = value.split_once('/').ok_or("scope CIDR requires a prefix")?;
        let address: IpAddr = address.parse().map_err(|_| "invalid scope CIDR address")?;
        let prefix: u32 = prefix.parse().map_err(|_| "invalid scope CIDR prefix")?;
        if prefix > if address.is_ipv4() { 32 } else { 128 } { return Err("invalid scope CIDR prefix".into()); }
        Ok(Self { address, prefix })
    }
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => self.prefix == 0 || u32::from(a) >> (32-self.prefix) == u32::from(b) >> (32-self.prefix),
            (IpAddr::V6(a), IpAddr::V6(b)) => self.prefix == 0 || u128::from(a) >> (128-self.prefix) == u128::from(b) >> (128-self.prefix),
            _ => false,
        }
    }
}

/// Operator policy is not proof of legal authorization or a root-resistant sandbox.
pub struct Policy {
    scope: Option<Scope>,
    cidrs: Vec<Cidr>,
    fingerprint: Option<String>,
    require_scope: bool,
    required: BTreeMap<String, Option<String>>,
    headers: HeaderMap,
}
fn env(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(format!("{name} is not valid Unicode")),
    }
}
fn header_name(name: &str) -> Result<HeaderName> {
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| "invalid operator header name")?;
    if matches!(name.as_str(), "host" | "authorization" | "cookie" | "proxy-authorization" | "content-length" | "transfer-encoding" | "connection" | "proxy-connection" | "upgrade" | "te" | "trailer") {
        return Err(format!("operator headers forbid header {name}"));
    }
    Ok(name)
}
#[doc(hidden)]
pub fn parse_headers(raw: &str) -> Result<HeaderMap> {
    let values: BTreeMap<String, String> = serde_json::from_str(raw).map_err(|_| "operator headers must be a JSON object of string values")?;
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let name = header_name(&name)?;
        if headers.contains_key(&name) { return Err(format!("operator headers repeat header {name}")); }
        let value = HeaderValue::from_str(&value).map_err(|_| format!("invalid operator header value for {name}"))?;
        headers.try_insert(name, value).map_err(|_| "too many operator headers")?;
    }
    Ok(headers)
}
fn normalize_names(names: &mut [String], dns_only: bool) -> Result<()> {
    for name in names {
        *name = Host::parse(name)?.as_str().to_owned();
        if dns_only && name.parse::<IpAddr>().is_ok() { return Err("scope suffix/CNAME entry must be a DNS name".into()); }
    }
    Ok(())
}
fn suffix(host: &str, domain: &str) -> bool {
    host == domain || host.strip_suffix(domain).is_some_and(|prefix| prefix.ends_with('.'))
}
impl Policy {
    pub fn load() -> Result<Self> {
        let mut policy = match env("RECON_SCOPE")? {
            Some(path) => Self::from_file(Path::new(&path))?,
            None => Self::build(None, None)?,
        };
        policy.require_scope = env("RECON_REQUIRE_SCOPE")?.is_some_and(|value| value == "1");
        if let Some(raw) = env("RECON_REQUIRED_HEADERS")? { policy.merge_required(parse_headers(&raw)?)?; }
        if let Some(name) = env("RECON_REQUIRED_HEADER")? {
            let name = header_name(&name)?.to_string();
            policy.required.entry(name).or_insert(None);
        }
        policy.headers.extend(parse_headers(env("RECON_HTTP_HEADERS")?.as_deref().unwrap_or("{}"))?);
        Ok(policy)
    }
    /// Load the exact protected file bytes, without following a final symlink.
    pub fn from_file(path: &Path) -> Result<Self> {
        if !path.is_absolute() { return Err("RECON_SCOPE must be an absolute path".into()); }
        let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path).map_err(|error| format!("cannot open RECON_SCOPE: {error}"))?;
        let metadata = file.metadata().map_err(|error| format!("cannot inspect RECON_SCOPE: {error}"))?;
        let uid = unsafe { libc::geteuid() };
        if !metadata.is_file() || (metadata.uid() != 0 && metadata.uid() != uid) || metadata.mode() & 0o022 != 0 {
            return Err("RECON_SCOPE must be a regular root/current-UID owned file, not group/other writable".into());
        }
        let mut bytes = Vec::new();
        (&mut file).take(1024*1024+1).read_to_end(&mut bytes).map_err(|error| format!("cannot read RECON_SCOPE: {error}"))?;
        if bytes.len() > 1024*1024 { return Err("RECON_SCOPE exceeds 1 MiB".into()); }
        Self::from_json(&bytes)
    }
    /// Parse an explicit policy (also useful for deterministic, environment-free callers).
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let scope: Scope = serde_json::from_slice(bytes).map_err(|error| format!("invalid RECON_SCOPE: {error}"))?;
        Self::build(Some(scope), Some(format!("{:x}", Sha256::digest(bytes))))
    }
    /// Supply validated effective operator headers without process-global environment mutation.
    pub fn with_http_headers(mut self, raw: &str) -> Result<Self> {
        self.headers = default_headers();
        self.headers.extend(parse_headers(raw)?);
        Ok(self)
    }
    fn build(mut scope: Option<Scope>, fingerprint: Option<String>) -> Result<Self> {
        let mut cidrs = Vec::new();
        if let Some(scope) = &mut scope {
            if scope.v != 1 { return Err("unsupported RECON_SCOPE version".into()); }
            if !scope.max_rps.is_finite() || scope.max_rps <= 0.0 || scope.max_rps > 2.0
                || Duration::try_from_secs_f64(1.0/scope.max_rps).is_err() {
                return Err("scope max_rps must be positive, representable, and at most 2".into());
            }
            normalize_names(&mut scope.in_scope.hosts, false)?;
            normalize_names(&mut scope.in_scope.suffixes, true)?;
            normalize_names(&mut scope.out_of_scope.hosts, false)?;
            normalize_names(&mut scope.out_of_scope.suffixes, true)?;
            normalize_names(&mut scope.provider_cname_denylist, true)?;
            for cidr in &scope.out_of_scope.cidrs { cidrs.push(Cidr::parse(cidr)?); }
        }
        let mut policy = Self { scope, cidrs, fingerprint, require_scope:false, required:BTreeMap::new(), headers:default_headers() };
        if let Some(scope) = &policy.scope {
            let headers = parse_headers(&serde_json::to_string(&scope.required_headers).map_err(|e| e.to_string())?)?;
            policy.merge_required(headers)?;
        }
        Ok(policy)
    }
    fn merge_required(&mut self, headers: HeaderMap) -> Result<()> {
        for (name, value) in &headers {
            let value = value.to_str().map_err(|_| format!("invalid required value for {name}"))?.to_owned();
            if self.required.get(name.as_str()).and_then(Option::as_ref).is_some_and(|old| old != &value) {
                return Err(format!("conflicting required header {name}"));
            }
            self.required.insert(name.to_string(), Some(value));
        }
        Ok(())
    }
    pub fn check_network(&self) -> Result<()> {
        if self.require_scope && self.scope.is_none() { return Err("RECON_REQUIRE_SCOPE requires RECON_SCOPE".into()); }
        Ok(())
    }
    pub fn permits_host(&self, host: &str) -> bool {
        let Ok(host) = Host::parse(host) else { return false; };
        let host = host.as_str();
        self.scope.as_ref().is_none_or(|scope| {
            !scope.out_of_scope.hosts.iter().any(|name| name == host)
                && !scope.out_of_scope.suffixes.iter().any(|name| suffix(host,name))
                && (scope.in_scope.hosts.iter().any(|name| name == host) || scope.in_scope.suffixes.iter().any(|name| suffix(host,name)))
        })
    }
    pub fn check_host(&self, host: &str) -> Result<()> {
        self.check_network()?;
        if !self.permits_host(host) { return Err(format!("policy blocks host {host}")); }
        Ok(())
    }
    pub fn disposition(&self, host: &str, ips: &[IpAddr], cnames: &[String]) -> &'static str {
        if !self.permits_host(host) { return "blocked_host"; }
        if let Some(scope) = &self.scope {
            for cname in cnames {
                let Ok(cname) = Host::parse(cname) else { return "blocked_cname"; };
                if scope.provider_cname_denylist.iter().chain(&scope.out_of_scope.suffixes).any(|name| suffix(cname.as_str(),name))
                    || scope.out_of_scope.hosts.iter().any(|name| name == cname.as_str()) { return "blocked_cname"; }
            }
        }
        for ip in ips {
            let normalized = match ip { IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(*ip)), _ => *ip };
            if self.cidrs.iter().any(|cidr| cidr.contains(*ip) || cidr.contains(normalized)) { return "blocked_ip"; }
            if self.scope.as_ref().is_none_or(|scope| scope.deny_private_ips) && !global(normalized) { return "blocked_ip"; }
        }
        "permitted"
    }
    pub fn check_resolution(&self, host: &str, ips: &[IpAddr], cnames: &[String]) -> Result<()> {
        self.check_host(host)?;
        let disposition = self.disposition(host,ips,cnames);
        if disposition != "permitted" { return Err(format!("policy {disposition} for {host}")); }
        Ok(())
    }
    pub fn fingerprint(&self) -> Option<&str> { self.fingerprint.as_deref() }
    pub fn request_interval(&self) -> Duration { Duration::from_secs_f64(1.0/self.scope.as_ref().map_or(2.0, |scope| scope.max_rps)) }
    /// Check attribution before resolving or connecting; diagnostics never expose required values.
    pub fn check_http(&self) -> Result<()> {
        self.check_network()?;
        for (name, value) in &self.required {
            let sent = self.headers.get(name.as_str()).ok_or_else(|| format!("missing required HTTP header {name}"))?;
            if value.as_ref().is_some_and(|expected| sent.as_bytes() != expected.as_bytes()) {
                return Err(format!("mismatched required HTTP header {name}"));
            }
        }
        Ok(())
    }
    pub fn http_headers(&self) -> Result<HeaderMap> {
        self.check_http()?;
        Ok(self.headers.clone())
    }
    pub fn record(&self, audit: &Audit) -> Result<()> { audit.record("policy", self.observation()) }
    pub(crate) fn observation(&self) -> serde_json::Value {
        json!({"scope_sha256":self.fingerprint,"scope_selected":self.scope.is_some(),"require_scope":self.require_scope,
            "deny_private_ips":self.scope.as_ref().is_none_or(|scope| scope.deny_private_ips),
            "required_header_names":self.required.keys().collect::<Vec<_>>(),"request_interval_ms":self.request_interval().as_millis()})
    }
}
fn default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("accept", HeaderValue::from_static("*/*"));
    headers.insert("accept-encoding", HeaderValue::from_static("identity"));
    headers.insert("user-agent", HeaderValue::from_static("recon/1"));
    headers
}
pub fn validate_startup() -> Result<()> { Policy::load().map(|_| ()) }
fn global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a,b,c,_] = ip.octets();
            !(a == 0 || a == 10 || a == 127 || a >= 224 || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254) || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
                || (a == 192 && b == 0 && (c == 0 || c == 2)) || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19)) || (a == 198 && b == 51 && c == 100) || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000 && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] <= 0x1ff || s[1] == 0xdb8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}
