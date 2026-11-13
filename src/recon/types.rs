use crate::Result;
use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub struct Domain(String);
impl Domain {
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.strip_suffix('.').unwrap_or(value);
        if value.len() > 253 || !value.is_ascii() || !value.contains('.') || value.parse::<std::net::IpAddr>().is_ok() {
            return Err("domain must be a DNS name, not a URL, IP, wildcard or flag".into());
        }
        for label in value.split('.') {
            if label.is_empty() || label.len() > 63 || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len()-1].is_ascii_alphanumeric()
                || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err("invalid DNS domain label".into());
            }
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
    pub fn as_str(&self) -> &str { &self.0 }
    pub fn contains_host(&self, host: &str) -> bool {
        let host = host.strip_suffix('.').unwrap_or(host);
        host.eq_ignore_ascii_case(&self.0) || host.len().checked_sub(self.0.len()+1).is_some_and(|offset| {
            host.as_bytes()[offset] == b'.'
                && host.get(offset+1..).is_some_and(|suffix| suffix.eq_ignore_ascii_case(&self.0))
        })
    }
}
impl<'de> Deserialize<'de> for Domain {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub struct Host(String);
impl Host {
    pub fn parse(value: &str) -> Result<Self> {
        if let Ok(ip) = value.parse::<std::net::IpAddr>() { return Ok(Self(ip.to_string())); }
        if value.strip_suffix('.').unwrap_or(value).eq_ignore_ascii_case("localhost") { return Ok(Self("localhost".into())); }
        Ok(Self(Domain::parse(value)?.0))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}
impl<'de> Deserialize<'de> for Host {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug)]
pub struct WebUrl(Url);
impl WebUrl {
    pub fn parse(value: &str) -> Result<Self> {
        if value.len() > 8192 || value.chars().any(char::is_control) { return Err("invalid or oversized HTTP URL".into()); }
        let mut url = Url::parse(value).map_err(|e| format!("invalid URL: {e}"))?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none()
            || !url.username().is_empty() || url.password().is_some() || url.port() == Some(0) {
            return Err("URL must be HTTP(S), without credentials, with a nonzero port".into());
        }
        url.set_fragment(None);
        Ok(Self(url))
    }
    pub fn as_url(&self) -> &Url { &self.0 }
    pub fn as_str(&self) -> &str { self.0.as_str() }
}
impl Serialize for WebUrl {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok,S::Error> { serializer.serialize_str(self.as_str()) }
}
impl<'de> Deserialize<'de> for WebUrl {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self,D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubdomainsInput {
    pub domain: Domain,
    #[serde(default)] pub since: Option<String>,
}
impl SubdomainsInput {
    pub fn validate(&self) -> Result<()> {
        if let Some(run) = &self.since { validate_run(run)?; }
        Ok(())
    }
}

fn default_ports() -> Vec<u16> { vec![80,443] }
fn default_paths() -> Vec<String> { vec!["/".into()] }
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverInput {
    pub hosts: Vec<Host>,
    #[serde(default="default_ports")] pub ports: Vec<u16>,
    #[serde(default="default_paths")] pub paths: Vec<String>,
}
impl DiscoverInput {
    pub fn validate(&self) -> Result<()> {
        targets(&self.hosts,&self.ports)?;
        if self.paths.is_empty() || self.paths.len()>64 || self.hosts.len()*self.ports.len()*self.paths.len()>256 { return Err("discovery permits 1..64 paths and at most 256 probes".into()); }
        for path in &self.paths {
            if !path.starts_with('/') || path.starts_with("//") || path.len()>2048 || path.contains('#')
                || path.contains('\\') || path.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err("paths must be bounded absolute URL paths, not authorities or fragments".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortsInput { pub hosts: Vec<Host>, pub ports: Vec<u16> }
impl PortsInput { pub fn validate(&self) -> Result<()> { targets(&self.hosts,&self.ports) } }
fn targets(hosts: &[Host], ports: &[u16]) -> Result<()> {
    if hosts.is_empty() || hosts.len()>32 || ports.is_empty() || ports.len()>128 || ports.contains(&0)
        || hosts.len()*ports.len()>256 { return Err("provide 1..32 hosts and 1..128 nonzero integer ports, at most 256 host/port pairs".into()); }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlMode {
    #[default]
    Archive,
    Crawl,
    Combined,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UrlsInput {
    pub domain: Domain,
    #[serde(default)] pub mode: UrlMode,
    #[serde(default)] pub seeds: Vec<WebUrl>,
    #[serde(default)] pub since: Option<String>,
    #[serde(default)] pub resume: Option<String>,
    #[serde(default)] pub queue: Option<CrawlCheckpoint>,
}
impl UrlsInput {
    pub fn validate(&self) -> Result<()> {
        if self.seeds.len()>8 { return Err("at most eight crawl seeds are allowed".into()); }
        match self.mode {
            UrlMode::Archive if !self.seeds.is_empty() || self.queue.is_some() || self.resume.is_some() => return Err("archive mode does not accept seeds or crawl checkpoints; select crawl or combined".into()),
            UrlMode::Crawl | UrlMode::Combined if self.seeds.is_empty() => return Err("crawl and combined modes require at least one seed".into()),
            _ => {}
        }
        for seed in &self.seeds {
            if !self.domain.contains_host(seed.as_url().host_str().unwrap_or("")) { return Err("crawl seed is outside the requested domain".into()); }
        }
        if let Some(run) = &self.since { validate_run(run)?; }
        if let Some(run) = &self.resume { validate_run(run)?; }
        if self.resume.is_some() && self.queue.is_some() { return Err("use a resume receipt or a queue checkpoint, not both".into()); }
        if let Some(queue) = &self.queue { queue.validate(&self.seeds)?; }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveInput { pub hosts: Vec<Host>, #[serde(default)] pub domain: Option<Domain> }
impl ResolveInput {
    pub fn validate(&self) -> Result<()> {
        if self.hosts.is_empty() || self.hosts.len() > 512 { return Err("resolution requires 1..512 hosts".into()); }
        if let Some(domain) = &self.domain {
            if self.hosts.iter().any(|host| !domain.contains_host(host.as_str())) { return Err("resolution host is outside the requested domain".into()); }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueKind { #[default] Navigation, Asset, Metadata }

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrawlQueueEntry {
    pub url: WebUrl,
    pub origin: String,
    pub depth: usize,
    #[serde(default)] pub kind: QueueKind,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrawlCheckpoint {
    pub v: u8,
    pub pending: Vec<CrawlQueueEntry>,
    #[serde(default)] pub visited: Vec<WebUrl>,
    #[serde(default)] pub omitted: usize,
    #[serde(default)] pub scope_sha256: Option<String>,
}
impl CrawlCheckpoint {
    pub fn validate(&self, seeds: &[WebUrl]) -> Result<()> {
        if self.v != 1 || self.pending.len() > 2000 || self.visited.len() > 4096 { return Err("invalid or oversized crawl checkpoint".into()); }
        let origins: Vec<_> = seeds.iter().map(|seed| seed.as_url().origin().ascii_serialization()).collect();
        for entry in &self.pending {
            let origin = entry.url.as_url().origin().ascii_serialization();
            if entry.depth > 2 || entry.origin != origin || !origins.contains(&origin) { return Err("checkpoint URL/depth is outside the exact seed origins".into()); }
        }
        if self.visited.iter().any(|url| !origins.contains(&url.as_url().origin().ascii_serialization())) { return Err("visited checkpoint URL is outside the exact seed origins".into()); }
        if let Some(hash) = &self.scope_sha256 {
            if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err("invalid checkpoint scope fingerprint".into()); }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSelect {
    #[serde(default)] pub kind: Vec<String>,
    #[serde(default)] pub class: Vec<String>,
    #[serde(default)] pub status: Vec<u16>,
    #[serde(default)] pub seq: Vec<u64>,
}
fn evidence_limit() -> usize { 100 }
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadInput {
    pub run: String,
    #[serde(default)] pub include_payloads: bool,
    #[serde(default)] pub include_integrity: Option<bool>,
    #[serde(default)] pub select: EvidenceSelect,
    #[serde(default)] pub offset: usize,
    #[serde(default = "evidence_limit")] pub limit: usize,
}
impl ReadInput {
    pub fn full(run: String) -> Self { Self { run, include_payloads: true, include_integrity: Some(true), select: EvidenceSelect::default(), offset: 0, limit: 4096 } }
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictInput { pub run: String, pub verdict: String, pub evidence: Vec<u64>, pub note: String }
pub fn validate_run(run: &str) -> Result<()> {
    if run.len()!=32 || !run.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err("run must be 32 lowercase hexadecimal characters".into()); }
    Ok(())
}
impl ReadInput {
    pub fn validate(&self) -> Result<()> {
        validate_run(&self.run)?;
        if self.limit == 0 || self.limit > 4096 || self.offset > 4096 { return Err("evidence offset must be 0..4096 and limit 1..4096".into()); }
        if self.select.kind.len() > 64 || self.select.class.len() > 16 || self.select.status.len() > 500 || self.select.seq.len() > 4096 { return Err("oversized evidence filter".into()); }
        if self.select.kind.iter().chain(self.select.class.iter()).any(|s| s.is_empty() || s.len() > 96 || !s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b,b'_'|b'-'|b'.'))) { return Err("invalid evidence kind/class filter".into()); }
        if self.select.status.iter().any(|status| !(100..=599).contains(status)) || self.select.seq.contains(&0) { return Err("invalid evidence status or sequence filter".into()); }
        Ok(())
    }
}
impl VerdictInput {
    pub fn validate(&self) -> Result<()> {
        validate_run(&self.run)?;
        if !matches!(self.verdict.as_str(),"hypothesis"|"confirmed"|"rejected"|"insufficient_evidence") || self.note.len()>2048 || self.evidence.len()>256 { return Err("invalid model verdict, note or evidence list".into()); }
        if self.verdict=="confirmed" && self.evidence.is_empty() { return Err("a model-confirmed verdict requires fact references".into()); }
        Ok(())
    }
}
