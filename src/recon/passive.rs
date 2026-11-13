use crate::recon::{audit::Audit, network, policy::Policy, result::{PartialInfo, WorkflowResult}, types::*};
use crate::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};
use url::Url;

const OUTPUT_BUDGET: usize = 8 * 1024 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_PAGES: usize = 32;
const MAX_ASSETS: usize = 8;
const MAX_VISITED: usize = 4096;
const MAX_DEPTH: usize = 2;
static LAST_CRAWL_REQUEST: Mutex<Option<Instant>> = Mutex::new(None);

#[derive(Clone, Copy)]
enum Backend { Subfinder, Gau, Dnsx }

impl Backend {
    fn name(self) -> &'static str {
        match self { Self::Subfinder => "subfinder", Self::Gau => "gau", Self::Dnsx => "dnsx" }
    }
    fn environment(self) -> &'static str {
        match self { Self::Subfinder => "RECON_SUBFINDER", Self::Gau => "RECON_GAU", Self::Dnsx => "RECON_DNSX" }
    }
    fn args(self, domain: Option<&Domain>) -> Vec<OsString> {
        let args: Vec<&str> = match self {
            // Leave one minute for provider shutdown before the 120-second supervisor deadline.
            Self::Subfinder => vec!["-d", domain.expect("sealed subfinder input").as_str(), "-silent", "-nc", "-duc", "-oJ", "-cs", "-timeout", "10", "-max-time", "1", "-rl", "2", "-rsr", "1048576"],
            Self::Gau => vec!["--subs", "--threads", "1", "--timeout", "10", "--retries", "0", "--providers", "wayback,commoncrawl", domain.expect("sealed gau input").as_str()],
            Self::Dnsx => vec!["-silent", "-json", "-a", "-aaaa", "-cname", "-rcode", "noerror,nxdomain,servfail,refused", "-rl", "2", "-t", "1", "-retry", "1", "-timeout", "5s", "-duc"],
        };
        args.into_iter().map(OsString::from).collect()
    }
}

pub(crate) enum BackendInput<'a> {
    Subdomains(&'a Domain),
    Urls(&'a Domain),
    Resolve(&'a [Host]),
}

pub(crate) struct CommandOutput {
    pub stdout: Vec<u8>,
    pub partial: Option<PartialInfo>,
}

enum BackendFailure { Operational(String), Evidence(String) }
impl BackendFailure {
    fn message(self) -> String { match self { Self::Operational(error) | Self::Evidence(error) => error } }
}

fn executable(path: &Path) -> bool {
    path.metadata().is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

fn resolve_backend(backend: Backend) -> Result<PathBuf> {
    if let Some(value) = std::env::var_os(backend.environment()) {
        let path = PathBuf::from(value);
        if !path.is_absolute() { return Err(format!("{} must be an absolute executable path", backend.environment())); }
        if !executable(&path) { return Err(format!("{} is not an executable file", backend.environment())); }
        return Ok(path);
    }
    let search = std::env::var_os("PATH").ok_or_else(|| format!("{} unavailable: PATH is not set", backend.name()))?;
    for directory in std::env::split_paths(&search) {
        let path = directory.join(backend.name());
        if executable(&path) {
            return std::fs::canonicalize(&path).map_err(|error| format!("resolve {}: {error}", backend.name()));
        }
    }
    Err(format!("{} backend not found; configure {} with an absolute executable path or install it on PATH", backend.name(), backend.environment()))
}

struct Capture {
    pid: u32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    status: Option<ExitStatus>,
    timed_out: bool,
    output_overflow: bool,
    errors: Vec<String>,
    descendant_statuses: Vec<Value>,
}

impl Capture {
    fn succeeded(&self) -> bool {
        !self.timed_out && !self.output_overflow && self.errors.is_empty() && self.status.is_some_and(|status| status.success())
    }
    fn evidence(&self) -> Value {
        json!({"evidence_type":"command_capture", "not_network_packet_evidence":true,
            "stdout_base64":STANDARD.encode(&self.stdout), "stderr_base64":STANDARD.encode(&self.stderr),
            "pid":self.pid, "stdout_bytes":self.stdout.len(), "stderr_bytes":self.stderr.len(),
            "exit_code":self.status.and_then(|status| status.code()),
            "signal":self.status.and_then(|status| status.signal()),
            "raw_wait_status":self.status.map(|status| status.into_raw()),
            "timed_out":self.timed_out, "output_overflow":self.output_overflow,
            "truncated":self.timed_out || self.output_overflow || !self.errors.is_empty(), "discarded_bytes_at_least":if self.output_overflow { 1 } else { 0 },
            "errors":self.errors, "reaped_descendants":self.descendant_statuses})
    }
}

// The guard also covers early I/O/setup errors: descendants cannot retain our pipes.
struct ProcessGroup { child: Child, reaped: bool }
impl ProcessGroup {
    fn kill_group(&mut self) -> std::io::Result<()> {
        let result = unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
        if result == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) { return Err(error); }
        }
        Ok(())
    }
    fn reap(&mut self) -> std::io::Result<ExitStatus> {
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.kill_group();
            let _ = self.child.wait();
            let _ = reap_group_descendants(self.child.id());
        }
    }
}

// Linux subreaping lets this long-lived MCP process reap orphaned backend
// descendants itself, instead of leaving cleanup to an unrelated PID 1.
fn enable_subreaper() -> Result<()> {
    static ENABLED: LazyLock<Result<()>> = LazyLock::new(|| {
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == -1 {
            Err(format!("enable backend descendant reaping: {}", std::io::Error::last_os_error()))
        } else { Ok(()) }
    });
    (*ENABLED).clone()
}

fn reap_group_descendants(group: u32) -> Result<Vec<Value>> {
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut statuses = Vec::new();
    loop {
        let mut status = 0;
        let pid = unsafe { libc::waitpid(-(group as i32), &mut status, libc::WNOHANG) };
        if pid > 0 { statuses.push(json!({"pid":pid,"raw_wait_status":status})); continue; }
        if pid == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) { return Ok(statuses); }
            if error.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(format!("reap backend descendants: {error}"));
        }
        if Instant::now() >= deadline { return Err("backend descendant reaping exceeded cleanup deadline".into()); }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn nonblocking(fd: RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

// Return captured bytes only, with one extra observed byte used to detect overflow.
fn drain(reader: &mut (impl Read + ?Sized), target: &mut Vec<u8>, remaining: &mut usize, deadline: Instant) -> std::io::Result<(bool, bool)> {
    let mut buffer = [0u8; 8192];
    loop {
        if Instant::now() >= deadline { return Ok((false, false)); }
        let size = buffer.len().min(remaining.saturating_add(1));
        match reader.read(&mut buffer[..size]) {
            Ok(0) => return Ok((true, false)),
            Ok(count) => {
                let retained = count.min(*remaining);
                target.extend_from_slice(&buffer[..retained]);
                *remaining -= retained;
                if retained < count { return Ok((false, true)); }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok((false, false)),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn capture_command(path: &Path, args: &[OsString], input: &[u8], timeout: Duration, budget: usize) -> Result<Capture> {
    enable_subreaper()?;
    let child = Command::new(path).args(args).stdin(if input.is_empty() { Stdio::null() } else { Stdio::piped() }).stdout(Stdio::piped()).stderr(Stdio::piped())
        .process_group(0).spawn().map_err(|error| format!("spawn {}: {error}", path.display()))?;
    let mut process = ProcessGroup { child, reaped: false };
    let mut stdin = process.child.stdin.take();
    let mut written = 0usize;
    let mut stdout = process.child.stdout.take().ok_or("missing backend stdout pipe")?;
    let mut stderr = process.child.stderr.take().ok_or("missing backend stderr pipe")?;
    let mut capture = Capture { pid: process.child.id(), stdout: Vec::new(), stderr: Vec::new(), status: None, timed_out: false, output_overflow: false, errors: Vec::new(), descendant_statuses: Vec::new() };
    if let Err(error) = nonblocking(stdout.as_raw_fd()).and_then(|()| nonblocking(stderr.as_raw_fd())) {
        capture.errors.push(format!("configure backend pipes: {error}"));
    }
    let deadline = Instant::now() + timeout;
    if let Some(pipe) = &stdin {
        if let Err(error) = nonblocking(pipe.as_raw_fd()) { capture.errors.push(format!("configure backend stdin: {error}")); }
    }
    let (mut out_done, mut err_done) = (false, false);
    let mut remaining = budget;
    let mut group_stopped = false;
    while capture.errors.is_empty() && !capture.output_overflow {
        if Instant::now() >= deadline { capture.timed_out = true; break; }
        if let Some(pipe) = &mut stdin {
            match pipe.write(&input[written..]) {
                Ok(0) => { capture.errors.push("write backend stdin: zero-byte write".into()); }
                Ok(count) => written += count,
                Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => (),
                Err(error) => capture.errors.push(format!("write backend stdin: {error}")),
            }
            if written == input.len() { stdin.take(); }
        }
        for (reader, target, done) in [(&mut stdout as &mut dyn Read, &mut capture.stdout, &mut out_done), (&mut stderr as &mut dyn Read, &mut capture.stderr, &mut err_done)] {
            if *done { continue; }
            match drain(reader, target, &mut remaining, deadline) {
                Ok((eof, overflow)) => { *done = eof; capture.output_overflow |= overflow; }
                Err(error) => capture.errors.push(format!("read backend output: {error}")),
            }
            if capture.output_overflow || !capture.errors.is_empty() { break; }
        }
        if capture.output_overflow || !capture.errors.is_empty() { break; }
        match process.child.try_wait() {
            Ok(Some(status)) => {
                capture.status = Some(status);
                // Always stop descendants, even if the group leader has already exited.
                if !group_stopped {
                    if let Err(error) = process.kill_group() { capture.errors.push(format!("kill backend process group: {error}")); break; }
                    group_stopped = true;
                }
                if out_done && err_done { break; }
            }
            Ok(None) => (),
            Err(error) => { capture.errors.push(format!("wait for backend: {error}")); break; }
        }
        let remaining_time = deadline.saturating_duration_since(Instant::now());
        let wait = remaining_time.min(Duration::from_millis(10));
        if !wait.is_zero() { std::thread::sleep(wait); }
    }
    if !group_stopped {
        if let Err(error) = process.kill_group() { capture.errors.push(format!("kill backend process group: {error}")); }
    }
    drop(stdin);
    match process.reap() {
        Ok(status) => capture.status = Some(status),
        Err(error) => capture.errors.push(format!("reap backend: {error}")),
    }
    // Retain bytes already emitted before the kill rather than dropping pipe tails.
    if capture.errors.is_empty() && !capture.output_overflow {
        let cleanup_deadline = Instant::now() + Duration::from_millis(100);
        for (reader, target) in [(&mut stdout as &mut dyn Read, &mut capture.stdout), (&mut stderr as &mut dyn Read, &mut capture.stderr)] {
            match drain(reader, target, &mut remaining, cleanup_deadline) {
                Ok((_, overflow)) => capture.output_overflow |= overflow,
                Err(error) => capture.errors.push(format!("drain backend output after reap: {error}")),
            }
            if capture.output_overflow { break; }
        }
    }
    match reap_group_descendants(capture.pid) {
        Ok(statuses) => capture.descendant_statuses = statuses,
        Err(error) => capture.errors.push(error),
    }
    if written < input.len() { capture.errors.push(format!("backend stdin incomplete: wrote {written} of {} bytes", input.len())); }
    Ok(capture)
}

fn captured_output(backend: Backend, mut capture: Capture) -> Result<CommandOutput> {
    if capture.succeeded() { return Ok(CommandOutput { stdout: capture.stdout, partial: None }); }
    let error = format!("{} failed: exit={:?}, signal={:?}, timeout={}, output_overflow={}, errors={:?}", backend.name(),
        capture.status.and_then(|s|s.code()), capture.status.and_then(|s|s.signal()), capture.timed_out, capture.output_overflow, capture.errors);
    let parsed_bytes = capture.stdout.iter().rposition(|byte| *byte == b'\n').map_or(0, |index| index + 1);
    if !capture.stdout[..parsed_bytes].iter().any(|byte| !byte.is_ascii_whitespace()) { return Err(error); }
    let partial = PartialInfo {
        error, cutoff_reason: if capture.timed_out { "timeout" } else if capture.output_overflow { "output_budget" }
            else if !capture.errors.is_empty() { "io_failure" } else { "backend_exit" }.into(),
        captured_bytes: capture.stdout.len() + capture.stderr.len(), parsed_bytes,
        discarded_tail_bytes: capture.stdout.len() - parsed_bytes,
        backend_exit: capture.status.and_then(|s|s.code()), backend_signal: capture.status.and_then(|s|s.signal()),
    };
    capture.stdout.truncate(parsed_bytes);
    Ok(CommandOutput { stdout: capture.stdout, partial: Some(partial) })
}

pub(crate) fn command_output(input: BackendInput<'_>, audit: &Audit) -> Result<CommandOutput> {
    command_output_classified(input, audit).map_err(BackendFailure::message)
}

fn command_output_classified(input: BackendInput<'_>, audit: &Audit) -> std::result::Result<CommandOutput, BackendFailure> {
    let (backend, domain, stdin) = match input {
        BackendInput::Subdomains(domain) => (Backend::Subfinder, Some(domain), Vec::new()),
        BackendInput::Urls(domain) => (Backend::Gau, Some(domain), Vec::new()),
        BackendInput::Resolve(hosts) => {
            if hosts.is_empty() || hosts.len() > 512 { return Err(BackendFailure::Operational("dnsx requires 1..512 validated hosts".into())); }
            let mut bytes = Vec::new();
            for host in hosts { bytes.extend_from_slice(host.as_str().as_bytes()); bytes.push(b'\n'); }
            (Backend::Dnsx, None, bytes)
        }
    };
    let path = match resolve_backend(backend) {
        Ok(path) => path,
        Err(error) => {
            audit.record("command_backend_unavailable", json!({"backend":backend.name(),"error":error})).map_err(BackendFailure::Evidence)?;
            return Err(BackendFailure::Operational(error));
        }
    };
    let args = backend.args(domain);
    let argv: Vec<&OsStr> = std::iter::once(path.as_os_str()).chain(args.iter().map(OsString::as_os_str)).collect();
    audit.record("command_intent", json!({"evidence_type":"command_execution", "backend":backend.name(),
        "argv":argv.iter().map(|arg|arg.to_string_lossy()).collect::<Vec<_>>(),
        "argv_base64":argv.iter().map(|arg|STANDARD.encode(arg.as_bytes())).collect::<Vec<_>>(),
        "stdin":if stdin.is_empty() {"closed"} else {"validated_host_lines"}, "stdin_base64":STANDARD.encode(&stdin),
        "shell":false, "timeout_seconds":COMMAND_TIMEOUT.as_secs(), "combined_output_budget_bytes":OUTPUT_BUDGET})).map_err(BackendFailure::Evidence)?;
    let capture = match capture_command(&path, &args, &stdin, COMMAND_TIMEOUT, OUTPUT_BUDGET) {
        Ok(capture) => capture,
        Err(error) => {
            audit.record("command_start_failed", json!({"backend":backend.name(),"error":error})).map_err(BackendFailure::Evidence)?;
            return Err(BackendFailure::Operational(error));
        }
    };
    // Always journal the entire retained capture, including the incomplete record.
    audit.record("command_capture", capture.evidence()).map_err(BackendFailure::Evidence)?;
    captured_output(backend, capture).map_err(BackendFailure::Operational)
}

struct Parsed {
    items: BTreeSet<String>,
    observations: Value,
}

fn sources(record: &Value) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for key in ["source", "sources"] {
        match &record[key] {
            Value::String(value) => { result.insert(value.clone()); }
            Value::Array(values) => for value in values { if let Some(source) = value.as_str() { result.insert(source.to_owned()); } },
            _ => (),
        }
    }
    result
}

fn parse_subdomains(bytes: &[u8], domain: &Domain) -> Result<Parsed> {
    let text = std::str::from_utf8(bytes).map_err(|error| format!("subfinder stdout is not UTF-8: {error}"))?;
    let mut hosts: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut rejected = Vec::new();
    let mut duplicates = 0usize;
    let mut records = 0usize;
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() { continue; }
        records += 1;
        let record: Value = match serde_json::from_str(line) {
            Ok(record) => record,
            Err(error) => { rejected.push(json!({"line":index+1,"reason":"invalid_json","error":error.to_string()})); continue; }
        };
        if let Some(input) = record.get("input") {
            if !input.as_str().is_some_and(|value| Domain::parse(value).is_ok_and(|value| value.as_str() == domain.as_str())) {
                rejected.push(json!({"line":index+1,"reason":"unexpected_input_domain"})); continue;
            }
        }
        let Some(value) = record["host"].as_str() else {
            rejected.push(json!({"line":index+1,"reason":"missing_string_host"})); continue;
        };
        if value.trim().is_empty() {
            rejected.push(json!({"line":index+1,"reason":"empty_host"})); continue;
        }
        for candidate in value.lines() {
            match Domain::parse(candidate.trim()) {
                Ok(host) if domain.contains_host(host.as_str()) => {
                    if hosts.contains_key(host.as_str()) { duplicates += 1; }
                    hosts.entry(host.as_str().to_owned()).or_default().extend(sources(&record));
                }
                Ok(_) => rejected.push(json!({"line":index+1,"candidate":candidate,"reason":"out_of_scope"})),
                Err(error) => rejected.push(json!({"line":index+1,"candidate":candidate,"reason":"invalid_host","error":error})),
            }
        }
    }
    let items = hosts.keys().cloned().collect();
    let accepted: Vec<Value> = hosts.into_iter().map(|(host, sources)|json!({"host":host,"sources":sources})).collect();
    Ok(Parsed { items, observations: json!({"evidence_type":"passive_backend_discovery", "records":records,"accepted":accepted,"duplicates":duplicates,"discarded":rejected}) })
}

fn parse_urls(bytes: &[u8], domain: &Domain) -> Result<Parsed> {
    let text = std::str::from_utf8(bytes).map_err(|error| format!("gau stdout is not UTF-8: {error}"))?;
    let mut items = BTreeSet::new();
    let mut rejected = Vec::new();
    let mut duplicates = 0usize;
    let mut records = 0usize;
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() { continue; }
        records += 1;
        match WebUrl::parse(line.trim()) {
            Ok(url) if domain.contains_host(url.as_url().host_str().unwrap_or("")) => {
                if !items.insert(url.as_str().to_owned()) { duplicates += 1; }
            }
            Ok(_) => rejected.push(json!({"line":index+1,"reason":"out_of_scope"})),
            Err(error) => rejected.push(json!({"line":index+1,"reason":"invalid_url","error":error})),
        }
    }
    Ok(Parsed { observations: json!({"evidence_type":"historical_archive_discovery", "asserted_live":false, "providers":["wayback","commoncrawl"],"records":records,"accepted":items,"duplicates":duplicates,"discarded":rejected}), items })
}

fn filter_passive(parsed: &mut Parsed, mut permits: impl FnMut(&str) -> bool, urls: bool) -> usize {
    let denied: Vec<_> = parsed.items.iter().filter(|item| {
        let host = if urls { Url::parse(item).ok().and_then(|url|url.host_str().map(str::to_owned)) } else { Some((*item).clone()) };
        !host.is_some_and(|host| permits(&host))
    }).cloned().collect();
    for item in &denied { parsed.items.remove(item); }
    parsed.observations["policy_excluded"] = json!(denied);
    parsed.observations["authorization_not_inferred_from_discovery"] = json!(true);
    denied.len()
}

fn require_partial_items(parsed: &Parsed, partial: &Option<PartialInfo>) -> Result<()> {
    if parsed.items.is_empty() {
        if let Some(partial) = partial { return Err(format!("{}; no usable permitted records in complete-line prefix", partial.error)); }
    }
    Ok(())
}

pub fn subdomains(input: &SubdomainsInput, audit: &Audit) -> Result<WorkflowResult> {
    input.validate()?;
    let policy = Policy::load()?;
    policy.record(audit)?;
    let output = command_output(BackendInput::Subdomains(&input.domain), audit)?;
    let mut parsed = parse_subdomains(&output.stdout, &input.domain)?;
    let excluded = filter_passive(&mut parsed, |host|policy.permits_host(host), false);
    audit.record("subdomain_discovery", std::mem::take(&mut parsed.observations))?;
    require_partial_items(&parsed, &output.partial)?;
    let mut result = WorkflowResult::complete(parsed.items.into_iter().map(Value::String).collect());
    result.coverage = json!({"policy_excluded":excluded,"passive_only":true,"ownership_asserted":false});
    result.partial = output.partial;
    Ok(result)
}

fn decode_entities(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('&') {
        result.push_str(&rest[..start]);
        rest = &rest[start..];
        let Some(end) = rest.find(';').filter(|end| *end <= 12) else {
            result.push('&'); rest = &rest[1..]; continue;
        };
        let entity = &rest[1..end];
        let character = match entity {
            "amp" => Some('&'), "quot" => Some('"'), "apos" | "#39" => Some('\''), "lt" => Some('<'), "gt" => Some('>'),
            _ => entity.strip_prefix("#x").or_else(||entity.strip_prefix("#X")).and_then(|v|u32::from_str_radix(v,16).ok()).or_else(||entity.strip_prefix('#').and_then(|v|v.parse().ok())).and_then(char::from_u32),
        };
        if let Some(character) = character { result.push(character); } else { result.push_str(&rest[..=end]); }
        rest = &rest[end+1..];
    }
    result.push_str(rest);
    result
}

struct Extractor { tags: Regex, attrs: Regex, locations: Regex, literals: Regex, scripts: Regex, base: Regex }

struct Candidate {
    value: String,
    source: &'static str,
    kind: QueueKind,
    class: &'static str,
    fetch: bool,
}

fn candidate(value: String, source: &'static str, kind: QueueKind, fetch: bool) -> Candidate {
    let lower = value.to_ascii_lowercase();
    let template = value.contains(['{', '}', '[', ']']) || value.split('/').any(|part| part.starts_with(':'))
        || value.contains('*') || ["%7b","%7d","%5b","%5d"].iter().any(|token|lower.contains(token));
    let noise = value == "/" && source.contains("literal") || value.contains(['|', ';', '(', ')']);
    Candidate { value, source, kind, class: if template { "template_candidate" } else if noise { "literal_noise" }
        else if !fetch { "literal_candidate" } else { "navigation" }, fetch: fetch && !template && !noise }
}

fn static_class(url: &Url) -> Option<&'static str> {
    let path = url.path().to_ascii_lowercase();
    let extension = path.rsplit('.').next().unwrap_or("");
    if matches!(extension, "js" | "mjs" | "cjs") { Some("javascript_asset") }
    else if matches!(extension, "css" | "png" | "jpg" | "jpeg" | "gif" | "svg" | "ico" | "webp" | "avif" | "woff" | "woff2" | "ttf" | "eot" | "otf" | "mp4" | "webm" | "mp3" | "pdf" | "map") { Some("static_asset_candidate") }
    else { None }
}
impl Extractor {
    fn new() -> Self {
        Self {
            tags: Regex::new(r"(?is)<(?:a|area|link|script)\b[^>]*>").expect("fixed tag regex"),
            base: Regex::new(r#"(?is)<base\b[^>]*?\shref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#).expect("fixed base URL regex"),
            attrs: Regex::new(r#"(?is)\s(?:href|src)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#).expect("fixed attribute regex"),
            locations: Regex::new(r"(?is)<loc\b[^>]*>\s*([^<]*)\s*</loc\s*>").expect("fixed sitemap regex"),
            literals: Regex::new(r#"["'`](/[^\s"'`<>\\]*)["'`]"#).expect("fixed literal path regex"),
            scripts: Regex::new(r"(?is)<script\b[^>]*>(.*?)</script\s*>").expect("fixed inline script regex"),
        }
    }
    fn links(&self, url: &Url, response: &network::Fetch) -> Vec<Candidate> {
        let mut links = Vec::new();
        let body = String::from_utf8_lossy(&response.body);
        let content_type = response.headers.get("content-type").map(String::as_str).unwrap_or("");
        let html = content_type.contains("html") || content_type.is_empty() && body.trim_start().starts_with('<');
        if html {
            for tag in self.tags.find_iter(&body) {
                let lower = tag.as_str().to_ascii_lowercase();
                let (source, kind, fetch) = if lower.starts_with("<script") { ("script_src", QueueKind::Asset, true) }
                    else if lower.starts_with("<link") { ("html_link_metadata", QueueKind::Metadata, false) }
                    else { ("html_navigation", QueueKind::Navigation, true) };
                for attr in self.attrs.captures_iter(tag.as_str()) {
                    if let Some(value) = attr.get(1).or_else(||attr.get(2)).or_else(||attr.get(3)) {
                        links.push(candidate(decode_entities(value.as_str()), source, kind, fetch));
                    }
                }
            }
            for script in self.scripts.captures_iter(&body) {
                for literal in self.literals.captures_iter(&script[1]) {
                    links.push(candidate(literal[1].to_owned(), "inline_script_literal", QueueKind::Navigation, false));
                }
            }
        } else if content_type.contains("javascript") || static_class(url) == Some("javascript_asset") {
            for literal in self.literals.captures_iter(&body) {
                links.push(candidate(literal[1].to_owned(), "javascript_literal", QueueKind::Navigation, false));
            }
        }
        if content_type.contains("xml") || url.path().ends_with(".xml") {
            for location in self.locations.captures_iter(&body) {
                links.push(candidate(decode_entities(location[1].trim()), "sitemap_location", QueueKind::Navigation, true));
            }
        }
        if url.path() == "/robots.txt" {
            for line in body.lines() {
                let line = line.split('#').next().unwrap_or("");
                if let Some((key, value)) = line.split_once(':') {
                    if key.trim().eq_ignore_ascii_case("sitemap") && !value.trim().is_empty() {
                        links.push(candidate(value.trim().to_owned(), "robots_sitemap", QueueKind::Metadata, true));
                    }
                }
            }
        }
        if html {
            if let Some(base) = self.base.captures(&body)
                .and_then(|capture| capture.get(1).or_else(|| capture.get(2)).or_else(|| capture.get(3)))
                .and_then(|href| url.join(&decode_entities(href.as_str())).ok())
                .filter(|base| matches!(base.scheme(), "http" | "https")) {
                for link in &mut links {
                    if !link.value.is_empty() && !link.value.starts_with('#') {
                        if let Ok(resolved) = base.join(&link.value) { link.value = resolved.into(); }
                    }
                }
            }
        }
        links
    }
}

fn scoped_link(base: &Url, candidate: &str, origin: &url::Origin) -> Result<Url> {
    if candidate.is_empty() || candidate.starts_with('#') || candidate.chars().any(char::is_control) {
        return Err("empty, fragment-only, or control-containing link".into());
    }
    let joined = base.join(candidate).map_err(|error|format!("invalid link: {error}"))?;
    let validated = WebUrl::parse(joined.as_str())?;
    if &validated.as_url().origin() != origin { return Err("outside exact seed origin".into()); }
    Ok(validated.as_url().clone())
}

fn pace_crawl(interval: Duration) -> Result<()> {
    let mut last = LAST_CRAWL_REQUEST.lock().map_err(|_|"crawl rate limiter poisoned")?;
    if let Some(previous) = *last {
        let delay = interval.saturating_sub(previous.elapsed());
        if !delay.is_zero() { std::thread::sleep(delay); }
    }
    *last = Some(Instant::now());
    Ok(())
}

#[derive(Default)]
struct Robots {
    rules: Vec<(Regex, usize, bool)>,
}

impl Robots {
    fn parse(body: &[u8]) -> Self {
        let mut groups = Vec::new();
        let (mut agents, mut rules) = (Vec::<String>::new(), Vec::<(String, bool)>::new());
        let mut directives_started = false;
        for line in String::from_utf8_lossy(body).lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            let Some((key, value)) = line.split_once(':') else { continue; };
            let value = value.trim();
            if key.trim().eq_ignore_ascii_case("user-agent") {
                if directives_started {
                    groups.push((std::mem::take(&mut agents), std::mem::take(&mut rules)));
                    directives_started = false;
                }
                agents.push(value.to_ascii_lowercase());
            } else if key.trim().eq_ignore_ascii_case("allow") || key.trim().eq_ignore_ascii_case("disallow") {
                directives_started = true;
                if !value.is_empty() { rules.push((value.to_owned(), key.trim().eq_ignore_ascii_case("allow"))); }
            }
        }
        groups.push((agents, rules));
        let specificity = |agents: &[String]| {
            if agents.iter().any(|agent| agent == "recon" || agent == "recon/1") { 2 }
            else if agents.is_empty() || agents.iter().any(|agent| agent == "*") { 1 } else { 0 }
        };
        let selected = groups.iter().map(|(agents, _)|specificity(agents)).max().unwrap_or(0);
        let mut result = Self::default();
        for (agents, rules) in groups {
            if selected == 0 || specificity(&agents) != selected { continue; }
            for (path, allow) in rules {
                let anchored = path.ends_with('$');
                let path = path.strip_suffix('$').unwrap_or(&path);
                let expression = format!("^{}{}", path.split('*').map(regex::escape).collect::<Vec<_>>().join(".*"), if anchored { "$" } else { "" });
                result.rules.push((Regex::new(&expression).expect("escaped robots expression"), path.replace('*', "").len(), allow));
            }
        }
        result
    }
    fn permits(&self, url: &Url) -> bool {
        let target = match url.query() { Some(query) => format!("{}?{query}",url.path()), None => url.path().to_owned() };
        self.rules.iter().filter(|(expression, _, _)|expression.is_match(&target))
            .max_by_key(|(_, length, allow)|(*length, *allow)).is_none_or(|(_, _, allow)|*allow)
    }
}

struct Pending {
    resume: VecDeque<CrawlQueueEntry>,
    new: VecDeque<CrawlQueueEntry>,
    deferred: VecDeque<CrawlQueueEntry>,
    seen: BTreeSet<String>,
    omitted: usize,
    limit: usize,
}
impl Pending {
    fn len(&self) -> usize { self.resume.len() + self.new.len() + self.deferred.len() }
    fn push(&mut self, entry: CrawlQueueEntry, resume: bool) -> &'static str {
        if !self.seen.insert(entry.url.as_str().to_owned()) { return "already_queued_or_visited"; }
        if self.len() >= self.limit {
            // A bundle cannot consume the bounded queue ahead of actual navigation.
            let displaced = if !matches!(entry.kind, QueueKind::Asset) {
                self.new.iter().rposition(|entry|matches!(entry.kind, QueueKind::Asset)).and_then(|index|self.new.remove(index))
            } else { None };
            self.omitted = self.omitted.saturating_add(1);
            if displaced.is_none() { return "queue_limit"; }
        }
        if resume { self.resume.push_back(entry); } else { self.new.push_back(entry); }
        "queued"
    }
    fn pop(&mut self, pages: usize, assets: usize) -> Option<(CrawlQueueEntry, bool)> {
        for (resume, queue) in [(true, &mut self.resume), (false, &mut self.new)] {
            if pages < MAX_PAGES {
                if let Some(index) = queue.iter().position(|entry|!matches!(entry.kind, QueueKind::Asset)) { return queue.remove(index).map(|entry|(entry,resume)); }
            }
            if assets < MAX_ASSETS {
                if let Some(index) = queue.iter().position(|entry|matches!(entry.kind, QueueKind::Asset)) { return queue.remove(index).map(|entry|(entry,resume)); }
            }
        }
        None
    }
    fn into_entries(self) -> Vec<CrawlQueueEntry> { self.resume.into_iter().chain(self.new).chain(self.deferred).collect() }
}

struct CrawlOptions<'a> {
    checkpoint: Option<&'a CrawlCheckpoint>,
    scope_sha256: Option<&'a str>,
    queue_limit: usize,
}
struct CrawlOutcome {
    items: BTreeSet<String>,
    coverage: Value,
    checkpoint: CrawlCheckpoint,
    partial: Option<PartialInfo>,
    observations: usize,
}
fn workflow_partial(error: String, cutoff_reason: &str) -> PartialInfo {
    PartialInfo { error, cutoff_reason: cutoff_reason.into(), captured_bytes:0, parsed_bytes:0, discarded_tail_bytes:0, backend_exit:None, backend_signal:None }
}
fn queue_entry(url: WebUrl, depth: usize, kind: QueueKind) -> CrawlQueueEntry {
    let kind = if static_class(url.as_url()) == Some("javascript_asset") { QueueKind::Asset } else { kind };
    CrawlQueueEntry { origin:url.as_url().origin().ascii_serialization(), url, depth, kind }
}

// Only observation/fetch boundaries are injected: fixtures require no sockets or journal.
fn crawl(seeds: &[WebUrl], options: CrawlOptions<'_>, permits: impl Fn(&str) -> bool,
    mut record: impl FnMut(&str, Value) -> Result<()>,
    mut fetch: impl FnMut(&Url) -> Result<network::Fetch, network::FetchError>) -> Result<CrawlOutcome> {
    if options.queue_limit == 0 || options.queue_limit > 2000 { return Err("crawl queue limit must be 1..2000".into()); }
    if let Some(checkpoint) = options.checkpoint {
        checkpoint.validate(seeds)?;
        if checkpoint.scope_sha256.as_deref() != options.scope_sha256 {
            return Err("crawl checkpoint scope fingerprint differs from current operator policy".into());
        }
    }
    for seed in seeds {
        if !permits(seed.as_url().host_str().unwrap_or("")) { return Err("crawl seed is excluded by operator policy".into()); }
    }
    let mut visited: BTreeMap<String, WebUrl> = options.checkpoint.into_iter().flat_map(|checkpoint|&checkpoint.visited)
        .map(|url|(url.as_str().to_owned(), url.clone())).collect();
    let mut queue = Pending { resume:VecDeque::new(), new:VecDeque::new(), deferred:VecDeque::new(),
        seen:visited.keys().cloned().collect(), omitted:options.checkpoint.map_or(0, |checkpoint|checkpoint.omitted), limit:options.queue_limit };
    if let Some(checkpoint) = options.checkpoint {
        for entry in &checkpoint.pending { queue.push(queue_entry(entry.url.clone(),entry.depth,entry.kind), true); }
    }
    let mut safety = VecDeque::new();
    let mut origins = BTreeSet::new();
    let mut robots = BTreeMap::<String, Robots>::new();
    let mut unavailable = BTreeMap::<String, &'static str>::new();
    for seed in seeds {
        let origin = seed.as_url().origin().ascii_serialization();
        if origins.insert(origin.clone()) {
            let url = WebUrl::parse(seed.as_url().join("/robots.txt").map_err(|e|e.to_string())?.as_str())?;
            // Current robots policy is a safety preflight, never stale checkpoint authority.
            record("crawl_safety_preflight", json!({"url":url.as_str(),"reason":"current_robots_policy","resume_visited_exception":visited.contains_key(url.as_str()),"charged_to":"navigation_metadata"}))?;
            safety.push_back(queue_entry(url, 0, QueueKind::Metadata));
        }
        for (url, kind) in [(seed.clone(), QueueKind::Navigation),
            (WebUrl::parse(seed.as_url().join("/sitemap.xml").map_err(|e|e.to_string())?.as_str())?, QueueKind::Metadata)] {
            record("crawl_seed", json!({"url":url.as_str(),"origin":origin,"asserted_live":false,"queue_status":queue.push(queue_entry(url.clone(),0,kind), false)}))?;
        }
    }
    let extractor = Extractor::new();
    let (mut pages, mut assets, mut responses, mut negatives) = (0usize, 0usize, 0usize, 0usize);
    let (mut depth_limited, mut candidates_only, mut policy_excluded, mut robots_excluded, mut static_skipped) = (0usize,0usize,0usize,0usize,0usize);
    let (mut resumed, mut safety_requests, mut truncated_bodies, mut visited_limited) = (0usize,0usize,0usize,false);
    let (mut failed_fetches, mut safety_unavailable, mut safety_not_queried, mut origin_not_queried) = (0usize,0usize,0usize,0usize);
    let mut failures = Vec::new();
    let mut items = BTreeSet::new();
    let mut candidate_classes = BTreeMap::<&'static str,usize>::new();
    let mut invalid_or_off_origin = 0usize;
    loop {
        let preflight = !safety.is_empty() && pages < MAX_PAGES;
        let Some((entry, from_resume)) = (if preflight { safety.pop_front().map(|entry|(entry,false)) } else { queue.pop(pages, assets) }) else { break; };
        let url = entry.url.as_url();
        if !preflight && visited.contains_key(entry.url.as_str()) { continue; }
        if !permits(url.host_str().unwrap_or("")) {
            policy_excluded += 1;
            record("crawl_not_queried",json!({"url":url.as_str(),"reason":"operator_policy"}))?;
            continue;
        }
        if !preflight {
            let queued_candidate = candidate(url.as_str().to_owned(),"checkpoint_navigation",entry.kind,true);
            if !queued_candidate.fetch {
                candidates_only += 1;
                record("crawl_not_queried",json!({"url":url.as_str(),"reason":queued_candidate.class,"source":"checkpoint_navigation"}))?;
                continue;
            }
            if let Some(reason) = unavailable.get(&entry.origin) {
                origin_not_queried += 1;
                record("crawl_not_queried",json!({"url":url.as_str(),"reason":reason}))?;
                if *reason != "observed_origin_negative" { queue.deferred.push_back(entry); }
                continue;
            }
            if !robots.get(&entry.origin).is_some_and(|rules|rules.permits(url)) {
                robots_excluded += 1;
                record("crawl_not_queried",json!({"url":url.as_str(),"reason":"robots_exclusion"}))?;
                continue;
            }
            if static_class(url) == Some("static_asset_candidate") {
                static_skipped += 1;
                record("crawl_not_queried",json!({"url":url.as_str(),"reason":"static_asset_candidate"}))?;
                continue;
            }
        }
        if visited.len() >= MAX_VISITED && !visited.contains_key(entry.url.as_str()) {
            if preflight { safety_not_queried += 1; } else { queue.deferred.push_back(entry); }
            visited_limited = true;
            break;
        }
        if preflight { safety_requests += 1; }
        if from_resume { resumed += 1; }
        if matches!(entry.kind, QueueKind::Asset) { assets += 1; } else { pages += 1; }
        let response = match fetch(url) {
            Ok(response) => response,
            Err(network::FetchError::Negative(error)) => {
                negatives += 1;
                visited.insert(entry.url.as_str().to_owned(), entry.url.clone());
                if preflight { unavailable.insert(entry.origin.clone(), "observed_origin_negative"); }
                record("crawl_negative",json!({"url":url.as_str(),"outcome":error,"asserted_live":false}))?;
                continue;
            }
            Err(network::FetchError::Operational(error)) => {
                record("crawl_fetch_failed",json!({"url":url.as_str(),"error":error}))?;
                failures.push(error);
                failed_fetches += 1;
                if preflight { safety_unavailable += 1; }
                if preflight { unavailable.insert(entry.origin, "robots_preflight_failed"); }
                else { queue.deferred.push_back(entry); }
                continue;
            }
            Err(network::FetchError::Audit(error) | network::FetchError::Invalid(error)) => return Err(error),
        };
        responses += 1;
        visited.insert(entry.url.as_str().to_owned(), entry.url.clone());
        queue.seen.insert(entry.url.as_str().to_owned());
        if response.truncated { truncated_bodies += 1; }
        if let Some(error) = &response.read_error {
            failures.push(format!("response body read failed for {url}: {error}"));
            failed_fetches += 1;
            if !preflight {
                visited.remove(entry.url.as_str());
                queue.deferred.push_back(entry.clone());
            }
        }
        if (200..300).contains(&response.status) { items.insert(url.as_str().to_owned()); }
        record("crawl_live_response",json!({"url":url.as_str(),"status":response.status,"depth":entry.depth,"kind":entry.kind,"body_truncated":response.truncated,"evidence_type":"observed_live_http_response"}))?;
        if preflight {
            if (200..300).contains(&response.status) && !response.truncated {
                robots.insert(entry.origin.clone(), Robots::parse(&response.body));
            } else if (400..500).contains(&response.status) && response.status != 429 {
                robots.insert(entry.origin.clone(), Robots::default());
            } else {
                unavailable.insert(entry.origin.clone(), "robots_preflight_unavailable");
                failures.push(format!("robots preflight unavailable: {} status={} truncated={}", url, response.status, response.truncated));
                safety_unavailable += 1;
            }
        }
        if (300..400).contains(&response.status) {
            record("crawl_redirect_not_followed",json!({"url":url.as_str(),"location":response.headers.get("location"),"reason":"automatic_redirects_disabled"}))?;
            continue;
        }
        if !(200..300).contains(&response.status) { continue; }
        let mut discovered = Vec::new();
        let mut discarded = Vec::new();
        for mut candidate in extractor.links(url, &response) {
            let origin = url.origin();
            match scoped_link(url, &candidate.value, &origin) {
                Ok(link) => {
                    if !permits(link.host_str().unwrap_or("")) {
                        policy_excluded += 1;
                        discarded.push(json!({"candidate":candidate.value,"source":candidate.source,"reason":"operator_policy"}));
                        continue;
                    }
                    if !matches!(candidate.class,"template_candidate"|"literal_noise") {
                        if let Some(class) = static_class(&link) {
                            candidate.class = class;
                            if class == "javascript_asset" && candidate.fetch { candidate.kind = QueueKind::Asset; }
                            else { candidate.fetch = false; }
                        } else if matches!(candidate.kind,QueueKind::Asset) { candidate.class = "javascript_asset"; }
                    }
                    let candidate_only = !candidate.fetch;
                    let template_or_noise = matches!(candidate.class,"template_candidate"|"literal_noise");
                    if !template_or_noise { items.insert(link.as_str().to_owned()); }
                    let status = if candidate_only { candidates_only += 1; "candidate_only" }
                        else if !robots.get(&entry.origin).is_some_and(|rules|rules.permits(&link)) {
                            robots_excluded += 1; "robots_exclusion"
                        } else if entry.depth >= MAX_DEPTH {
                            if queue.seen.insert(link.as_str().to_owned()) { depth_limited += 1; queue.omitted = queue.omitted.saturating_add(1); }
                            "depth_limit"
                        } else {
                            queue.push(queue_entry(WebUrl::parse(link.as_str())?,entry.depth+1,candidate.kind),false)
                        };
                    *candidate_classes.entry(candidate.class).or_default() += 1;
                    discovered.push(json!({"url":link.as_str(),"candidate":candidate.value,"source":candidate.source,"class":candidate.class,"queue_status":status,"asserted_live":false}));
                }
                Err(error) => {
                    invalid_or_off_origin += 1;
                    *candidate_classes.entry(candidate.class).or_default() += 1;
                    if !candidate.fetch { candidates_only += 1; }
                    discarded.push(json!({"candidate":candidate.value,"source":candidate.source,"class":candidate.class,"reason":error}));
                }
            }
        }
        record("crawl_link_discovery",json!({"from":url.as_str(),"asserted_live":false,"discovered":discovered,"discarded":discarded}))?;
    }
    let queued_not_fetched = queue.len();
    let pending_assets = queue.resume.iter().chain(&queue.new).chain(&queue.deferred).filter(|entry|matches!(entry.kind,QueueKind::Asset)).count();
    let pending_pages = queued_not_fetched - pending_assets;
    let omitted = queue.omitted;
    let coverage = json!({"max_pages":MAX_PAGES,"max_js_assets":MAX_ASSETS,"max_depth":MAX_DEPTH,
        "navigation_metadata_requests":pages,"js_asset_requests":assets,"attempts":pages+assets,"live_responses":responses,
        "explicit_negatives":negatives,"failed_fetches":failed_fetches,"operational_failures":failures,
        "queued_not_fetched":queued_not_fetched,"queue_limit":options.queue_limit,"queue_omitted":omitted,
        "depth_limited_links":depth_limited,"candidate_only":candidates_only,"policy_excluded":policy_excluded,
        "robots_excluded":robots_excluded,"static_skipped":static_skipped,"body_truncated_responses":truncated_bodies,
        "navigation_metadata_pending":pending_pages,"js_asset_pending":pending_assets,
        "candidate_classes":candidate_classes,"invalid_or_off_origin":invalid_or_off_origin,
        "page_budget_exhausted":pages == MAX_PAGES && (pending_pages > 0 || !safety.is_empty()),
        "asset_budget_exhausted":assets == MAX_ASSETS && pending_assets > 0,"visited_budget_exhausted":visited_limited,
        "resumed_requests":resumed,"robots_safety_requests":safety_requests,"robots_revalidated_on_resume":options.checkpoint.is_some(),
        "robots_safety_unavailable":safety_unavailable,"robots_safety_not_queried":safety_not_queried+safety.len(),"origin_not_queried":origin_not_queried,
        "exhaustive":false,"discovery_complete":queued_not_fetched == 0 && omitted == 0 && failures.is_empty() && truncated_bodies == 0 && safety.is_empty() && safety_not_queried == 0,
        "get_only":true,"forms_submitted":false,"redirects_followed":false});
    record("crawl_coverage",coverage.clone())?;
    if responses + negatives == 0 && !failures.is_empty() { return Err("crawl observed no usable responses; see recorded fetch failures".into()); }
    let partial = if failures.is_empty() { None } else { Some(workflow_partial(failures.join("; "), "crawl_operational_failure")) };
    let checkpoint = CrawlCheckpoint { v:1,pending:queue.into_entries(),visited:visited.into_values().collect(),omitted,scope_sha256:options.scope_sha256.map(str::to_owned) };
    Ok(CrawlOutcome { items,coverage,checkpoint,partial,observations:responses+negatives })
}

fn queue_limit() -> Result<usize> {
    match std::env::var("RECON_QUEUE_LIMIT") {
        Ok(value) => value.parse::<usize>().ok().filter(|limit|(1..=2000).contains(limit)).ok_or("RECON_QUEUE_LIMIT must be 1..2000".into()),
        Err(std::env::VarError::NotPresent) => Ok(512),
        Err(error) => Err(format!("RECON_QUEUE_LIMIT: {error}")),
    }
}

fn archive(domain: &Domain, policy: &Policy, audit: &Audit) -> std::result::Result<(Parsed, Option<PartialInfo>, usize), BackendFailure> {
    let output = command_output_classified(BackendInput::Urls(domain),audit)?;
    let mut parsed = parse_urls(&output.stdout,domain).map_err(BackendFailure::Operational)?;
    let excluded = filter_passive(&mut parsed,|host|policy.permits_host(host),true);
    audit.record("archive_url_discovery",std::mem::take(&mut parsed.observations)).map_err(BackendFailure::Evidence)?;
    require_partial_items(&parsed,&output.partial).map_err(BackendFailure::Operational)?;
    Ok((parsed,output.partial,excluded))
}

fn merge_partial(existing: &mut Option<PartialInfo>, mut incoming: PartialInfo) {
    if let Some(partial) = existing {
        if incoming.captured_bytes > 0 && partial.captured_bytes == 0 {
            incoming.error = format!("{}; {}",partial.error,incoming.error);
            *partial = incoming;
        } else {
            partial.error.push_str("; ");
            partial.error.push_str(&incoming.error);
        }
    } else { *existing = Some(incoming); }
}

fn merge_archive(result: &mut WorkflowResult, items: &mut BTreeSet<String>, crawl_observations: usize,
    stage: std::result::Result<(Parsed, Option<PartialInfo>, usize), BackendFailure>,
    mut record: impl FnMut(&str, Value) -> Result<()>) -> Result<()> {
    match stage {
        Ok((parsed,partial,excluded)) => {
            result.coverage["archive"] = json!({"completed":partial.is_none(),"policy_excluded":excluded,"accepted":parsed.items.len(),"asserted_live":false});
            items.extend(parsed.items);
            if let Some(partial) = partial { merge_partial(&mut result.partial,partial); }
        }
        Err(BackendFailure::Evidence(error)) => return Err(error),
        Err(BackendFailure::Operational(error)) if crawl_observations > 0 => {
            record("required_stage_failed",json!({"stage":"archive","error":error,"preserved_crawl_observations":crawl_observations}))?;
            result.coverage["archive"] = json!({"completed":false,"required_stage_failed":true,"error":error});
            merge_partial(&mut result.partial,workflow_partial(error,"required_archive_stage_failed"));
        }
        Err(BackendFailure::Operational(error)) => return Err(error),
    }
    Ok(())
}

pub fn urls(input: &UrlsInput, audit: &Audit) -> Result<WorkflowResult> {
    input.validate()?;
    if input.resume.is_some() { return Err("resume receipt must be expanded by the verified frontend before crawling".into()); }
    let policy = Policy::load()?;
    // Fingerprint validation in crawl occurs before its first fetch/socket.
    policy.record(audit)?;
    let mut result = WorkflowResult::complete(Vec::new());
    let mut items = BTreeSet::new();
    let mut crawl_observations = 0;
    if matches!(input.mode, UrlMode::Crawl | UrlMode::Combined) {
        let outcome = crawl(&input.seeds,CrawlOptions { checkpoint:input.queue.as_ref(),scope_sha256:policy.fingerprint(),queue_limit:queue_limit()? },
            |host|policy.permits_host(host),|kind,data|audit.record(kind,data),
            |url| { pace_crawl(policy.request_interval()).map_err(network::FetchError::Invalid)?; network::fetch(url,audit) })?;
        items.extend(outcome.items);
        result.coverage["crawl"] = outcome.coverage;
        result.queue = Some(outcome.checkpoint);
        result.partial = outcome.partial;
        crawl_observations = outcome.observations;
    }
    if matches!(input.mode, UrlMode::Archive | UrlMode::Combined) {
        merge_archive(&mut result,&mut items,crawl_observations,archive(&input.domain,&policy,audit),|kind,data|audit.record(kind,data))?;
    }
    result.rows = items.into_iter().map(Value::String).collect();
    result.coverage["historical_and_link_discovery_is_not_live_verification"] = json!(true);
    Ok(result)
}
