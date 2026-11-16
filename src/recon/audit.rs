//! Tool-owned observations in the root-owned system journal, not an execution attestation.
//! Root/admin can alter storage; retention can remove history. Another process with the
//! same UID (including unrestricted agent execution) can append forged new entries.
//! Hash chains detect inconsistent/missing records, not a malicious writer with the
//! ability to construct a new chain. Trusted journal attribution identifies the sender
//! process; it does not authenticate the truth of its observations or its binary.
use super::types::{ReadInput, VerdictInput, validate_run};
use crate::{Result, sha256};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const VERSION: &str = "1";
const CHUNK_BYTES: usize = 24 * 1024;
const MAX_EVENT_BYTES: usize = 32 * 1024 * 1024;
const MAX_RUN_BYTES: usize = 256 * 1024 * 1024;
const MAX_EVENTS: usize = 4096;
const MAX_RECORDS: usize = MAX_RUN_BYTES / CHUNK_BYTES + MAX_EVENTS;
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const JOURNAL_ROOT: &str = "/var/log/journal";
const JOURNAL_FIELDS: [&str; 14] = ["_UID", "_PID", "_EXE", "_BOOT_ID", "_TRANSPORT", "RECON_VERSION", "RECON_RUN", "RECON_SEQ", "RECON_INDEX", "RECON_PARTS", "RECON_HASH", "RECON_SIZE", "RECON_CHUNK_HASH", "RECON_DATA"];
const LIMITATIONS: &str = "Root/admin can rewrite or delete journal storage; retention can remove records. Ordinary users cannot edit protected history, but can append forged new entries under their own trusted UID/PID/EXE. Tool binaries and unrestricted same-user execution are not an attestation boundary. SHA256 chains are consistency checks, not cryptographic execution provenance. Model verdicts are supplied opinions, never tool-confirmed findings.";

#[derive(Clone, Debug, Serialize)]
pub struct Receipt {
    pub run: String,
    pub hash: String,
    pub cursor: String,
    pub events: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    v: u8,
    run: String,
    seq: u64,
    kind: String,
    class: String,
    prev: String,
    data: Value,
}

struct State {
    seq: u64,
    hash: String,
    bytes: usize,
    closed: bool,
    poisoned: bool,
}

pub struct Audit {
    run: String,
    identity: Identity,
    state: Mutex<State>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Identity {
    uid: String,
    pid: String,
    exe: String,
    boot: String,
}

impl Audit {
    pub fn start(tool: &str, input: &Value) -> Result<Self> {
        if tool.is_empty() || tool.len() > 64 || !tool.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':')) {
            return Err("invalid audit tool name".into());
        }
        protected_journal()?;
        let mut random = [0u8; 16];
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut random)).map_err(|e| format!("run randomness: {e}"))?;
        let run = random.iter().map(|b| format!("{b:02x}")).collect();
        let identity = Identity {
            uid: unsafe { libc::getuid() }.to_string(),
            pid: std::process::id().to_string(),
            exe: std::fs::read_link("/proc/self/exe").map_err(|e| format!("sender executable: {e}"))?.to_str().ok_or("non-UTF8 executable path")?.into(),
            boot: std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|e| format!("boot identity: {e}"))?.trim().replace('-', ""),
        };
        let audit = Self { run, identity, state: Mutex::new(State { seq: 0, hash: ZERO_HASH.into(), bytes: 0, closed: false, poisoned: false }) };
        {
            let mut state = audit.state.lock().map_err(|_| "audit mutex poisoned")?;
            audit.append(&mut state, "request", "request", &json!({"tool":tool,"input":input,"source":if tool == "evidence_verdict" {"model_supplied"} else {"typed_tool_request"}}), false)?;
            audit.acknowledge(&state, false)?;
        }
        Ok(audit)
    }

    pub fn record(&self, kind: &str, data: impl std::borrow::Borrow<Value>) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| "audit mutex poisoned")?;
        if state.poisoned { return Err("audit has an unrecorded observation; success is forbidden".into()); }
        let result = self.append(&mut state, kind, "tool_observation", data.borrow(), false);
        if result.is_err() { state.poisoned = true; }
        result
    }

    pub fn finish(&self, result: &Value) -> Result<Receipt> {
        let mut state = self.state.lock().map_err(|_| "audit mutex poisoned")?;
        if state.poisoned { return Err("audit has an unrecorded observation; success is forbidden".into()); }
        self.append(&mut state, "complete", "complete", result, true)?;
        state.closed = true;
        self.acknowledge(&state, true)
    }

    pub fn abort(&self, error: &str) -> Result<Receipt> {
        self.abort_terminal(error, None)
    }

    /// Close a partial workflow as failure, retaining any unrecorded-observation flag.
    pub fn abort_with_partial(&self, error: &str, partial: &Value) -> Result<Receipt> {
        self.abort_terminal(error, Some(partial))
    }

    fn abort_terminal(&self, error: &str, partial: Option<&Value>) -> Result<Receipt> {
        let mut state = self.state.lock().map_err(|_| "audit mutex poisoned")?;
        let unrecorded = state.poisoned;
        let mut data = json!({"error":error,"unrecorded_observation":unrecorded});
        if let Some(partial) = partial { data["partial"] = partial.clone(); }
        self.append(&mut state, "failure", "failure", &data, true)?;
        state.closed = true;
        self.acknowledge(&state, true)
    }

    fn append(&self, state: &mut State, kind: &str, class: &str, data: &Value, terminal: bool) -> Result<()> {
        if state.closed { return Err("audit run is already closed".into()); }
        if kind.is_empty() || kind.len() > 96 || !kind.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')) {
            return Err("invalid audit event kind".into());
        }
        if state.seq as usize >= MAX_EVENTS - usize::from(!terminal) { return Err("audit event budget exceeded".into()); }
        let seq = state.seq + 1;
        let bytes = encode_event(&self.run, seq, kind, class, &state.hash, data)?;
        let budget = MAX_RUN_BYTES - if terminal { 0 } else { MAX_EVENT_BYTES };
        if bytes.len() > MAX_EVENT_BYTES || state.bytes + bytes.len() > budget { return Err("audit payload budget exceeded; no bytes silently discarded".into()); }
        let hash = sha256(&bytes);
        let count = bytes.len().div_ceil(CHUNK_BYTES);
        for (index, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
            let fields = [
                "SYSLOG_IDENTIFIER=recon-evidence".to_owned(),
                "MESSAGE=Recon evidence transport chunk".to_owned(),
                format!("RECON_VERSION={VERSION}"), format!("RECON_RUN={}", self.run),
                format!("RECON_SEQ={seq}"), format!("RECON_INDEX={index}"),
                format!("RECON_PARTS={count}"), format!("RECON_HASH={hash}"),
                format!("RECON_SIZE={}", bytes.len()), format!("RECON_CHUNK_HASH={}", sha256(chunk)),
                format!("RECON_DATA={}", STANDARD.encode(chunk)),
            ];
            if let Err(error) = send(&fields) { state.poisoned = true; return Err(error); }
        }
        state.seq = seq;
        state.hash = hash;
        state.bytes += bytes.len();
        Ok(())
    }

    fn acknowledge(&self, state: &State, complete: bool) -> Result<Receipt> {
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            let records = journal_records(&self.run)?;
            if let Ok(verified) = verify(&self.run, &records) {
                if verified.identity != self.identity { return Err("journal sender attribution differs from the actual tool process".into()); }
                if let Ok(receipt) = verified.receipt(&self.run, &state.hash, state.seq as usize, complete) {
                    return Ok(receipt);
                }
            }
            if Instant::now() >= deadline { return Err("journal did not acknowledge the complete expected SHA256 chain within 4 seconds (missing/dropped/invalid records); no success receipt".into()); }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn read(input: &ReadInput) -> Result<Value> {
        input.validate()?;
        Ok(verify(&input.run, &journal_records(&input.run)?)?.project(input))
    }

    pub fn verdict(input: &VerdictInput) -> Result<Receipt> {
        input.validate()?;
        let original = verify(&input.run, &journal_records(&input.run)?)?;
        let refs = original.references(input)?;
        let request = json!({"source_run":input.run,"source_hash":original.hash,"source_cursor":original.cursor,"verdict":input.verdict,"note":input.note,"evidence":refs,"source":"model_supplied","tool_confirmed":false});
        let audit = Self::start("evidence_verdict", &request)?;
        {
            let mut state = audit.state.lock().map_err(|_| "audit mutex poisoned")?;
            audit.append(&mut state, "verdict", "model_supplied", &request, false)?;
        }
        audit.finish(&json!({"source":"model_supplied","tool_confirmed":false}))
    }
}

// Deterministic JSON representation: sorted object keys, original array order,
// serde_json number/string encoding. This does not claim RFC8785 float semantics.
fn emit(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort_unstable();
            for (i, key) in keys.into_iter().enumerate() {
                if i != 0 { out.push(b','); }
                serde_json::to_writer(&mut *out, key).map_err(|e| e.to_string())?;
                out.push(b':');
                emit(&map[key], out)?;
            }
            out.push(b'}');
        }
        Value::Array(values) => {
            out.push(b'[');
            for (i, value) in values.iter().enumerate() { if i != 0 { out.push(b','); } emit(value, out)?; }
            out.push(b']');
        }
        _ => serde_json::to_writer(&mut *out, value).map_err(|e| e.to_string())?,
    }
    if out.len() > MAX_EVENT_BYTES { return Err("audit event exceeds 32MiB canonical JSON budget".into()); }
    Ok(())
}
fn canonical(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    emit(value, &mut bytes)?;
    Ok(bytes)
}
fn encode_event(run: &str, seq: u64, kind: &str, class: &str, prev: &str, data: &Value) -> Result<Vec<u8>> {
    // Write the envelope in canonical key order without cloning raw observations.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"{\"class\":");
    serde_json::to_writer(&mut bytes, class).map_err(|e| e.to_string())?;
    bytes.extend_from_slice(b",\"data\":");
    emit(data, &mut bytes)?;
    for (key, value) in [("kind", kind), ("prev", prev), ("run", run)] {
        bytes.push(b',');
        serde_json::to_writer(&mut bytes, key).map_err(|e| e.to_string())?;
        bytes.push(b':');
        serde_json::to_writer(&mut bytes, value).map_err(|e| e.to_string())?;
    }
    write!(&mut bytes, ",\"seq\":{seq},\"v\":1}}").map_err(|e| e.to_string())?;
    if bytes.len() > MAX_EVENT_BYTES { return Err("audit event exceeds 32MiB canonical JSON budget".into()); }
    Ok(bytes)
}

struct Verified {
    events: Vec<(Event, String, String, usize)>,
    identity: Identity,
    hash: String,
    cursor: String,
}

impl Verified {
    fn terminal(&self) -> bool { self.events.last().is_some_and(|(e, _, _, _)| matches!(e.class.as_str(), "complete" | "failure")) }
    fn receipt(self, run: &str, hash: &str, events: usize, terminal: bool) -> Result<Receipt> {
        if self.events.len() != events || self.hash != hash || (terminal && !self.terminal()) {
            return Err("journal chain does not match the writer's expected event count/hash/terminal state".into());
        }
        Ok(Receipt { run: run.into(), hash: self.hash, cursor: self.cursor, events: self.events.len() })
    }
    fn references(&self, input: &VerdictInput) -> Result<Vec<Value>> {
        input.validate()?;
        if !self.terminal() { return Err("cannot reference an incomplete run".into()); }
        let mut seen = BTreeSet::new();
        let mut refs = Vec::new();
        for seq in &input.evidence {
            if !seen.insert(*seq) { return Err("duplicate evidence sequence reference".into()); }
            let (event, hash, cursor, _) = self.events.iter().find(|(e, _, _, _)| e.seq == *seq).ok_or("evidence sequence does not exist")?;
            if event.class != "tool_observation" { return Err("evidence must reference immutable tool observations, not requests, completions or model verdicts".into()); }
            refs.push(json!({"seq":seq,"hash":hash,"cursor":cursor}));
        }
        Ok(refs)
    }
    fn output(self, payloads: bool) -> Value {
        let status = match self.events.last().map(|(e, _, _, _)| e.class.as_str()) { Some("complete") => "complete", Some("failure") => "failure", _ => "incomplete" };
        let tool = self.events.first().map(|(event, _, _, _)| event.data["tool"].clone()).unwrap_or(Value::Null);
        let events: Vec<_> = self.events.into_iter().map(|(event, hash, cursor, bytes)| {
            let mut value = json!({"seq":event.seq,"kind":event.kind,"class":event.class,"hash":hash,"cursor":cursor,"bytes":bytes});
            if payloads { value["data"] = event.data; }
            value
        }).collect();
        json!({"tool":tool,"status":status,"hash":self.hash,"cursor":self.cursor,"attribution":self.identity,"events":events,"limits":{"event_bytes":MAX_EVENT_BYTES,"run_bytes":MAX_RUN_BYTES,"events":MAX_EVENTS,"chunk_bytes":CHUNK_BYTES},"limitations":LIMITATIONS})
    }
    fn project(self, input: &ReadInput) -> Value {
        let status = match self.events.last().map(|(e, _, _, _)| e.class.as_str()) { Some("complete") => "complete", Some("failure") => "failure", _ => "incomplete" };
        let tool = self.events.first().map(|(event, _, _, _)| event.data["tool"].clone()).unwrap_or(Value::Null);
        let run_events = self.events.len();
        let integrity = input.include_integrity.unwrap_or(input.include_payloads);
        let select = &input.select;
        let mut events_total = 0;
        let mut events = Vec::new();
        for (event, hash, cursor, bytes) in self.events {
            if (!select.kind.is_empty() && !select.kind.contains(&event.kind))
                || (!select.class.is_empty() && !select.class.contains(&event.class))
                || (!select.seq.is_empty() && !select.seq.contains(&event.seq))
                || (!select.status.is_empty() && !http_status(&event.data).is_some_and(|status| select.status.contains(&status))) {
                continue;
            }
            let index = events_total;
            events_total += 1;
            if index < input.offset || events.len() >= input.limit { continue; }
            let mut value = json!({"seq":event.seq,"kind":event.kind,"class":event.class,"bytes":bytes});
            if integrity {
                value["hash"] = Value::String(hash);
                value["cursor"] = Value::String(cursor);
            }
            for key in ["url", "host", "provider"] {
                if let Some(text) = event.data.get(key).and_then(Value::as_str) {
                    value[key] = Value::String(text.into());
                }
            }
            for key in ["stdout_bytes", "stderr_bytes"] {
                if let Some(bytes) = event.data.get(key).and_then(Value::as_u64) { value[key] = json!(bytes); }
            }
            if let Some(timed_out) = event.data.get("timed_out").and_then(Value::as_bool) { value["timed_out"] = json!(timed_out); }
            if let Some(status) = http_status(&event.data) { value["status"] = json!(status); }
            if let Some(outcome) = event.data.get("outcome").and_then(Value::as_str)
                .or_else(|| event.data.get("status").and_then(Value::as_str)) {
                value["outcome"] = Value::String(outcome.into());
            } else if event.data.get("error").is_some_and(|error| !error.is_null()) {
                value["outcome"] = json!("error");
            }
            if input.include_payloads { value["data"] = event.data; }
            events.push(value);
        }
        let events_omitted = events_total - events.len();
        let end = input.offset + events.len();
        let next_offset = (end < events_total).then_some(end);
        json!({"run":input.run,"tool":tool,"status":status,"hash":self.hash,"cursor":self.cursor,"attribution":self.identity,
            "run_events":run_events,"events_total":events_total,"events_omitted":events_omitted,"offset":input.offset,"next_offset":next_offset,"events":events,
            "limits":{"event_bytes":MAX_EVENT_BYTES,"run_bytes":MAX_RUN_BYTES,"events":MAX_EVENTS,"chunk_bytes":CHUNK_BYTES},"limitations":LIMITATIONS})
    }
}

/// Verify saved journal JSON records without journal access. The caller supplies
/// the records: this pure parser does NOT authenticate their origin. Production
/// readers obtain these fields only from the protected native system journal.
#[doc(hidden)]
pub fn verify_records(run: &str, records: &[Value], include_payloads: bool) -> Result<Value> {
    let mut value = verify(run, records)?.output(include_payloads);
    value["run"] = Value::String(run.into());
    Ok(value)
}

/// Verify every saved journal record before selecting or paginating events.
/// Like `verify_records`, caller-supplied fixtures do not authenticate their origin.
/// Filters intersect before pagination. `events_total` counts all matching events;
/// `events_omitted` counts matching events outside this page, including earlier ones.
/// `next_offset` is relative to that filtered sequence, or null at its end.
/// Run integrity/attribution and terminal status always describe the full chain.
/// Per-event integrity defaults to payload visibility and can be overridden.
pub fn projected_records(input: &ReadInput, records: &[Value]) -> Result<Value> {
    input.validate()?;
    Ok(verify(&input.run, records)?.project(input))
}

fn http_status(data: &Value) -> Option<u16> {
    data.get("status").and_then(Value::as_u64).filter(|status| (100..=599).contains(status)).map(|status| status as u16)
}

/// Pure expected-chain acknowledgement check used by the live writer too.
/// Fixture records alone do not establish trusted storage or sender attribution.
#[doc(hidden)]
pub fn verify_acknowledged(run: &str, records: &[Value], expected_hash: &str, expected_events: usize, require_terminal: bool) -> Result<Receipt> {
    verify(run, records)?.receipt(run, expected_hash, expected_events, require_terminal)
}

/// Pure reference-integrity validation for saved fixtures, not a write API.
#[doc(hidden)]
pub fn verify_verdict_references(input: &VerdictInput, records: &[Value]) -> Result<Value> {
    let verified = verify(&input.run, records)?;
    Ok(Value::Array(verified.references(input)?))
}

fn text<'a>(record: &'a Value, key: &str) -> Result<&'a str> {
    record.get(key).and_then(Value::as_str).ok_or_else(|| format!("missing, duplicate or non-string journal field {key}"))
}
fn number(record: &Value, key: &str) -> Result<usize> {
    let s = text(record, key)?;
    let n: usize = s.parse().map_err(|_| format!("invalid journal integer {key}"))?;
    if n.to_string() != s { return Err(format!("noncanonical journal integer {key}")); }
    Ok(n)
}
fn hex(s: &str, len: usize) -> bool { s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }
fn identity(record: &Value) -> Result<Identity> {
    let uid = text(record, "_UID")?;
    let pid = text(record, "_PID")?;
    if uid.parse::<u32>().is_err() || pid.parse::<u32>().ok().filter(|n| *n > 0).is_none() { return Err("invalid trusted UID/PID".into()); }
    let exe = text(record, "_EXE")?;
    let boot = text(record, "_BOOT_ID")?;
    if !exe.starts_with('/') || !hex(boot, 32) || text(record, "_TRANSPORT")? != "journal" { return Err("missing trusted native journal source attribution".into()); }
    Ok(Identity { uid: uid.into(), pid: pid.into(), exe: exe.into(), boot: boot.into() })
}

fn verify(run: &str, records: &[Value]) -> Result<Verified> {
    validate_run(run)?;
    if records.is_empty() || records.len() > MAX_RECORDS { return Err("journal run absent or exceeds transport budget".into()); }
    let sender = identity(&records[0])?;
    let mut cursors = BTreeSet::new();
    let mut grouped: BTreeMap<usize, Vec<&Value>> = BTreeMap::new();
    for record in records {
        if identity(record)? != sender { return Err("mixed trusted sender attribution within run".into()); }
        let cursor = text(record, "__CURSOR")?;
        if cursor.is_empty() || !cursors.insert(cursor) { return Err("missing or duplicate journal cursor".into()); }
        if text(record, "RECON_RUN")? != run || text(record, "RECON_VERSION")? != VERSION { return Err("journal transport run/version mismatch".into()); }
        let seq = number(record, "RECON_SEQ")?;
        if seq == 0 || seq > MAX_EVENTS { return Err("event sequence out of budget".into()); }
        grouped.entry(seq).or_default().push(record);
    }
    let mut events = Vec::new();
    let mut prev = ZERO_HASH.to_owned();
    let mut total_bytes = 0;
    let mut terminal = false;
    let mut model_run = false;
    for (seq, mut chunks) in grouped {
        if seq != events.len() + 1 || terminal { return Err("missing/forged event sequence or event after terminal record".into()); }
        let size = number(chunks[0], "RECON_SIZE")?;
        let count = number(chunks[0], "RECON_PARTS")?;
        let expected_hash = text(chunks[0], "RECON_HASH")?.to_owned();
        if size == 0 || size > MAX_EVENT_BYTES || count != size.div_ceil(CHUNK_BYTES) || chunks.len() != count || !hex(&expected_hash, 64) { return Err("missing/truncated chunks or invalid event size/hash".into()); }
        total_bytes += size;
        if total_bytes > MAX_RUN_BYTES { return Err("journal run payload budget exceeded".into()); }
        chunks.sort_by_key(|r| number(r, "RECON_INDEX").unwrap_or(usize::MAX));
        let mut bytes = Vec::with_capacity(size);
        for (index, record) in chunks.iter().enumerate() {
            if number(record, "RECON_INDEX")? != index || number(record, "RECON_SIZE")? != size || number(record, "RECON_PARTS")? != count || text(record, "RECON_HASH")? != expected_hash { return Err("inconsistent/duplicate transport chunk".into()); }
            let encoded = text(record, "RECON_DATA")?;
            if encoded.len() > CHUNK_BYTES.div_ceil(3) * 4 { return Err("transport chunk over budget".into()); }
            let chunk = STANDARD.decode(encoded).map_err(|e| format!("invalid base64 chunk: {e}"))?;
            let expected_len = if index + 1 == count { size - index * CHUNK_BYTES } else { CHUNK_BYTES };
            if chunk.len() != expected_len || sha256(&chunk) != text(record, "RECON_CHUNK_HASH")? { return Err("truncated/corrupt transport chunk".into()); }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() != size || sha256(&bytes) != expected_hash { return Err("event checksum mismatch".into()); }
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| format!("event JSON: {e}"))?;
        if canonical(&value)? != bytes { return Err("noncanonical event JSON".into()); }
        let event: Event = serde_json::from_value(value).map_err(|e| format!("invalid event schema: {e}"))?;
        if event.v != 1 || event.run != run || event.seq != seq as u64 || event.prev != prev { return Err("SHA256 event chain/run/sequence mismatch".into()); }
        if seq == 1 {
            if event.class != "request" || event.kind != "request" || event.data.get("tool").and_then(Value::as_str).is_none() || event.data.get("input").is_none() { return Err("run must begin with typed request".into()); }
            model_run = event.data["tool"] == "evidence_verdict";
            let source = if model_run { "model_supplied" } else { "typed_tool_request" };
            if event.data["source"] != source { return Err("request source disagrees with tool/model classification".into()); }
        } else {
            match event.class.as_str() {
                "tool_observation" if !model_run => (),
                "model_supplied" if model_run && event.kind == "verdict" && event.data["source"] == "model_supplied" && event.data["tool_confirmed"] == false => (),
                "complete" if event.kind == "complete" => {
                    if model_run && (event.data["source"] != "model_supplied" || event.data["tool_confirmed"] != false) {
                        return Err("model completion must remain explicitly model supplied, not tool confirmed".into());
                    }
                    terminal = true;
                }
                "failure" if event.kind == "failure" => terminal = true,
                _ => return Err("invalid event class or model/tool fact confusion".into()),
            }
        }
        let cursor = text(chunks.last().ok_or("no chunks")?, "__CURSOR")?.to_owned();
        prev = expected_hash.clone();
        events.push((event, expected_hash, cursor, size));
    }
    let cursor = events.last().ok_or("run has no events")?.2.clone();
    Ok(Verified { events, identity: sender, hash: prev, cursor })
}

// Fail closed unless both the journal storage and every discovered journal file
// are root-owned and cannot be changed through a writable parent directory.
fn protected_journal() -> Result<()> {
    for path in ["/", "/var", "/var/log", JOURNAL_ROOT, "/run", "/run/systemd", "/run/systemd/journal"] {
        let metadata = std::fs::symlink_metadata(path).map_err(|e| format!("protected journal path {path}: {e}"))?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 { return Err(format!("journal path is not a protected root-owned directory: {path}")); }
    }
    let socket = std::fs::symlink_metadata("/run/systemd/journal/socket").map_err(|e| format!("system journal socket: {e}"))?;
    use std::os::unix::fs::FileTypeExt;
    if socket.uid() != 0 || !socket.file_type().is_socket() { return Err("system journal socket is not root-owned".into()); }
    fn check(path: &std::path::Path, depth: usize) -> Result<()> {
        if depth > 4 { return Err("unexpected journal directory depth".into()); }
        for entry in std::fs::read_dir(path).map_err(|e| format!("journal directory unreadable: {e}"))? {
            let entry = entry.map_err(|e| e.to_string())?;
            let metadata = std::fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 || metadata.file_type().is_symlink() { return Err(format!("unprotected journal storage: {}", entry.path().display())); }
            if metadata.is_dir() { check(&entry.path(), depth + 1)?; }
        }
        Ok(())
    }
    check(std::path::Path::new(JOURNAL_ROOT), 0)
}

#[repr(C)]
struct SdJournal { _private: [u8; 0] }
#[link(name = "systemd")]
unsafe extern "C" {
    fn sd_journal_sendv(iov: *const libc::iovec, n: c_int) -> c_int;
    fn sd_journal_open_directory(ret: *mut *mut SdJournal, path: *const c_char, flags: c_int) -> c_int;
    fn sd_journal_close(j: *mut SdJournal);
    fn sd_journal_add_match(j: *mut SdJournal, data: *const c_void, size: usize) -> c_int;
    fn sd_journal_seek_head(j: *mut SdJournal) -> c_int;
    fn sd_journal_next(j: *mut SdJournal) -> c_int;
    fn sd_journal_set_data_threshold(j: *mut SdJournal, size: usize) -> c_int;
    fn sd_journal_enumerate_data(j: *mut SdJournal, data: *mut *const c_void, length: *mut usize) -> c_int;
    fn sd_journal_restart_data(j: *mut SdJournal);
    fn sd_journal_get_cursor(j: *mut SdJournal, cursor: *mut *mut c_char) -> c_int;
}
fn systemd_result(code: c_int, action: &str) -> Result<()> {
    if code < 0 { Err(format!("{action}: {}", std::io::Error::from_raw_os_error(-code))) } else { Ok(()) }
}
fn send(fields: &[String]) -> Result<()> {
    let iov: Vec<_> = fields.iter().map(|s| libc::iovec { iov_base: s.as_ptr() as *mut c_void, iov_len: s.len() }).collect();
    systemd_result(unsafe { sd_journal_sendv(iov.as_ptr(), iov.len() as c_int) }, "system journal send")
}
struct Journal(*mut SdJournal);
impl Drop for Journal { fn drop(&mut self) { unsafe { sd_journal_close(self.0); } } }

fn journal_field(record: &mut serde_json::Map<String, Value>, bytes: &[u8]) -> Result<()> {
    let separator = bytes.iter().position(|b| *b == b'=').ok_or("journal field separator absent")?;
    let field = std::str::from_utf8(&bytes[..separator]).map_err(|e| format!("journal field name UTF8: {e}"))?;
    if !JOURNAL_FIELDS.contains(&field) { return Ok(()); }
    if bytes.len() > CHUNK_BYTES * 2 { return Err("journal field over transport budget".into()); }
    if record.contains_key(field) { return Err(format!("duplicate journal field {field}")); }
    let value = std::str::from_utf8(&bytes[separator + 1..]).map_err(|e| format!("journal field UTF8: {e}"))?;
    record.insert(field.into(), Value::String(value.into()));
    Ok(())
}
fn journal_records(run: &str) -> Result<Vec<Value>> {
    validate_run(run)?;
    protected_journal()?;
    let path = CString::new(JOURNAL_ROOT).map_err(|e| e.to_string())?;
    let mut pointer = std::ptr::null_mut();
    systemd_result(unsafe { sd_journal_open_directory(&mut pointer, path.as_ptr(), 0) }, "open protected system journal")?;
    let journal = Journal(pointer);
    let filter = format!("RECON_RUN={run}");
    systemd_result(unsafe { sd_journal_add_match(journal.0, filter.as_ptr().cast(), filter.len()) }, "match journal run")?;
    // Enumeration must not decompress unrelated fields without a useful size hint.
    // The library may exceed this hint, so journal_field also checks exact sizes.
    systemd_result(unsafe { sd_journal_set_data_threshold(journal.0, CHUNK_BYTES * 2 + 1) }, "set journal field threshold")?;
    systemd_result(unsafe { sd_journal_seek_head(journal.0) }, "seek journal")?;
    let mut records = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let next = unsafe { sd_journal_next(journal.0) };
        systemd_result(next, "read journal entry")?;
        if next == 0 { break; }
        if records.len() >= MAX_RECORDS || Instant::now() > deadline { return Err("journal read transport/time budget exceeded".into()); }
        let mut record = serde_json::Map::new();
        // get_data selects only one value for repeated field names. Enumerate all
        // values instead so malformed native entries cannot hide an alternative.
        unsafe { sd_journal_restart_data(journal.0); }
        loop {
            let mut data = std::ptr::null();
            let mut length = 0;
            let next = unsafe { sd_journal_enumerate_data(journal.0, &mut data, &mut length) };
            systemd_result(next, "enumerate journal fields")?;
            if next == 0 { break; }
            if data.is_null() { return Err("journal field absent".into()); }
            journal_field(&mut record, unsafe { std::slice::from_raw_parts(data.cast::<u8>(), length) })?;
        }
        if record.len() != JOURNAL_FIELDS.len() { return Err("required journal field absent".into()); }
        let mut cursor = std::ptr::null_mut();
        systemd_result(unsafe { sd_journal_get_cursor(journal.0, &mut cursor) }, "read journal cursor")?;
        if cursor.is_null() { return Err("journal cursor absent".into()); }
        let value = unsafe { CStr::from_ptr(cursor) }.to_str().map(str::to_owned).map_err(|e| e.to_string());
        unsafe { libc::free(cursor.cast()); }
        record.insert("__CURSOR".into(), Value::String(value?));
        records.push(Value::Object(record));
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_field_capture_rejects_every_repeated_required_field() {
        for field in JOURNAL_FIELDS {
            let mut record = serde_json::Map::new();
            let original = format!("{field}=saved original");
            journal_field(&mut record, original.as_bytes()).unwrap();
            let alternative = format!("{field}=saved alternative");
            assert!(journal_field(&mut record, alternative.as_bytes()).is_err(), "{field}");
            assert_eq!(record[field], "saved original");
        }
    }

    #[test]
    fn native_field_capture_keeps_complete_values_and_ignores_unrelated_fields() {
        let mut record = serde_json::Map::new();
        journal_field(&mut record, b"MESSAGE=unrelated").unwrap();
        journal_field(&mut record, b"MESSAGE=another unrelated value").unwrap();
        let encoded = format!("RECON_DATA={}", "x".repeat(CHUNK_BYTES.div_ceil(3) * 4));
        journal_field(&mut record, encoded.as_bytes()).unwrap();
        assert_eq!(record.len(), 1);
        assert_eq!(record["RECON_DATA"].as_str().unwrap().len(), CHUNK_BYTES.div_ceil(3) * 4);
        assert!(journal_field(&mut serde_json::Map::new(), b"RECON_DATA=\xff").is_err());
        let oversized = format!("RECON_DATA={}", "x".repeat(CHUNK_BYTES * 2));
        assert!(journal_field(&mut serde_json::Map::new(), oversized.as_bytes()).is_err());
    }
}
