//! Receipt-driven inputs from the protected, fully verified journal chain.
use super::{audit::Audit, result::PartialInfo, types::{Domain, ReadInput, WebUrl, validate_run}};
use crate::Result;
use serde_json::{Value, json};

#[derive(Debug)]
pub struct SavedObservation {
    pub seq: u64,
    pub kind: String,
    pub data: Value,
}

#[derive(Debug)]
pub struct SavedWorkflow {
    pub run: String,
    pub hash: String,
    pub cursor: String,
    pub tool: String,
    pub status: String,
    pub completeness: String,
    pub domain: Domain,
    /// Original request event data, including its typed input and source label.
    pub request: Value,
    pub payload: Value,
    pub result_seq: u64,
    pub observations: Vec<SavedObservation>,
    pub partial: Option<PartialInfo>,
}

impl SavedWorkflow {
    /// Source references only: never raw rows, query values or captured bodies.
    pub fn metadata(&self) -> Value {
        json!({"source_run":self.run,"source_hash":self.hash,"source_cursor":self.cursor,
            "source_tool":self.tool,"source_status":self.status,"source_completeness":self.completeness,
            "source_domain":self.domain,"source_result_seq":self.result_seq})
    }

    pub fn require_complete(&self) -> Result<()> {
        if self.status != "complete" || self.completeness != "complete" || self.partial.is_some() {
            return Err("source must be a completed workflow, not retained partial observations".into());
        }
        Ok(())
    }
}

fn selection(run: &str, surface: bool) -> ReadInput {
    let mut input = ReadInput::full(run.into());
    input.select.kind = ["request", "workflow_result", "complete", "failure"].into_iter().map(str::to_owned).collect();
    if surface {
        input.select.kind.extend(["crawl_live_response".into(), "crawl_link_discovery".into()]);
    }
    input.select.class = ["request", "tool_observation", "complete", "failure"].into_iter().map(str::to_owned).collect();
    input
}

/// Read only selected facts, after Audit verifies the entire protected chain.
/// The run is an identifier, never a model-selected filesystem path.
pub fn load(run: &str, expected_tool: &str) -> Result<SavedWorkflow> {
    validate_run(run)?;
    source_tool(expected_tool)?;
    decode_projection(run, expected_tool, Audit::read(&selection(run, false))?)
}

/// Include compact historical crawl evidence, not HTTP bodies or command captures.
pub fn load_surface(run: &str) -> Result<SavedWorkflow> {
    validate_run(run)?;
    decode_projection(run, "recon_urls", Audit::read(&selection(run, true))?)
}

fn source_tool(tool: &str) -> Result<()> {
    if !matches!(tool, "recon_subdomains" | "recon_urls") {
        return Err("saved source must be recon_subdomains or recon_urls, never a model verdict".into());
    }
    Ok(())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| format!("saved source requires string {key}"))
}

fn number(value: &Value, key: &str) -> Result<u64> {
    value.get(key).and_then(Value::as_u64).ok_or_else(|| format!("saved source requires unsigned {key}"))
}

fn hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn scoped_url(value: &str, domain: &Domain) -> Result<()> {
    let url = WebUrl::parse(value)?;
    if !domain.contains_host(url.as_url().host_str().ok_or("source URL has no host")?) {
        return Err("saved source URL is outside the request domain".into());
    }
    Ok(())
}

fn validate_rows(payload: &Value, tool: &str, domain: &Domain) -> Result<usize> {
    let rows = payload.get("rows").and_then(Value::as_array).ok_or("saved workflow requires rows array")?;
    for row in rows {
        let value = row.as_str().ok_or("saved source rows must be strings")?;
        if tool == "recon_subdomains" {
            let host = Domain::parse(value)?;
            if !domain.contains_host(host.as_str()) { return Err("saved hostname is outside the request domain".into()); }
        } else {
            scoped_url(value, domain)?;
        }
    }
    Ok(rows.len())
}

fn validate_observation(observation: &SavedObservation, domain: &Domain) -> Result<()> {
    let data = &observation.data;
    match observation.kind.as_str() {
        "crawl_live_response" => {
            scoped_url(text(data, "url")?, domain)?;
            if !(100..=599).contains(&number(data, "status")?) {
                return Err("saved crawl response has invalid HTTP status".into());
            }
        }
        "crawl_link_discovery" => {
            scoped_url(text(data, "from")?, domain)?;
            if data.get("asserted_live") != Some(&Value::Bool(false)) {
                return Err("link discovery cannot assert HTTP liveness".into());
            }
            for candidate in data.get("discovered").and_then(Value::as_array).ok_or("saved discovery requires discovered array")? {
                // Legacy discoveries were URL strings without navigation provenance.
                let url = if let Some(url) = candidate.as_str() { url } else {
                    if candidate.get("asserted_live").is_some_and(|value| value != &Value::Bool(false)) {
                        return Err("discovered candidate cannot assert HTTP liveness".into());
                    }
                    text(candidate, "url")?
                };
                scoped_url(url, domain)?;
            }
        }
        _ => return Err("unsupported saved observation".into()),
    }
    Ok(())
}

fn partial_info(value: Value) -> Result<PartialInfo> {
    // Option fields must also be retained explicitly; absent facts are not defaults.
    for key in ["error", "cutoff_reason", "captured_bytes", "parsed_bytes", "discarded_tail_bytes", "backend_exit", "backend_signal"] {
        if value.get(key).is_none() { return Err(format!("retained partial information is missing {key}")); }
    }
    let partial: PartialInfo = serde_json::from_value(value).map_err(|error| format!("invalid retained partial information: {error}"))?;
    if partial.error.trim().is_empty() || partial.cutoff_reason.trim().is_empty()
        || partial.parsed_bytes.checked_add(partial.discarded_tail_bytes).is_none_or(|bytes| bytes > partial.captured_bytes)
        || (partial.backend_exit.is_some() && partial.backend_signal.is_some())
        || partial.backend_exit.is_some_and(|exit| exit < 0)
        || partial.backend_signal.is_some_and(|signal| signal <= 0) {
        return Err("inconsistent retained partial information".into());
    }
    Ok(partial)
}

/// Decode the exact full-payload Audit projection shape without journal access.
/// Caller-supplied JSON is NOT authenticated by this pure decoder. Production
/// callers must use `load` or `load_surface`, which always invoke Audit::read.
#[doc(hidden)]
pub fn decode_projection(run: &str, expected_tool: &str, mut projection: Value) -> Result<SavedWorkflow> {
    validate_run(run)?;
    source_tool(expected_tool)?;
    if text(&projection, "run")? != run || text(&projection, "tool")? != expected_tool {
        return Err("saved source run/tool differs from the requested receipt".into());
    }
    let status = text(&projection, "status")?.to_owned();
    if !matches!(status.as_str(), "complete" | "failure") { return Err("saved source has no verified terminal outcome".into()); }
    let head_hash = text(&projection, "hash")?.to_owned();
    let cursor = text(&projection, "cursor")?.to_owned();
    if !hash(&head_hash) || cursor.is_empty() { return Err("saved source lacks head integrity metadata".into()); }
    let run_events = number(&projection, "run_events")?;
    let selected = number(&projection, "events_total")?;
    if !(3..=4096).contains(&run_events) || selected > run_events
        || number(&projection, "events_omitted")? != 0 || number(&projection, "offset")? != 0
        || projection.get("next_offset") != Some(&Value::Null) {
        return Err("saved source projection is omitted, paginated or inconsistent".into());
    }
    let events = projection.get_mut("events").ok_or("saved source has no selected events")?.take();
    let Value::Array(events) = events else { return Err("saved source requires events array".into()); };
    if selected != events.len() as u64 { return Err("saved source selected event count disagrees".into()); }
    let mut request = None;
    let mut result = None;
    let mut terminal = None;
    let mut observations = Vec::new();
    let mut previous_seq = 0;
    for mut event in events {
        let seq = number(&event, "seq")?;
        if seq <= previous_seq || seq > run_events || terminal.is_some() { return Err("saved source has inconsistent selected sequence".into()); }
        previous_seq = seq;
        let kind = text(&event, "kind")?.to_owned();
        let class = text(&event, "class")?;
        let event_hash = text(&event, "hash")?;
        let event_cursor = text(&event, "cursor")?;
        if !hash(event_hash) || event_cursor.is_empty() { return Err("selected event lacks integrity metadata".into()); }
        match kind.as_str() {
            "request" if class == "request" && seq == 1 && request.is_none() => {}
            "workflow_result" if class == "tool_observation" && request.is_some() && result.is_none() => {}
            "crawl_live_response" | "crawl_link_discovery" if class == "tool_observation" && expected_tool == "recon_urls" && request.is_some() && result.is_none() => {}
            "complete" | "failure" if class == kind && kind == status && seq == run_events && result.is_some() => {
                if event_hash != head_hash || event_cursor != cursor { return Err("selected terminal disagrees with source head".into()); }
            }
            _ => return Err("unexpected, duplicate or wrongly attributed saved event".into()),
        }
        let data = event.get_mut("data").ok_or("selected saved event payload was omitted")?.take();
        if !data.is_object() && !(kind == "complete" && data.is_array()) {
            return Err("selected saved event requires an object or legacy completion array".into());
        }
        match kind.as_str() {
            "request" => request = Some(data),
            "workflow_result" => result = Some((seq, data)),
            "complete" | "failure" => terminal = Some(data),
            _ => observations.push(SavedObservation { seq, kind, data }),
        }
    }
    let request = request.ok_or("saved source is missing its request")?;
    if text(&request, "tool")? != expected_tool || text(&request, "source")? != "typed_tool_request" {
        return Err("saved request tool/source attribution is contradictory or model supplied".into());
    }
    let input = request.get("input").filter(|input| input.is_object()).ok_or("saved source requires typed input object")?;
    let domain = Domain::parse(text(input, "domain")?)?;
    let (result_seq, mut payload) = result.ok_or("saved source is missing its workflow result")?;
    let terminal = terminal.ok_or("saved source is missing its terminal event")?;
    if text(&payload, "tool")? != expected_tool { return Err("saved result tool differs from its request".into()); }
    let completeness;
    let partial;
    match payload.get("v") {
        None | Some(Value::Number(_)) if payload.get("v").is_none() || payload.get("v").and_then(Value::as_u64) == Some(1) => {
            if status != "complete" || payload.get("rows").is_some() || payload.get("partial").is_some() {
                return Err("legacy saved result must be completed and unambiguous".into());
            }
            if payload.get("completeness").is_some_and(|value| value != "complete") {
                return Err("legacy result contradicts its completed terminal".into());
            }
            let items = payload.as_object_mut().ok_or("saved result must be an object")?.remove("items").ok_or("legacy result is missing items")?;
            if !items.is_array() { return Err("legacy result requires items array".into()); }
            let terminal_rows = if terminal.is_array() { Some(&terminal) } else { terminal.get("items") };
            if terminal_rows.is_some_and(|rows| rows != &items) {
                return Err("legacy completion rows contradict the recorded workflow result".into());
            }
            payload["rows"] = items;
            let total = validate_rows(&payload, expected_tool, &domain)?;
            for (key, expected) in [("total", total as u64), ("omitted", 0)] {
                if payload.get(key).is_some() && number(&payload, key)? != expected { return Err("legacy result has inconsistent totals".into()); }
            }
            payload["completeness"] = json!("complete");
            completeness = "complete".to_owned();
            partial = None;
        }
        Some(value) if value.as_u64() == Some(2) => {
            if payload.get("items").is_some() { return Err("v2 saved result cannot contain legacy items".into()); }
            let total = validate_rows(&payload, expected_tool, &domain)?;
            if number(&payload, "total")? != total as u64 || number(&payload, "omitted")? != 0 {
                return Err("saved result rows are omitted or totals disagree".into());
            }
            completeness = text(&payload, "completeness")?.to_owned();
            match completeness.as_str() {
                "complete" if status == "complete" => {
                    if payload.get("partial").is_some_and(|value| !value.is_null()) { return Err("completed result retains contradictory partial information".into()); }
                    partial = None;
                }
                "partial" if status == "failure" => {
                    let retained = payload.get("partial").ok_or("partial result lacks retained failure information")?;
                    if terminal.get("partial") != Some(retained) || terminal.get("unrecorded_observation") != Some(&Value::Bool(false)) {
                        return Err("failure terminal does not retain the same fully recorded partial information".into());
                    }
                    if terminal.get("error") != retained.get("error") { return Err("failure terminal contradicts partial error".into()); }
                    // Only the small partial-info object is copied; row datasets are moved.
                    partial = Some(partial_info(retained.clone())?);
                }
                _ => return Err("saved result completeness contradicts terminal status".into()),
            }
            if status == "complete" && (terminal.get("v").and_then(Value::as_u64) != Some(2)
                || text(&terminal, "tool")? != expected_tool || number(&terminal, "total")? != total as u64
                || text(&terminal, "completeness")? != completeness) {
                return Err("saved complete terminal contradicts its v2 result".into());
            }
        }
        _ => return Err("saved workflow result has unsupported schema version".into()),
    }
    // Legacy completions may predate v2 summaries, but any retained summary must agree.
    for key in ["tool", "completeness", "total", "omitted"] {
        if let Some(value) = terminal.get(key) {
            let consistent = match key {
                "tool" => value == expected_tool,
                "completeness" => value == &completeness,
                "total" => value.as_u64() == payload["rows"].as_array().map(|rows| rows.len() as u64),
                "omitted" => value.as_u64() == Some(0),
                _ => unreachable!(),
            };
            if !consistent { return Err(format!("saved terminal has contradictory {key}")); }
        }
    }
    for observation in &observations { validate_observation(observation, &domain)?; }
    Ok(SavedWorkflow { run:run.into(), hash:head_hash, cursor, tool:expected_tool.into(), status,
        completeness, domain, request, payload, result_seq, observations, partial })
}
