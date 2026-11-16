use super::{audit::{Audit, Receipt}, network, passive, policy, resolve, saved, surface, types::*};
use crate::Result;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::io::{self, BufRead, Read, Write};

const MAX_REQUEST: usize = 65536;
const TOOLS: [&str;8] = ["recon_subdomains","recon_resolve","recon_discover","recon_urls","recon_surface","recon_ports","evidence_read","evidence_verdict"];

pub fn schema(tool: &str) -> Value {
    let domain = json!({"type":"string","format":"hostname","minLength":3,"maxLength":254,"description":"ASCII DNS domain, not a URL, wildcard, IP or command"});
    let hosts = json!({"type":"array","minItems":1,"maxItems":32,"items":{"type":"string","minLength":1,"maxLength":253}});
    let ports = json!({"type":"array","minItems":1,"maxItems":128,"items":{"type":"integer","minimum":1,"maximum":65535}});
    let run = json!({"type":"string","pattern":"^[0-9a-f]{32}$"});
    let queue_entry = json!({"type":"object","additionalProperties":false,"required":["url","origin","depth"],"properties":{
        "url":{"type":"string","format":"uri","maxLength":8192},"origin":{"type":"string","format":"uri","maxLength":8192},
        "depth":{"type":"integer","minimum":0,"maximum":2},"kind":{"type":"string","enum":["navigation","asset","metadata"],"default":"navigation"}}});
    let checkpoint = json!({"type":"object","additionalProperties":false,"required":["v","pending"],"properties":{
        "v":{"const":1},"pending":{"type":"array","maxItems":2000,"items":queue_entry},
        "visited":{"type":"array","maxItems":4096,"items":{"type":"string","format":"uri","maxLength":8192},"default":[]},
        "omitted":{"type":"integer","minimum":0,"default":0},"scope_sha256":{"type":["string","null"],"pattern":"^[0-9a-f]{64}$"}}});
    let (properties,required) = match tool {
        "recon_subdomains" => (json!({"domain":domain,"since":run}),json!(["domain"])),
        "recon_resolve" => {
            let mut resolve_hosts = hosts;
            resolve_hosts["maxItems"] = json!(512);
            resolve_hosts["minItems"] = json!(0);
            (json!({"hosts":resolve_hosts,"domain":domain,"source_run":run}),json!([]))
        },
        "recon_discover" => (json!({"hosts":hosts,"ports":ports,"paths":{"type":"array","minItems":1,"maxItems":64,"items":{"type":"string","pattern":"^/(?!/)","maxLength":2048},"default":["/"]}}),json!(["hosts"])),
        "recon_ports" => (json!({"hosts":hosts,"ports":ports}),json!(["hosts","ports"])),
        "recon_urls" => (json!({"domain":domain,"mode":{"type":"string","enum":["archive","crawl","combined"],"default":"archive","description":"archive: passive providers only, no seeds; crawl: bounded live navigation from seeds; combined: both stages."},"seeds":{"type":"array","maxItems":8,"default":[],"description":"Required for crawl/combined: 1-8 absolute HTTP(S) URLs within domain. Omit for archive.","items":{"type":"string","format":"uri","maxLength":8192}},"since":run,"resume":run,"queue":checkpoint}),json!(["domain"])),
        "recon_surface" => (json!({"run":run,"site":domain,"prefix":{"type":"string","pattern":"^/(?!/)","maxLength":2048,"description":"Optional route prefix to zoom into, not a URL or request target"}}),json!(["run"])),
        "evidence_read" => (json!({"run":run,"include_payloads":{"type":"boolean","default":false},"include_integrity":{"type":"boolean"},
            "select":{"type":"object","additionalProperties":false,"properties":{
                "kind":{"type":"array","maxItems":64,"items":{"type":"string","maxLength":96}},
                "class":{"type":"array","maxItems":16,"items":{"type":"string","maxLength":96}},
                "status":{"type":"array","maxItems":500,"items":{"type":"integer","minimum":100,"maximum":599}},
                "seq":{"type":"array","maxItems":4096,"items":{"type":"integer","minimum":1}}}},
            "offset":{"type":"integer","minimum":0,"maximum":4096,"default":0},
            "limit":{"type":"integer","minimum":1,"maximum":4096,"default":100}}),json!(["run"])),
        "evidence_verdict" => (json!({"run":run,"verdict":{"type":"string","enum":["hypothesis","confirmed","rejected","insufficient_evidence"]},"evidence":{"type":"array","maxItems":256,"items":{"type":"integer","minimum":0}},"note":{"type":"string","maxLength":2048}}),json!(["run","verdict","evidence","note"])),
        _ => return Value::Null,
    };
    let mut result = json!({"type":"object","additionalProperties":false,"properties":properties,"required":required});
    if tool=="recon_discover" { result["properties"]["ports"]["default"] = json!([80,443]); }
    if tool=="recon_resolve" {
        result["oneOf"] = json!([
            {"required":["hosts"],"properties":{"hosts":{"minItems":1}},"not":{"required":["source_run"]}},
            {"required":["source_run"],"properties":{"hosts":{"maxItems":0}}}
        ]);
    }
    if tool=="recon_urls" {
        // Keep the typed object at the root: MCP schema renderers can turn
        // constraint-only allOf branches into `unknown & unknown`.
        result["if"] = json!({"properties":{"mode":{"const":"archive"}}});
        result["then"] = json!({"properties":{"seeds":{"maxItems":0}},
            "not":{"anyOf":[{"required":["resume"]},{"required":["queue"]}]}});
        result["else"] = json!({"required":["mode","seeds"],
            "properties":{"mode":{"enum":["crawl","combined"]},"seeds":{"minItems":1}}});
        result["not"] = json!({"required":["resume","queue"]});
        result["properties"]["resume"]["description"] = json!("Prior crawl/combined receipt; requires the original seeds. Do not combine with queue.");
        result["properties"]["queue"]["description"] = json!("Inline crawl/combined checkpoint; requires matching seeds. Do not combine with resume.");
    }
    result
}

fn parse<T: DeserializeOwned>(input: Value) -> Result<T> {
    serde_json::from_value(input).map_err(|e| format!("invalid typed input: {e}"))
}
struct Complete { result: Value, receipt: Option<Receipt> }
struct Failed { error: String, receipt: Option<Receipt> }
impl From<String> for Failed { fn from(error:String) -> Self { Self{error,receipt:None} } }
impl From<&str> for Failed { fn from(error:&str)->Self { Self::from(error.to_owned()) } }


fn compare_sets(current: &mut Value, baseline: &Value, run: &str, hash: &Value) -> Result<Value> {
    use std::collections::BTreeSet;
    let before: BTreeSet<&str> = baseline["rows"].as_array().ok_or("prior result has no rows")?
        .iter().map(|row|row.as_str().ok_or("set comparison requires string rows")).collect::<std::result::Result<_,_>>()?;
    let rows = current["rows"].as_array().ok_or("current result has no rows")?;
    let after: BTreeSet<&str> = rows.iter().map(|row|row.as_str().ok_or("set comparison requires string rows")).collect::<std::result::Result<_,_>>()?;
    let unchanged = after.intersection(&before).count();
    let new_rows: Vec<Value> = after.difference(&before).map(|row|json!(row)).collect();
    let comparable = current["completeness"]=="complete"
        && current.pointer("/coverage/scope_file_sha256").unwrap_or(&Value::Null)==baseline.pointer("/coverage/scope_file_sha256").unwrap_or(&Value::Null);
    let delta = json!({"baseline_run":run,"baseline_hash":hash,"baseline_total":before.len(),
        "observed_current":after.len(),"new":new_rows.len(),"unchanged":unchanged,
        "gone":if comparable {Some(before.difference(&after).count())}else{None},
        "comparison_complete":comparable,"meaning":"observation-set difference, not live/dead status"});
    current["total"] = json!(new_rows.len());
    current["rows"] = Value::Array(new_rows);
    current["delta"] = delta.clone();
    Ok(delta)
}

fn execute(tool: &str, input: Value) -> std::result::Result<Complete, Failed> {
    if tool=="evidence_read" {
        let request:ReadInput = parse(input)?;
        request.validate()?;
        return Ok(Complete{result:Audit::read(&request)?,receipt:None});
    }
    if tool=="evidence_verdict" {
        let request:VerdictInput = parse(input)?;
        request.validate()?;
        let receipt=Audit::verdict(&request)?;
        return Ok(Complete{result:json!({"verdict":request.verdict,"model_supplied":true}),receipt:Some(receipt)});
    }
    enum Request { Subdomains(SubdomainsInput), Resolve(ResolveInput), Discover(DiscoverInput), Urls(UrlsInput), Surface(SurfaceInput), Ports(PortsInput) }
    let mut request = match tool {
        "recon_subdomains" => { let r:SubdomainsInput=parse(input)?; r.validate()?; Request::Subdomains(r) },
        "recon_resolve" => { let r:ResolveInput=parse(input)?; r.validate()?; Request::Resolve(r) },
        "recon_discover" => { let r:DiscoverInput=parse(input)?; r.validate()?; Request::Discover(r) },
        "recon_urls" => { let r:UrlsInput=parse(input)?; r.validate()?; Request::Urls(r) },
        "recon_surface" => {let r:SurfaceInput=parse(input)?;r.validate()?;Request::Surface(r)},
        "recon_ports" => { let r:PortsInput=parse(input)?; r.validate()?; Request::Ports(r) },
        _ => return Err(format!("unknown workflow {tool}").into()),
    };
    let canonical = match &request {
        Request::Subdomains(r)=>serde_json::to_value(r),Request::Resolve(r)=>serde_json::to_value(r),
        Request::Discover(r)=>serde_json::to_value(r),Request::Urls(r)=>serde_json::to_value(r),Request::Surface(r)=>serde_json::to_value(r),Request::Ports(r)=>serde_json::to_value(r),
    }.map_err(|e|e.to_string())?;
    let since = match &request { Request::Subdomains(r)=>r.since.as_deref(),Request::Urls(r)=>r.since.as_deref(),_=>None };
    let baseline = since.map(|run| -> Result<_> {
        let source=saved::load(run,tool)?;
        source.require_complete()?;
        let previous=&source.request["input"];
        for key in ["domain","mode","seeds"] {
            if previous.get(key)!=canonical.get(key) { return Err(format!("prior {key} differs; observation sets are not comparable")); }
        }
        Ok((run.to_owned(),json!(source.hash),source.payload))
    }).transpose()?;
    let resumed = if let Request::Urls(r)=&mut request {
        if let Some(run)=r.resume.take() {
            let source=saved::load(&run,tool)?;
            let reference=json!({"source_run":run,"source_hash":source.hash});
            let queue:CrawlCheckpoint=serde_json::from_value(source.payload["queue"].clone()).map_err(|e|format!("prior run has no usable crawl checkpoint: {e}"))?;
            queue.validate(&r.seeds)?;
            r.queue=Some(queue);
            r.validate()?;
            Some(reference)
        } else { None }
    } else { None };
    let audit=Audit::start(tool,&canonical)?;
    let outcome = (|| -> Result<(Value,Value)> {
        let policy=policy::Policy::load()?;
        policy.record(&audit)?;
        if let Some(reference)=resumed { audit.record("crawl_resume",reference)?; }
        let mut result = match &request {
            Request::Subdomains(r)=>passive::subdomains(r,&audit),Request::Resolve(r)=>resolve::resolve(r,&audit),
            Request::Discover(r)=>network::discover(r,&audit),Request::Urls(r)=>passive::urls(r,&audit),Request::Ports(r)=>network::ports(r,&audit),
            Request::Surface(r)=>surface::surface(r,&audit),
        }?;
        result.coverage["scope_file_sha256"]=json!(policy.fingerprint());
        let mut payload=result.into_payload(tool);
        audit.record("workflow_result",&payload)?;
        let terminal=json!({"v":2,"tool":tool,"total":payload["total"],"completeness":payload["completeness"],"coverage":payload["coverage"]});
        if let Some((run,hash,previous))=baseline {
            let delta=compare_sets(&mut payload,&previous,&run,&hash)?;
            audit.record("set_comparison",delta)?;
        }
        Ok((payload,terminal))
    })();
    match outcome {
        Ok((result,terminal))=>{
            let receipt = if result["completeness"]=="partial" {
                let error=result.pointer("/partial/error").and_then(Value::as_str).unwrap_or("required backend did not complete");
                audit.abort_with_partial(error,&result["partial"])
            } else { audit.finish(&terminal) };
            receipt.map(|receipt|Complete{result,receipt:Some(receipt)})
                .map_err(|error|Failed{error:format!("evidence completion failed: {error}"),receipt:None})
        },
        Err(error)=>match audit.abort(&error) {
            Ok(receipt)=>Err(Failed{error,receipt:Some(receipt)}),
            Err(audit_error)=>Err(Failed{error:format!("{error}; failure evidence unavailable: {audit_error}"),receipt:None}),
        },
    }
}

pub fn cli(tool: &str) {
    let result=(|| -> std::result::Result<Complete,Failed> {
        let options=crate::Options::parse(&["--all","--schema"],&["--queue-out","--since"])?;
        if options.help() {
            let default_limit=if tool=="recon_surface" {20}else{200};
            println!("{tool}: typed whole-workflow JSON on stdin; --schema prints input schema.\n--limit N (default {default_limit}) bounds rows; --all explicitly emits all rows.\n--since RUN compares subdomain/URL observation sets. recon_urls --queue-out PATH creates a checkpoint export.\nrecon_resolve accepts hosts or source_run; recon_surface reads an existing URL run without target requests.\nResults use v2 rows/total/omitted/completeness; stderr carries the journal receipt.\nExit 0: completed workflow; 3: retained partial output with failure receipt; 2: error.\nOperator scope, private-address and required-header policies remain enforced; no backend flag passthrough.");
            return Ok(Complete{result:Value::Null,receipt:None});
        }
        if !options.inputs.is_empty() { return Err("provide typed JSON on stdin, not positional arguments".to_owned().into()); }
        if options.flag("--schema") { println!("{}",schema(tool)); return Ok(Complete{result:Value::Null,receipt:None}); }
        let requested_limit=options.number("--limit",if tool=="recon_surface" {20}else{200})?;
        let limit=if options.flag("--all") {usize::MAX}else{requested_limit};
        let mut bytes=Vec::new();
        io::stdin().take((MAX_REQUEST+1) as u64).read_to_end(&mut bytes).map_err(|e|e.to_string())?;
        if bytes.len()>MAX_REQUEST { return Err("request exceeds 64 KiB".to_owned().into()); }
        let mut input:Value=serde_json::from_slice(&bytes).map_err(|e|format!("invalid JSON: {e}"))?;
        if let Some(run)=options.value("--since") {
            if !matches!(tool,"recon_subdomains"|"recon_urls") { return Err("--since applies only to subdomain and URL observation sets".to_owned().into()); }
            let object=input.as_object_mut().ok_or("typed input must be an object")?;
            if object.get("since").is_some_and(|v|!v.is_null()) { return Err("provide since once, in JSON or --since".to_owned().into()); }
            object.insert("since".into(),json!(run));
        }
        if tool=="evidence_read" {
            if options.flag("--all") { input["limit"]=json!(4096); }
            else if let Some(limit)=options.value("--limit") { input["limit"]=json!(limit.parse::<usize>().map_err(|_|"--limit requires a nonnegative integer")?); }
        }
        let metadata_only=tool=="evidence_read" && input.get("include_payloads").and_then(Value::as_bool)!=Some(true);
        if options.value("--queue-out").is_some() && tool!="recon_urls" { return Err("--queue-out applies only to recon_urls".to_owned().into()); }
        let mut done=execute(tool,input)?;
        if let Some(path)=options.value("--queue-out") {
            use std::os::unix::fs::OpenOptionsExt;
            if done.result["queue"].is_null() { return Err("this workflow produced no crawl checkpoint".to_owned().into()); }
            let file=std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|e|format!("checkpoint export {path}: {e}"))?;
            let mut out=io::BufWriter::new(file);
            serde_json::to_writer(&mut out,&done.result["queue"]).map_err(|e|format!("checkpoint export: {e}"))?;
            out.write_all(b"\n").and_then(|()|out.flush()).map_err(|e|format!("checkpoint export: {e}"))?;
        }
        done.result=present(done.result,done.receipt.as_ref(),limit,if options.flag("--all"){None}else{Some(MCP_PREVIEW_BYTES)},metadata_only);
        Ok(done)
    })();
    match result {
        Ok(done)=> {
            if done.result.is_null() { return; }
            if let Some(receipt)=&done.receipt {
                let mut receipt=serde_json::to_value(receipt).expect("receipt serializes");
                if let Some(partial)=done.result.get("partial") { receipt["completeness"]=json!("partial");receipt["partial"]=partial.clone(); }
                eprintln!("{receipt}");
            }
            let mut out=io::stdout().lock();
            if let Err(error)=serde_json::to_writer(&mut out,&done.result).map_err(io::Error::other).and_then(|()|out.write_all(b"\n")) {
                eprintln!("{}",json!({"error":format!("stdout: {error}")}));std::process::exit(2);
            }
            if done.result["completeness"]=="partial" { std::process::exit(3); }
        },
        Err(failed)=> {eprintln!("{}",json!({"error":failed.error,"receipt":failed.receipt}));std::process::exit(2);},
    }
}

fn rpc_error(id:Value,code:i64,message:&str)->Value { json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}) }

const MCP_PREVIEW_ROWS: usize = 100;
const MCP_PREVIEW_BYTES: usize = 24 * 1024;

struct SizeBudget { remaining: usize, used: usize }
impl Write for SizeBudget {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining { return Err(io::Error::new(io::ErrorKind::WriteZero, "preview budget exceeded")); }
        self.remaining -= bytes.len();
        self.used += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn bound_rows(mut rows: Vec<Value>, limit: usize, bytes: Option<usize>) -> (Vec<Value>,usize) {
    let total=rows.len();
    if bytes.is_none() { rows.truncate(limit);let omitted=total-rows.len();return (rows,omitted); }
    let mut shown=0;
    let mut remaining=bytes.unwrap_or(usize::MAX).saturating_sub(2);
    for row in rows.iter().take(limit) {
        let mut budget=SizeBudget{remaining,used:0};
        if serde_json::to_writer(&mut budget,row).is_err() {break;}
        remaining=remaining.saturating_sub(budget.used+1);
        shown+=1;
    }
    rows.truncate(shown);
    (rows,total-shown)
}

fn present(mut result:Value,receipt:Option<&Receipt>,limit:usize,bytes:Option<usize>,metadata_only:bool)->Value {
    if let Some(Value::Array(rows))=result.as_object_mut().and_then(|object|object.remove("rows")) {
        let total=rows.len();
        let (rows,omitted)=bound_rows(rows,limit,bytes);
        result["rows"]=Value::Array(rows);
        result["total"]=json!(total);
        result["omitted"]=json!(omitted);
    }
    if let Some(queue)=result.as_object_mut().and_then(|object|object.remove("queue")) {
        result["queue"]=if queue.is_object() {json!({
            "pending":queue["pending"].as_array().map_or(0,Vec::len),
            "visited":queue["visited"].as_array().map_or(0,Vec::len),
            "omitted":queue["omitted"],"scope_sha256":queue["scope_sha256"],
            "resume":receipt.map(|r|r.run.as_str()),"storage":"full checkpoint retained in workflow_result evidence"
        })}else{Value::Null};
    }
    if let Some(Value::Array(events))=result.as_object_mut().and_then(|object|object.remove("events")) {
        let offset=result["offset"].as_u64().unwrap_or(0) as usize;
        let total=result["events_total"].as_u64().unwrap_or(events.len() as u64) as usize;
        let (events,_)=bound_rows(events,limit,if metadata_only{bytes}else{None});
        let next=offset+events.len();
        result["events_omitted"]=json!(total.saturating_sub(events.len()));
        result["next_offset"]=if next<total && next>offset {json!(next)}else{Value::Null};
        result["events"]=Value::Array(events);
    }
    result
}

fn mcp_result(result: Value, receipt: Option<Receipt>, metadata_only: bool) -> Value {
    let limit=if result["tool"]=="recon_surface" {20}else{MCP_PREVIEW_ROWS};
    let mut result=present(result,receipt.as_ref(),limit,Some(MCP_PREVIEW_BYTES),metadata_only);
    if let Some(receipt)=receipt {result["receipt"]=json!(receipt);}
    result
}

fn description(tool:&str)->&str {
    match tool {
        "recon_subdomains"=>"Enumerate passive subdomain observations with bounded v2 rows, explicit completeness and journal receipts.",
        "recon_resolve"=>"Resolve typed hosts and return compact addresses, CNAMEs, explicit observed/unknown outcomes and operator-policy dispositions.",
        "recon_discover"=>"Discover HTTP services/content with operator scope, required research headers and private-address guards.",
        "recon_urls"=>"Discover URLs with mode archive, crawl, or combined. Archive accepts no seeds; crawl/combined require 1-8 HTTP(S) seeds within domain. Supports bounded JavaScript collection and receipt resumption.",
        "recon_surface"=>"Summarize verified saved URL evidence into compact offline route groups; zoom by prefix without rescanning or exporting raw captures.",
        "recon_ports"=>"Check explicit integer TCP ports with operator scope/address guards and honest negative coverage.",
        "evidence_read"=>"Verify the complete journal chain, then filter/page lean observations; payloads and per-event integrity are opt-in.",
        _=>"Append a separately labeled model verdict referencing existing facts; cannot alter evidence.",
    }
}
fn rpc(message:Value)->Option<Value> {
    let id=message.get("id").cloned().unwrap_or(Value::Null);
    if !message.is_object() || message["jsonrpc"]!="2.0" || !message["method"].is_string()
        || !(id.is_null() || id.is_string() || id.is_number()) {
        return Some(rpc_error(Value::Null,-32600,"invalid JSON-RPC request"));
    }
    if message.get("id").is_none() { return None; }
    if message.get("params").is_some_and(|params| !params.is_object()) {
        return Some(rpc_error(id,-32602,"params must be an object"));
    }
    let method=message["method"].as_str().unwrap();
    let result = match method {
        "initialize"=> {
            let requested=message.pointer("/params/protocolVersion").and_then(Value::as_str).unwrap_or("2024-11-05");
            let version=if ["2024-11-05","2025-03-26","2025-06-18","2025-11-25"].contains(&requested) { requested } else { "2024-11-05" };
            json!({"protocolVersion":version,"capabilities":{"tools":{}},"serverInfo":{"name":"recon-workflows","version":env!("CARGO_PKG_VERSION")}})
        },
        "ping"=>json!({}),
        "tools/list"=>json!({"tools":TOOLS.iter().map(|name|json!({"name":name,"description":description(name),"inputSchema":schema(name)})).collect::<Vec<_>>()}),
        "tools/call"=> {
            let Some(name)=message.pointer("/params/name").and_then(Value::as_str) else { return Some(rpc_error(id,-32602,"tool name required")); };
            if !TOOLS.contains(&name) { return Some(rpc_error(id,-32602,"unknown workflow tool")); }
            let input=message.pointer("/params/arguments").cloned().unwrap_or_else(||json!({}));
            let metadata_only = name=="evidence_read" && input.get("include_payloads").and_then(Value::as_bool) != Some(true);
            match execute(name,input) {
                Ok(done)=>{let partial=done.result["completeness"]=="partial";json!({"content":[{"type":"text","text":mcp_result(done.result,done.receipt,metadata_only).to_string()}],"isError":partial})},
                Err(failed)=>json!({"content":[{"type":"text","text":json!({"error":failed.error,"receipt":failed.receipt}).to_string()}],"isError":true}),
            }
        },
        _=>return Some(rpc_error(id,-32601,"method not supported")),
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}

/// Bound memory before deserializing an untrusted MCP frame, draining oversized lines.
fn frame(reader:&mut impl BufRead)->io::Result<Option<std::result::Result<Vec<u8>,()>>> {
    let mut bytes=Vec::new();
    let mut oversized=false;
    loop {
        let available=reader.fill_buf()?;
        if available.is_empty() { return Ok(if bytes.is_empty() && !oversized {None} else {Some(if oversized {Err(())} else {Ok(bytes)})}); }
        let n=available.iter().position(|&b|b==b'\n').map_or(available.len(),|n|n+1);
        let ended=available[n-1]==b'\n';
        if !oversized {
            if bytes.len()+n>MAX_REQUEST { bytes.clear(); oversized=true; }
            else { bytes.extend_from_slice(&available[..n]); }
        }
        reader.consume(n);
        if ended { return Ok(Some(if oversized {Err(())} else {Ok(bytes)})); }
    }
}

pub fn mcp()->Result<()> {
    if std::env::args().skip(1).any(|a|a=="--help" || a=="-h") {
        println!("recon_mcp: MCP stdio server for six typed workflows and two evidence tools, including offline saved-surface mapping. Operator scope/header/address enforcement; no flag passthroughs. Requires systemd-journald.");
        return Ok(());
    }
    if std::env::args().len()!=1 { return Err("recon_mcp accepts no arguments".into()); }
    policy::validate_startup()?;
    let stdin=io::stdin();
    let mut reader=stdin.lock();
    let stdout=io::stdout();
    let mut out=stdout.lock();
    while let Some(input)=frame(&mut reader).map_err(|e|e.to_string())? {
        let reply=match input {
            Err(())=>Some(rpc_error(Value::Null,-32600,"request exceeds 64 KiB")),
            Ok(bytes)=>match serde_json::from_slice(&bytes) {
                Ok(message)=>rpc(message),Err(_)=>Some(rpc_error(Value::Null,-32700,"invalid JSON")),
            },
        };
        if let Some(reply)=reply {
            serde_json::to_writer(&mut out,&reply).map_err(|e|e.to_string())?;
            out.write_all(b"\n").and_then(|()|out.flush()).map_err(|e|e.to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_workflow_previews_bound_bytes_and_account_for_every_omitted_item() {
        let rows: Vec<_> = (0..500).map(|n| json!(format!("https://example.test/{n}/{}", "é".repeat(300)))).collect();
        let response = mcp_result(json!({"v":2,"rows":rows,"total":500,"omitted":0}), None, false);
        let shown = response["rows"].as_array().unwrap();
        assert!(shown.len() < 500);
        assert_eq!(response["total"], 500);
        assert_eq!(response["omitted"].as_u64().unwrap() as usize, 500 - shown.len());
        assert!(serde_json::to_vec(&response["rows"]).unwrap().len() <= MCP_PREVIEW_BYTES);
        for (n, row) in shown.iter().enumerate() {
            assert_eq!(row.as_str().unwrap(), format!("https://example.test/{n}/{}", "é".repeat(300)));
        }
    }

    #[test]
    fn oversized_first_item_is_explicitly_omitted_not_changed_or_reported_as_no_results() {
        let response = mcp_result(json!({"v":2,"rows":["x".repeat(100_000)],"total":1,"omitted":0}), None, false);
        assert_eq!(response["rows"], json!([]));
        assert_eq!(response["total"], 1);
        assert_eq!(response["omitted"], 1);
    }

    #[test]
    fn metadata_preview_keeps_filtered_totals_and_advances_within_filtered_sequence() {
        let events: Vec<_> = (101..=300).map(|seq| json!({"seq":seq,"kind":"http_response","status":404})).collect();
        let full = json!({"status":"complete","hash":"verified-head","events":events,"events_total":500,"events_omitted":300,"offset":100});
        let preview = mcp_result(full,None,true);
        assert_eq!(preview["hash"],"verified-head");
        assert_eq!(preview["events_total"],500);
        assert_eq!(preview["events_omitted"],400);
        assert_eq!(preview["next_offset"],200);
        assert_eq!(preview["events"][0]["seq"],101);
        assert_eq!(preview["events"][99]["seq"],200);
    }

    #[test]
    fn partial_observation_sets_never_assert_gone_records() {
        let mut current=json!({"rows":["b.example.test","c.example.test"],"completeness":"partial","coverage":{}});
        let prior=json!({"rows":["a.example.test","b.example.test"],"coverage":{}});
        let delta=compare_sets(&mut current,&prior,"baseline",&json!("hash")).unwrap();
        assert_eq!(current["rows"],json!(["c.example.test"]));
        assert_eq!(delta["new"],1);
        assert_eq!(delta["unchanged"],1);
        assert!(delta["gone"].is_null());
        assert_eq!(delta["comparison_complete"],false);
    }

    #[test]
    fn complete_sets_compare_identities_and_treat_legacy_unset_policy_as_null() {
        let mut current=json!({"rows":["b.example.test","c.example.test"],"completeness":"complete","coverage":{"scope_file_sha256":null}});
        let prior=json!({"rows":["a.example.test","b.example.test"],"coverage":{}});
        let delta=compare_sets(&mut current,&prior,"baseline",&json!("hash")).unwrap();
        assert_eq!(delta["new"],1);
        assert_eq!(delta["gone"],1);
        assert_eq!(delta["unchanged"],1);
    }

    #[test]
    fn checkpoints_are_not_dumped_into_default_model_responses() {
        let queue=json!({"v":1,"pending":[{"url":"https://example.test/account","origin":"https://example.test","depth":1}],"visited":["https://example.test/"],"omitted":0});
        let receipt=Receipt{run:"a".repeat(32),hash:"b".repeat(64),cursor:"cursor".into(),events:5};
        let response=mcp_result(json!({"v":2,"rows":[],"queue":queue}),Some(receipt),false);
        assert_eq!(response["queue"]["pending"],1);
        assert_eq!(response["queue"]["visited"],1);
        assert_eq!(response["queue"]["resume"],"a".repeat(32));
        assert!(response["queue"].get("url").is_none());
    }
}
