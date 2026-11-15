use super::audit::Audit;
use super::passive::{self, BackendInput};
use super::policy::Policy;
use super::result::{PartialInfo, WorkflowResult};
use super::saved::{self, SavedWorkflow};
use super::types::{Host, ResolveInput};
use crate::Result;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct Resolution {
    pub ips: Vec<IpAddr>,
    pub cnames: Vec<String>,
    pub status: String,
}
impl Resolution {
    fn row(&self, host: &str, policy: &Policy) -> Value {
        let a = self.ips.iter().filter(|ip| ip.is_ipv4()).map(|ip| Value::String(ip.to_string())).collect();
        let aaaa = self.ips.iter().filter(|ip| ip.is_ipv6()).map(|ip| Value::String(ip.to_string())).collect();
        let cname = self.cnames.iter().map(|name| Value::String(name.clone())).collect();
        Value::Array(vec![Value::String(host.into()), Value::Array(a), Value::Array(aaaa),
            Value::Array(cname), Value::String(self.status.clone()),
            Value::String(policy.disposition(host,&self.ips,&self.cnames).into())])
    }
}
fn strings(value: &Value, name: &str) -> Result<Vec<String>> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values.iter().map(|value| value.as_str().map(str::to_owned).ok_or_else(|| format!("dnsx {name} must contain strings"))).collect(),
        _ => Err(format!("dnsx {name} must be an array")),
    }
}
fn status(value: &Value, has_records: bool) -> Result<String> {
    if value.get("error").is_some_and(|value| !value.is_null() && value != "") { return Ok("error".into()); }
    let rcode = value.get("status_code").or_else(|| value.get("rcode")).or_else(|| value.get("status"));
    let code = match rcode {
        Some(Value::String(code)) => code.to_ascii_uppercase(),
        Some(Value::Number(code)) => match code.as_u64() { Some(0) => "NOERROR".into(), Some(3) => "NXDOMAIN".into(), Some(2) => "SERVFAIL".into(), Some(5) => "REFUSED".into(), _ => format!("RCODE_{code}") },
        None if has_records => "NOERROR".into(),
        _ => return Err("dnsx record lacks a valid observed status or records".into()),
    };
    Ok(match code.as_str() {
        "NOERROR" | "SUCCESS" | "0" => if has_records { "resolved".into() } else { "nodata".into() },
        "NXDOMAIN" | "3" => "nxdomain".into(),
        "NODATA" => "nodata".into(),
        "SERVFAIL" | "REFUSED" | "FORMERR" | "NOTIMP" | "TIMEOUT" | "ERROR" => code.to_ascii_lowercase(),
        _ => return Err(format!("unrecognized dnsx status {code}")),
    })
}
fn parse(bytes: &[u8], requested: &BTreeSet<String>) -> Result<BTreeMap<String, Resolution>> {
    let text = std::str::from_utf8(bytes).map_err(|_| "dnsx output is not UTF-8")?;
    let mut observed = BTreeMap::<String, Resolution>::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let value: Value = serde_json::from_str(line).map_err(|error| format!("malformed dnsx JSON record: {error}"))?;
        let host = Host::parse(value.get("host").and_then(Value::as_str).ok_or("dnsx record lacks host")?)?;
        if !requested.contains(host.as_str()) { return Err("dnsx returned an unrequested host".into()); }
        let mut ips = Vec::new();
        for (key, ipv4) in [("a",true),("aaaa",false)] {
            for address in strings(&value,key)? {
                let address: IpAddr = address.parse().map_err(|_| format!("invalid dnsx {key} address"))?;
                if address.is_ipv4() != ipv4 { return Err(format!("wrong address family in dnsx {key}")); }
                ips.push(address);
            }
        }
        let cnames: Vec<String> = strings(&value,"cname")?.into_iter().map(|name| {
            let name = Host::parse(&name)?;
            if name.as_str().parse::<IpAddr>().is_ok() { return Err("invalid IP in dnsx CNAME".into()); }
            Ok(name.as_str().to_owned())
        }).collect::<Result<_>>()?;
        let status = status(&value,!ips.is_empty() || !cnames.is_empty())?;
        if matches!(status.as_str(),"nxdomain" | "nodata") && (!ips.is_empty() || !cnames.is_empty()) {
            return Err("dnsx negative record contradicts observed answers".into());
        }
        let entry = observed.entry(host.as_str().to_owned()).or_insert_with(|| Resolution { ips:Vec::new(),cnames:Vec::new(),status:status.clone() });
        if entry.status != status { return Err("conflicting dnsx statuses for one host".into()); }
        entry.ips.extend(ips);
        entry.ips.sort(); entry.ips.dedup();
        entry.cnames.extend(cnames);
        entry.cnames.sort(); entry.cnames.dedup();
    }
    Ok(observed)
}
fn dns_failure(observed: &BTreeMap<String,Resolution>, bytes: usize) -> Option<PartialInfo> {
    let errors: Vec<_> = observed.iter().filter(|(_,resolution)| !matches!(resolution.status.as_str(),"resolved" | "nxdomain" | "nodata"))
        .map(|(host,resolution)| format!("{host}: {}",resolution.status)).collect();
    if errors.is_empty() { return None; }
    Some(PartialInfo { error:format!("DNS failures: {}",errors.join("; ")),cutoff_reason:"dns_error".into(),
        captured_bytes:bytes,parsed_bytes:bytes,discarded_tail_bytes:0,backend_exit:Some(0),backend_signal:None })
}
fn query(hosts: &[Host], audit: &Audit) -> Result<(BTreeMap<String,Resolution>, Option<PartialInfo>)> {
    let requested = hosts.iter().map(|host| host.as_str().to_owned()).collect();
    audit.record("dns_resolution_intent",json!({"hosts":hosts,"source":"dnsx","http_liveness":false,"ownership_asserted":false}))?;
    let output = passive::command_output(BackendInput::Resolve(hosts),audit)?;
    let observed = parse(&output.stdout,&requested)?;
    if output.partial.is_some() && observed.is_empty() { return Err("interrupted dnsx produced no usable observations".into()); }
    for (host, resolution) in &observed {
        audit.record("dns_resolution",json!({"host":host,"ips":resolution.ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "cname":resolution.cnames,"status":resolution.status,"source":"dnsx","http_liveness":false,"ownership_asserted":false}))?;
    }
    let partial = output.partial.or_else(|| dns_failure(&observed,output.stdout.len()));
    Ok((observed,partial))
}
/// A fresh backend observation, not a caller-provided resolution row. Never use partial DNS to authorize contact.
#[doc(hidden)]
pub fn lookup(host: &str, policy: &Policy, audit: &Audit) -> Result<Resolution> {
    policy.check_host(host)?;
    let host = Host::parse(host)?;
    let (mut rows, partial) = query(std::slice::from_ref(&host),audit)?;
    if let Some(partial) = partial { return Err(partial.error); }
    let resolution = rows.remove(host.as_str()).ok_or("DNS resolution was not observed")?;
    if !matches!(resolution.status.as_str(),"resolved" | "nxdomain" | "nodata") {
        return Err(format!("DNS resolution failed: {}",resolution.status));
    }
    policy.check_resolution(host.as_str(),&resolution.ips,&resolution.cnames)?;
    Ok(resolution)
}
pub fn resolve(input: &ResolveInput, audit: &Audit) -> Result<WorkflowResult> {
    input.validate()?;
    let policy = Policy::load()?;
    policy.check_network()?;
    policy.record(audit)?;
    let (rows,queried,source_metadata) = if let Some(run) = &input.source_run {
        let (expanded,metadata) = source_input(input,saved::load(run,"recon_subdomains")?)?;
        audit.record("workflow_source",&metadata)?;
        let (rows,queried)=prepare(expanded.hosts,&policy);
        (rows,queried,Some(metadata))
    } else {
        let (rows,queried)=prepare(input.hosts.iter().cloned(),&policy);
        (rows,queried,None)
    };
    let (observed, partial) = if queried.is_empty() { (BTreeMap::new(),None) } else { query(&queried,audit)? };
    let mut result=assemble(rows,&queried,observed,partial,&policy)?;
    if let Some(metadata)=source_metadata {result.coverage["source"]=metadata;}
    Ok(result)
}
fn source_input(input:&ResolveInput,source:SavedWorkflow)->Result<(ResolveInput,Value)> {
    source.require_complete()?;
    if source.tool!="recon_subdomains" || input.source_run.as_deref()!=Some(source.run.as_str()) {
        return Err("resolution source must be the requested subdomain workflow".into());
    }
    if input.domain.as_ref().is_some_and(|domain|domain.as_str()!=source.domain.as_str()) {
        return Err("requested domain differs from the recorded subdomain domain".into());
    }
    let rows=source.payload["rows"].as_array().ok_or("recorded subdomain result has no rows")?;
    if rows.is_empty() || rows.len()>512 {return Err("recorded subdomain input requires 1..512 hosts; choose a bounded source run".into());}
    let hosts=rows.iter().map(|row|row.as_str().ok_or_else(||"recorded host row is not a string".to_owned()).and_then(Host::parse)).collect::<Result<Vec<_>>>()?;
    let metadata=source.metadata();
    let expanded=ResolveInput{hosts,domain:Some(source.domain),source_run:None};
    expanded.validate()?;
    Ok((expanded,metadata))
}

fn prepare(hosts:impl IntoIterator<Item=Host>, policy: &Policy) -> (BTreeMap<String,Value>,Vec<Host>) {
    let mut requested = BTreeMap::new();
    let mut queried = Vec::new();
    let mut rows = BTreeMap::new();
    for host in hosts {
        if requested.insert(host.as_str().to_owned(),()).is_some() { continue; }
        if !policy.permits_host(host.as_str()) {
            rows.insert(host.as_str().to_owned(),json!([host,[],[],[],"not_queried","blocked_host"]));
        } else if let Ok(ip) = host.as_str().parse::<IpAddr>() {
            rows.insert(host.as_str().to_owned(),Resolution { ips:vec![ip],cnames:Vec::new(),status:"ip_literal".into() }.row(host.as_str(),&policy));
        } else { queried.push(host); }
    }
    (rows,queried)
}
fn assemble(mut rows: BTreeMap<String,Value>, queried: &[Host], observed: BTreeMap<String,Resolution>, partial: Option<PartialInfo>, policy: &Policy) -> Result<WorkflowResult> {
    let observed_count = observed.len();
    for host in queried {
        rows.insert(host.as_str().to_owned(),match observed.get(host.as_str()) {
            Some(resolution) => resolution.row(host.as_str(),policy),
            None => json!([host,[],[],[],"not_observed","unknown"]),
        });
    }
    let statuses = rows.values().fold(BTreeMap::<String,usize>::new(),|mut counts,row| { *counts.entry(row[4].as_str().expect("fixed DNS status column").to_owned()).or_default() += 1; counts });
    let mut result = WorkflowResult::complete(rows.into_values().collect());
    result.cols = vec!["host","a","aaaa","cname","status","disposition"];
    result.coverage = json!({"requested_unique":result.rows.len(),"queried":queried.len(),"observed_dns":observed_count,
        "not_queried":statuses.get("not_queried").copied().unwrap_or(0),"ip_literals":statuses.get("ip_literal").copied().unwrap_or(0),
        "not_observed":queried.len()-observed_count,"statuses":statuses,"backend_complete":partial.as_ref().is_none_or(|partial| partial.cutoff_reason == "dns_error"),
        "http_liveness":false,"ownership_asserted":false});
    result.partial = partial;
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Policy { Policy::from_json(br#"{"v":1,"in_scope":{"suffixes":["example.test"]},"provider_cname_denylist":["provider.test"]}"#).unwrap() }
    fn hosts() -> Vec<Host> { ["a.example.test","b.example.test","c.example.test"].iter().map(|host| Host::parse(host).unwrap()).collect() }
    fn project(bytes: &[u8], partial: Option<PartialInfo>) -> WorkflowResult {
        let hosts = hosts();
        let observed = parse(bytes,&hosts.iter().map(|host| host.as_str().to_owned()).collect()).unwrap();
        let partial = partial.or_else(|| dns_failure(&observed,bytes.len()));
        assemble(BTreeMap::new(),&hosts,observed,partial,&policy()).unwrap()
    }
    #[test]
    fn silent_success_is_not_fabricated_negative_dns() {
        let result = project(b"",None);
        assert!(result.rows.iter().all(|row| row[4] == "not_observed"));
        assert_eq!(result.coverage["not_observed"],3);
        assert_eq!(result.coverage["observed_dns"],0);
    }
    #[test]
    fn explicit_negatives_and_silent_absence_remain_distinct() {
        let result = project(b"{\"host\":\"a.example.test\",\"status_code\":\"NXDOMAIN\"}\n{\"host\":\"b.example.test\",\"status_code\":\"NOERROR\"}\n",None);
        assert_eq!(result.rows[0][4],"nxdomain");
        assert_eq!(result.rows[1][4],"nodata");
        assert_eq!(result.rows[2][4],"not_observed");
        assert_eq!(result.coverage["observed_dns"],2);
        assert_eq!(result.coverage["not_observed"],1);
        assert!(result.partial.is_none());
    }
    #[test]
    fn positive_answers_keep_all_addresses_and_provider_disposition() {
        let result = project(b"{\"host\":\"a.example.test\",\"a\":[\"8.8.8.8\",\"1.1.1.1\"],\"aaaa\":[\"2606:4700:4700::1111\"],\"cname\":[\"tenant.provider.test\"],\"status_code\":\"NOERROR\"}\n",None);
        assert_eq!(result.rows[0][1],json!(["1.1.1.1","8.8.8.8"]));
        assert_eq!(result.rows[0][2],json!(["2606:4700:4700::1111"]));
        assert_eq!(result.rows[0][5],"blocked_cname");
        assert_eq!(result.rows[0][4],"resolved");
    }
    #[test]
    fn interrupted_results_keep_observations_and_unobserved_hosts() {
        let partial = PartialInfo { error:"dnsx interrupted".into(),cutoff_reason:"timeout".into(),captured_bytes:100,parsed_bytes:50,
            discarded_tail_bytes:50,backend_exit:None,backend_signal:Some(9) };
        let result = project(b"{\"host\":\"a.example.test\",\"status_code\":\"NXDOMAIN\"}\n",Some(partial));
        assert_eq!(result.rows.len(),3);
        assert_eq!(result.rows[0][4],"nxdomain");
        assert_eq!(result.rows[1][4],"not_observed");
        assert_eq!(result.partial.unwrap().cutoff_reason,"timeout");
        assert_eq!(result.coverage["backend_complete"],false);
    }
    #[test]
    fn dns_operational_errors_are_observed_but_not_complete_success() {
        let result = project(b"{\"host\":\"a.example.test\",\"status_code\":\"SERVFAIL\"}\n{\"host\":\"b.example.test\",\"error\":\"timeout\"}\n",None);
        assert_eq!(result.rows[0][4],"servfail");
        assert_eq!(result.rows[1][4],"error");
        assert_eq!(result.rows[2][4],"not_observed");
        assert_eq!(result.partial.unwrap().cutoff_reason,"dns_error");
    }
    #[test]
    fn policy_blocked_inputs_never_enter_the_backend_host_list() {
        let input = ResolveInput { hosts:vec![Host::parse("a.example.test").unwrap(),Host::parse("elsewhere.test").unwrap(),Host::parse("a.example.test").unwrap()],domain:None,source_run:None };
        let (rows,queried) = prepare(input.hosts,&policy());
        assert_eq!(rows["elsewhere.test"][4],"not_queried");
        assert_eq!(queried.len(),1);
        assert_eq!(queried[0].as_str(),"a.example.test");
    }
    #[test]
    fn malformed_or_unrequested_complete_records_are_errors() {
        let requested = hosts().iter().map(|host| host.as_str().to_owned()).collect();
        for bytes in [
            b"{\"host\":\"a.example.test\"}\n".as_slice(),
            b"{\"host\":\"elsewhere.test\",\"status_code\":\"NXDOMAIN\"}\n",
            b"{\"host\":\"a.example.test\",\"a\":[\"127.0.0.1\"],\"status_code\":\"NXDOMAIN\"}\n",
            b"{\"host\":\"a.example.test\",\"aaaa\":[\"1.1.1.1\"]}\n",
            b"{\"host\":\"a.example.test\",\"status_code\":\"UNKNOWN\"}\n",
            b"{\"host\":\"a.example.test\",\"a\":\"1.1.1.1\"}\n",
            b"not JSON\n",
        ] { assert!(parse(bytes,&requested).is_err()); }
    }

    fn saved_names(count:usize)->SavedWorkflow {
        let domain=super::super::types::Domain::parse("example.test").unwrap();
        let rows:Vec<Value>=(0..count).map(|n|json!(format!("n{n}.example.test"))).collect();
        SavedWorkflow {run:"a".repeat(32),hash:"b".repeat(64),cursor:"fixture".into(),
            tool:"recon_subdomains".into(),status:"complete".into(),completeness:"complete".into(),
            domain,request:json!({"tool":"recon_subdomains","input":{"domain":"example.test"},"source":"typed_tool_request"}),
            payload:json!({"rows":rows}),result_seq:2,observations:Vec::new(),partial:None}
    }

    fn receipt_input()->ResolveInput {
        ResolveInput{hosts:Vec::new(),domain:None,source_run:Some("a".repeat(32))}
    }

    #[test]
    fn source_expansion_uses_the_complete_snapshot_not_a_preview() {
        let (expanded,metadata)=source_input(&receipt_input(),saved_names(314)).unwrap();
        assert_eq!(expanded.hosts.len(),314);
        assert_eq!(expanded.hosts[313].as_str(),"n313.example.test");
        assert_eq!(expanded.domain.unwrap().as_str(),"example.test");
        assert!(expanded.source_run.is_none());
        assert_eq!(metadata["source_run"],"a".repeat(32));
    }

    #[test]
    fn source_selection_rejects_partial_mismatched_or_oversized_inputs() {
        let mut partial=saved_names(1);
        partial.status="failure".into();
        partial.completeness="partial".into();
        assert!(source_input(&receipt_input(),partial).is_err());
        for count in [0,513] { assert!(source_input(&receipt_input(),saved_names(count)).is_err()); }
        let mut other_domain=receipt_input();
        other_domain.domain=Some(super::super::types::Domain::parse("other.test").unwrap());
        assert!(source_input(&other_domain,saved_names(1)).is_err());
        let mut other_run=receipt_input();
        other_run.source_run=Some("c".repeat(32));
        assert!(source_input(&other_run,saved_names(1)).is_err());
    }
}
