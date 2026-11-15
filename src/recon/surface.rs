//! Offline navigation aids from verified URL receipts, never fresh HTTP evidence.
use super::audit::Audit;
use super::result::WorkflowResult;
use super::saved::{self, SavedWorkflow};
use super::types::{SurfaceInput, WebUrl};
use crate::routes::{self, Candidate, Inventory};
use crate::Result;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const COLUMNS: &[&str] = &[
    "origin", "path", "kind", "families", "candidate_occurrences",
    "captured_statuses", "examples", "evidence_seqs",
];
const SAMPLE_LIMIT: usize = 3;
type FamilyKey = (String, String, Vec<String>);

#[derive(Default)]
struct UrlEvidence {
    in_result: bool,
    navigation: bool,
    asset: bool,
    noise: bool,
    template: bool,
    known_provenance: bool,
    seqs: BTreeSet<u64>,
    statuses: BTreeMap<u16, usize>,
}
impl UrlEvidence {
    fn kind(&self) -> &'static str {
        if self.asset { "static_asset" }
        else if !self.statuses.is_empty() { "observed_live" }
        else if self.navigation { "navigation" }
        else if self.noise { "literal_noise" }
        else if self.template { "template" }
        else { "url_literal" }
    }
}

#[derive(Default)]
struct Evidence {
    seqs: BTreeSet<u64>,
    statuses: BTreeMap<u16, usize>,
    captured_urls: usize,
}
impl Evidence {
    fn merge(&mut self, other: Self) {
        self.seqs.extend(other.seqs);
        for (status, count) in other.statuses { *self.statuses.entry(status).or_default() += count; }
        self.captured_urls += other.captured_urls;
    }
    fn statuses(&self, candidates: u64) -> Value {
        json!({"responses":self.statuses.values().sum::<usize>(),"urls":self.captured_urls,
            "inferred_urls":candidates - self.captured_urls as u64,
            "statuses":self.statuses,"scope":"source_run_historical","current_liveness":"unknown"})
    }
}

struct ViewRow {
    origin: String,
    path: String,
    params: Vec<String>,
    families: usize,
    candidates: u64,
    examples: Vec<Value>,
    examples_total: usize,
    evidence: Evidence,
}
impl ViewRow {
    fn into_row(self, detailed: bool) -> Value {
        let statuses = self.evidence.statuses(self.candidates);
        let seq_total = self.evidence.seqs.len();
        let seqs: Vec<_> = self.evidence.seqs.into_iter().take(SAMPLE_LIMIT).collect();
        json!([self.origin,self.path,if detailed { "route_family" } else { "route_cluster" },
            self.families,self.candidates,statuses,
            bounded(self.examples,self.examples_total),bounded(seqs,seq_total)])
    }
}
fn bounded<T: serde::Serialize>(items: Vec<T>, total: usize) -> Value {
    let omitted = total - items.len();
    json!({"items":items,"total":total,"omitted":omitted})
}

/// Load and verify one complete journal chain. Summarization performs no network work.
pub fn surface(input: &SurfaceInput, audit: &Audit) -> Result<WorkflowResult> {
    input.validate()?;
    let source = saved::load_surface(&input.run)?;
    let result = summarize(input, source)?;
    audit.record("surface_summary", json!({"source_run":input.run,"rows":result.rows.len(),
        "view":result.coverage["view"],"network_requests":0}))?;
    Ok(result)
}

fn url(value: &str, source: &SavedWorkflow) -> Result<String> {
    let url = WebUrl::parse(value)?;
    if !source.domain.contains_host(url.as_url().host_str().unwrap_or("")) {
        return Err("saved surface URL is outside the source domain".into());
    }
    Ok(url.as_str().to_owned())
}
fn identity(url: &WebUrl) -> FamilyKey {
    let mut params: Vec<_> = url.as_url().query_pairs().map(|(name, _)| name.into_owned()).collect();
    params.sort();
    (url.as_url().origin().ascii_serialization(),routes::normalized(url.as_url().path(),false),params)
}
fn cluster(path: &str) -> String {
    // Preserve empty path segments; grouping must not imply HTTP path equivalence.
    let mut parts = path.strip_prefix('/').unwrap_or(path).split('/');
    let first = parts.next().unwrap_or("");
    match parts.next() { Some(second) => format!("/{first}/{second}"), None => format!("/{first}") }
}
fn matches_prefix(path: &str, prefix: &str) -> bool {
    prefix == "/" || path == prefix || path.strip_prefix(prefix).is_some_and(|suffix| suffix.starts_with('/'))
}

// Keep only typed bounds/counts. Source error text and arbitrary coverage values can
// contain complete URLs, query secrets or response content and do not belong here.
fn source_bounds(source: &SavedWorkflow) -> Value {
    let mut crawl = serde_json::Map::new();
    for key in ["max_pages","max_js_assets","max_depth","navigation_metadata_requests","js_asset_requests",
        "attempts","live_responses","explicit_negatives","failed_fetches","queued_not_fetched","queue_limit",
        "queue_omitted","depth_limited_links","candidate_only","policy_excluded","robots_excluded","static_skipped",
        "body_truncated_responses","navigation_metadata_pending","js_asset_pending","invalid_or_off_origin",
        "page_budget_exhausted","asset_budget_exhausted","visited_budget_exhausted","resumed_requests",
        "robots_safety_requests","robots_revalidated_on_resume","robots_safety_unavailable","robots_safety_not_queried",
        "origin_not_queried","exhaustive","discovery_complete","get_only","forms_submitted","redirects_followed"] {
        if let Some(value) = source.payload.pointer(&format!("/coverage/crawl/{key}")) {
            if value.is_number() || value.is_boolean() { crawl.insert(key.into(),value.clone()); }
        }
    }
    let mut archive = serde_json::Map::new();
    for key in ["completed","policy_excluded","accepted","asserted_live","required_stage_failed"] {
        if let Some(value) = source.payload.pointer(&format!("/coverage/archive/{key}")) {
            if value.is_number() || value.is_boolean() { archive.insert(key.into(),value.clone()); }
        }
    }
    let queue = source.payload.get("queue").filter(|queue| queue.is_object()).map(|queue| json!({
        "pending":queue.get("pending").and_then(Value::as_array).map(Vec::len),
        "visited":queue.get("visited").and_then(Value::as_array).map(Vec::len),
        "omitted":queue.get("omitted").and_then(Value::as_u64)}));
    json!({"total":source.payload.get("total").and_then(Value::as_u64),
        "omitted":source.payload.get("omitted").and_then(Value::as_u64),
        "crawl":crawl,"archive":archive,"queue":queue})
}

/// Pure consumer of a decoded receipt. Caller-supplied SavedWorkflow is not journal authentication.
pub fn summarize(input: &SurfaceInput, source: SavedWorkflow) -> Result<WorkflowResult> {
    input.validate()?;
    if input.run != source.run || source.tool != "recon_urls" {
        return Err("surface requires the requested recon_urls receipt".into());
    }
    if let Some(site) = &input.site {
        if !source.domain.contains_host(site.as_str()) { return Err("surface site must narrow the source domain".into()); }
    }
    let rows = source.payload.get("rows").and_then(Value::as_array).ok_or("saved URL receipt lacks rows")?;
    let mut urls = BTreeMap::<String,UrlEvidence>::new();
    for row in rows {
        let value = row.as_str().ok_or("saved URL row must be a string")?;
        let entry = urls.entry(url(value,&source)?).or_default();
        entry.in_result = true;
        entry.seqs.insert(source.result_seq);
    }
    let mut recorded_responses = 0usize;
    let mut discovery_candidates = 0usize;
    for observation in &source.observations {
        match observation.kind.as_str() {
            "crawl_live_response" => {
                let value = observation.data.get("url").and_then(Value::as_str).ok_or("saved response lacks URL")?;
                let status = observation.data.get("status").and_then(Value::as_u64)
                    .filter(|status| (100..=599).contains(status)).ok_or("saved response lacks valid HTTP status")?;
                let entry = urls.entry(url(value,&source)?).or_default();
                entry.seqs.insert(observation.seq);
                entry.known_provenance = true;
                entry.asset |= observation.data.get("kind").and_then(Value::as_str) == Some("asset");
                *entry.statuses.entry(status as u16).or_default() += 1;
                recorded_responses += 1;
            }
            "crawl_link_discovery" => {
                let discovered = observation.data.get("discovered").and_then(Value::as_array)
                    .ok_or("saved link discovery lacks candidates")?;
                for candidate in discovered {
                    let value = candidate.as_str().or_else(||candidate.get("url").and_then(Value::as_str))
                        .ok_or("saved discovery candidate lacks URL")?;
                    let entry = urls.entry(url(value,&source)?).or_default();
                    entry.seqs.insert(observation.seq);
                    discovery_candidates += 1;
                    // Legacy strings are literals, not evidence of HTML navigation.
                    if candidate.is_string() { continue; }
                    let source_kind = candidate.get("source").and_then(Value::as_str).unwrap_or("");
                    let class = candidate.get("class").and_then(Value::as_str).unwrap_or("");
                    entry.navigation |= class == "navigation" && matches!(source_kind,
                        "html_navigation" | "sitemap_location" | "robots_sitemap");
                    entry.asset |= matches!(class,"javascript_asset" | "static_asset_candidate");
                    entry.noise |= class == "literal_noise";
                    entry.template |= class == "template_candidate";
                    entry.known_provenance |= matches!(source_kind,"html_navigation" | "html_link_metadata" |
                        "sitemap_location" | "robots_sitemap" | "inline_script_literal" | "javascript_literal" | "script_src");
                }
            }
            _ => {}
        }
    }
    let candidate_response_overlap = urls.values().filter(|entry|entry.in_result && !entry.statuses.is_empty()).count();
    let unknown_provenance_urls = urls.values().filter(|entry|!entry.known_provenance).count();
    let unique_urls = urls.len();
    let mut inventory = Inventory::default();
    let mut evidence = BTreeMap::<FamilyKey,Evidence>::new();
    let mut filtered_urls = 0usize;
    for (value, entry) in urls {
        let parsed = WebUrl::parse(&value)?;
        if input.site.as_ref().is_some_and(|site|!site.contains_host(parsed.as_url().host_str().unwrap_or(""))) {
            filtered_urls += 1;
            continue;
        }
        inventory.add(Candidate { url:&value,source:json!({"run":source.run,"result_seq":source.result_seq,
            "provenance":if entry.known_provenance { "recorded_source" } else { "unknown_literal" }}),
            kind:entry.kind(),asserted_live:!entry.statuses.is_empty(),count:1,params:None },None,false)?;
        // Explicit asset/noise provenance must not leak into a route family with
        // the same normalized identifier shape.
        if !matches!(entry.kind(), "static_asset" | "literal_noise") {
            let captured_urls = usize::from(!entry.statuses.is_empty());
            evidence.entry(identity(&parsed)).or_default().merge(Evidence { seqs:entry.seqs,statuses:entry.statuses,captured_urls });
        }
    }
    let report = inventory.finish();
    let prefix = input.prefix.as_ref().map(|prefix|routes::normalized(prefix,false));
    let detailed = prefix.is_some();
    let mut groups = BTreeMap::<(String,String),ViewRow>::new();
    let mut details = Vec::new();
    let mut route_families = 0usize;
    let mut route_candidates = 0u64;
    let mut excluded_families = BTreeMap::<&str,usize>::new();
    let mut excluded_candidates = BTreeMap::<&str,u64>::new();
    let mut matched_families = 0usize;
    for family in report.families {
        if family.class != "route" {
            *excluded_families.entry(family.class).or_default() += 1;
            *excluded_candidates.entry(family.class).or_default() += family.count;
            continue;
        }
        route_families += 1;
        route_candidates += family.count;
        if prefix.as_ref().is_some_and(|prefix|!matches_prefix(&family.route,prefix)) { continue; }
        matched_families += 1;
        let key = (family.origin.clone(),family.route.clone(),family.params.clone());
        let family_evidence = evidence.remove(&key).ok_or("route inventory lost source URL identity")?;
        if detailed {
            let examples = family.variants.iter().take(SAMPLE_LIMIT).map(|variant|
                json!({"path":variant["path"],"params":family.params})).collect();
            details.push(ViewRow { origin:family.origin,path:family.route,params:family.params,families:1,candidates:family.count,
                examples,examples_total:family.variants_total,evidence:family_evidence });
        } else {
            let path = cluster(&family.route);
            let group = groups.entry((family.origin.clone(),path.clone())).or_insert_with(||ViewRow {
                origin:family.origin.clone(),path,params:Vec::new(),families:0,candidates:0,examples:Vec::new(),examples_total:0,evidence:Evidence::default() });
            group.families += 1;
            group.candidates += family.count;
            group.examples_total += 1;
            if group.examples.len() < SAMPLE_LIMIT { group.examples.push(json!({"path":family.route,"params":family.params})); }
            group.evidence.merge(family_evidence);
        }
    }
    if !detailed { details.extend(groups.into_values()); }
    details.sort_by(|a,b|b.families.cmp(&a.families).then(b.candidates.cmp(&a.candidates))
        .then(a.origin.cmp(&b.origin)).then(a.path.cmp(&b.path))
        .then(a.params.cmp(&b.params)));
    let view_candidates: u64 = details.iter().map(|row|row.candidates).sum();
    let mut result = WorkflowResult::complete(details.into_iter().map(|row|row.into_row(detailed)).collect());
    result.cols = COLUMNS.to_vec();
    result.coverage = json!({"source":source.metadata(),"source_bounds":source_bounds(&source),
        "view":if detailed { "prefix_families" } else { "first_two_segments" },"prefix":prefix,
        "network_requests":0,"current_liveness":"unknown","captured_status_scope":"source_run_historical",
        "api_operations":"unknown","authentication_states":"unknown","object_graph":"unknown",
        "grouping":"inferred_navigation_aid_not_endpoint_equivalence","exhaustive":false,
        "candidate_count_basis":"distinct_canonical_urls_including_query_values",
        "counts":{"source_rows":rows.len(),"discovery_candidates":discovery_candidates,
            "recorded_responses":recorded_responses,"unique_urls":unique_urls,
            "candidate_response_overlap":candidate_response_overlap,"unknown_provenance_urls":unknown_provenance_urls,
            "site_filtered_urls":filtered_urls,"route_families":route_families,"route_candidates":route_candidates,
            "matched_families":matched_families,"view_rows":result.rows.len(),"view_candidates":view_candidates,
            "excluded_families":excluded_families,"excluded_candidates":excluded_candidates},
        "sample_limit":SAMPLE_LIMIT,"inventory":report.stats,
        "partial_origin":if source.partial.is_some() { Some("source_run") } else { None }});
    result.partial = source.partial;
    Ok(result)
}
