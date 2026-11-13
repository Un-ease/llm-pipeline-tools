use llm_pipeline_tools::{Options, Result, input, main_result, report};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Read;
use url::{Host, Url};

const SAMPLE_LIMIT: usize = 5;
const MAX_URL_BYTES: usize = 8192;

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct Key {
    class: &'static str,
    origin: String,
    route: String,
    params: Vec<String>,
}

#[derive(Default)]
struct Family {
    count: u64,
    inferred: u64,
    asserted_live: u64,
    variants: BTreeMap<String, u64>,
    provenance: BTreeMap<String, (Value, u64)>,
}

#[derive(Default)]
struct Inventory {
    families: BTreeMap<Key, Family>,
    candidates: u64,
    rejected: u64,
    filtered: u64,
    route: u64,
    static_asset: u64,
    noise: u64,
    upstream_omitted: u64,
}

struct Candidate<'a> {
    url: &'a str,
    source: Value,
    kind: &'a str,
    asserted_live: bool,
    count: u64,
    params: Option<Vec<String>>,
}

fn site_domain(value: &str) -> Result<String> {
    let value = value.strip_suffix('.').unwrap_or(value);
    match Host::parse(value) {
        Ok(Host::Domain(domain)) if domain.len() <= 253 && domain.split('.').all(|label|
            !label.is_empty() && label.len() <= 63 && !label.starts_with('-')
                && !label.ends_with('-') && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        ) => Ok(domain),
        _ => Err("--site requires a DNS domain, not a URL or IP address".into()),
    }
}

fn in_site(host: &str, site: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    host == site || host.strip_suffix(site).is_some_and(|prefix| prefix.ends_with('.'))
}

// Only whole segments are placeholders. In particular, change-password and
// delete-account are operations, not generic identifiers or interchangeable leaves.
fn parameter(segment: &str) -> bool {
    let name = segment.strip_prefix("${").and_then(|s| s.strip_suffix('}'))
        .or_else(|| segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')))
        .or_else(|| segment.strip_prefix('[').and_then(|s| s.strip_suffix(']')))
        .or_else(|| segment.strip_prefix('<').and_then(|s| s.strip_suffix('>')))
        .or_else(|| segment.strip_prefix(':'));
    if let Some(name) = name {
        let name = name.strip_prefix("...").unwrap_or(name);
        return !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
    }
    if !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()) { return true; }
    let uuid = segment.len() == 36 && segment.bytes().enumerate().all(|(i, b)| {
        if matches!(i, 8 | 13 | 18 | 23) { b == b'-' } else { b.is_ascii_hexdigit() }
    });
    uuid || (segment.len() >= 16 && segment.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn locale(segment: &str) -> bool {
    let lower = segment.to_ascii_lowercase();
    if matches!(lower.as_str(), ":locale" | ":lang" | ":language" | "{locale}" | "{lang}" | "{language}"
        | "[locale]" | "[lang]" | "[language]" | "${locale}" | "${lang}" | "${language}") { return true; }
    let mut parts = lower.split(['-', '_']);
    let language = parts.next().unwrap_or("");
    let known = matches!(language, "af" | "am" | "ar" | "az" | "be" | "bg" | "bn" | "bs" | "ca" | "cs"
        | "cy" | "da" | "de" | "el" | "en" | "es" | "et" | "eu" | "fa" | "fi" | "fil" | "fr"
        | "ga" | "gl" | "gu" | "he" | "hi" | "hr" | "hu" | "hy" | "id" | "is" | "it" | "ja"
        | "ka" | "kk" | "km" | "kn" | "ko" | "ky" | "lo" | "lt" | "lv" | "mk" | "ml" | "mn"
        | "mr" | "ms" | "mt" | "my" | "nb" | "ne" | "nl" | "nn" | "no" | "pa" | "pl" | "pt"
        | "ro" | "ru" | "si" | "sk" | "sl" | "sq" | "sr" | "sv" | "sw" | "ta" | "te" | "th"
        | "tl" | "tr" | "uk" | "ur" | "uz" | "vi" | "zh" | "zu");
    known && parts.all(|part| {
        ((part.len() == 2 || part.len() == 4) && part.bytes().all(|b| b.is_ascii_alphabetic()))
            || (part.len() == 3 && part.bytes().all(|b| b.is_ascii_digit()))
    })
}

fn decoded_segment(segment: &str) -> String {
    // Decode only template delimiters. Do not turn encoded slashes into segments,
    // lowercase paths, resolve dot segments, or otherwise merge distinct routes.
    let mut decoded = String::with_capacity(segment.len());
    let mut rest = segment;
    while !rest.is_empty() {
        if rest.starts_with('%') && rest.len() >= 3 {
            let code = &rest.as_bytes()[1..3];
            let delimiter = if code.eq_ignore_ascii_case(b"7b") { Some('{') }
                else if code.eq_ignore_ascii_case(b"7d") { Some('}') }
                else if code.eq_ignore_ascii_case(b"5b") { Some('[') }
                else if code.eq_ignore_ascii_case(b"5d") { Some(']') }
                else if code.eq_ignore_ascii_case(b"3c") { Some('<') }
                else if code.eq_ignore_ascii_case(b"3e") { Some('>') }
                else { None };
            if let Some(c) = delimiter { decoded.push(c); rest = &rest[3..]; continue; }
        }
        let c = rest.chars().next().unwrap();
        decoded.push(c);
        rest = &rest[c.len_utf8()..];
    }
    decoded
}

fn normalized(path: &str, keep_locale: bool) -> String {
    let mut segments: Vec<String> = path.split('/').map(decoded_segment).collect();
    if segments.get(1).is_some_and(|s| locale(s)) {
        if keep_locale {
            if parameter(&segments[1]) { segments[1] = ":locale".into(); }
        } else {
            segments.remove(1);
        }
    }
    for segment in &mut segments {
        if parameter(segment) && segment != ":locale" { *segment = ":param".into(); }
    }
    let result = segments.join("/");
    if result.is_empty() { "/".into() } else { result }
}

fn classification(path: &str, kind: &str) -> &'static str {
    if matches!(kind, "noise" | "literal_noise") { return "noise"; }
    if matches!(kind, "asset" | "static_asset") { return "static_asset"; }
    let lower = path.to_ascii_lowercase();
    if lower.split('/').any(|segment| matches!(segment, "undefined" | "null" | "[object object]"))
        || path.contains(['\n', '\r', '\t']) || path.contains("'+") || path.contains("\"+")
    { return "noise"; }
    let leaf = lower.rsplit('/').next().unwrap_or("");
    let extension = leaf.rsplit_once('.').map(|(_, extension)| extension).unwrap_or("");
    if matches!(extension, "js" | "mjs" | "cjs" | "css" | "map" | "png" | "jpg" | "jpeg" | "gif"
        | "webp" | "avif" | "svg" | "ico" | "woff" | "woff2" | "ttf" | "otf" | "eot" | "mp4"
        | "webm" | "mp3" | "wav") { "static_asset" } else { "route" }
}

impl Inventory {
    fn add(&mut self, candidate: Candidate<'_>, site: Option<&str>, keep_locale: bool) -> Result<()> {
        self.candidates = self.candidates.checked_add(candidate.count).ok_or("observation count overflow")?;
        let text = candidate.url;
        if text.len() > MAX_URL_BYTES || text.contains('\\') {
            self.rejected += candidate.count;
            return Ok(());
        }
        let Some(authority) = text.find("://").map(|start| start + 3) else {
            self.rejected += candidate.count;
            return Ok(());
        };
        let Ok(url) = Url::parse(text) else { self.rejected += candidate.count; return Ok(()); };
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            self.rejected += candidate.count;
            return Ok(());
        }
        if site.is_some_and(|site| !in_site(url.host_str().unwrap(), site)) {
            self.filtered += candidate.count;
            return Ok(());
        }
        let suffix = &text[authority..];
        let start = suffix.find(['/', '?', '#']).unwrap_or(suffix.len());
        let remainder = &suffix[start..];
        let path = if remainder.starts_with('/') {
            &remainder[..remainder.find(['?', '#']).unwrap_or(remainder.len())]
        } else { "/" };
        let mut params = candidate.params.unwrap_or_else(|| url.query_pairs().map(|(name, _)| name.into_owned()).collect());
        params.sort();
        let class = classification(path, candidate.kind);
        match class {
            "static_asset" => self.static_asset += candidate.count,
            "noise" => self.noise += candidate.count,
            _ => self.route += candidate.count,
        }
        let key = Key { class, origin: url.origin().ascii_serialization(), route: normalized(path, keep_locale), params };
        let family = self.families.entry(key).or_default();
        family.count += candidate.count;
        if candidate.asserted_live { family.asserted_live += candidate.count; } else { family.inferred += candidate.count; }
        *family.variants.entry(path.to_owned()).or_default() += candidate.count;
        let provenance = json!({"source": candidate.source, "kind": candidate.kind,
            "asserted_live": candidate.asserted_live});
        let identity = serde_json::to_string(&provenance).map_err(|e| e.to_string())?;
        family.provenance.entry(identity).and_modify(|(_, count)| *count += candidate.count)
            .or_insert((provenance, candidate.count));
        Ok(())
    }

    fn json(&mut self, value: &Value, source: &str, record: usize, pointer: &str, site: Option<&str>, keep_locale: bool) -> Result<()> {
        match value {
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    self.json(value, source, record, &format!("{pointer}/{index}"), site, keep_locale)?;
                }
                Ok(())
            }
            Value::String(url) => self.add(Candidate { url, source: json!({"file":source,"record":record,"pointer":pointer}),
                kind: "url_literal", asserted_live: false, count: 1, params: None }, site, keep_locale),
            Value::Object(object) if object.get("tool").and_then(Value::as_str) == Some("bbp-urls") => {
                self.url_report(value, source, site, keep_locale)
            }
            Value::Object(object) => {
                let url = object.get("url").and_then(Value::as_str).ok_or("candidate requires a string url")?;
                let kind = match object.get("kind") {
                    Some(value) => value.as_str().ok_or("candidate kind must be a string")?,
                    None => "candidate",
                };
                let asserted_live = match object.get("asserted_live") {
                    Some(value) => value.as_bool().ok_or("candidate asserted_live must be boolean")?,
                    None => kind == "observed_live",
                };
                let mut provenance = json!({"file":source,"record":record,"pointer":pointer});
                if let Some(tag) = object.get("source") { provenance["tag"] = tag.clone(); }
                if let Some(confidence) = object.get("confidence") { provenance["confidence"] = confidence.clone(); }
                self.add(Candidate { url, source: provenance, kind, asserted_live, count: 1, params: None }, site, keep_locale)
            }
            _ => Err("expected URLs, tagged URL candidates, or a bbp-urls report".into()),
        }
    }

    fn url_report(&mut self, value: &Value, source: &str, site: Option<&str>, keep_locale: bool) -> Result<()> {
        let invalid = || "malformed bbp-urls report".to_owned();
        let cols = value["cols"].as_array().ok_or_else(invalid)?;
        let rows = value["rows"].as_array().ok_or_else(invalid)?;
        let omitted = value["omitted"].as_u64().ok_or_else(invalid)?;
        let total = value["total"].as_u64().ok_or_else(invalid)?;
        if value["v"] != 1 || total.checked_sub(omitted) != Some(rows.len() as u64) { return Err(invalid()); }
        self.upstream_omitted = self.upstream_omitted.checked_add(omitted).ok_or("omitted count overflow")?;
        let required = ["scheme", "host", "port", "path", "params", "count", "source", "line", "byte"];
        let positions: Vec<usize> = required.iter().map(|name| {
            let found: Vec<_> = cols.iter().enumerate().filter(|(_, c)| c.as_str() == Some(*name)).map(|(n, _)| n).collect();
            if found.len() == 1 { Ok(found[0]) } else { Err(invalid()) }
        }).collect::<Result<_>>()?;
        for row in rows {
            let row = row.as_array().filter(|r| r.len() == cols.len()).ok_or_else(invalid)?;
            let get = |n: usize| &row[positions[n]];
            let scheme = get(0).as_str().filter(|s| matches!(*s, "http" | "https")).ok_or_else(invalid)?;
            let host = get(1).as_str().ok_or_else(invalid)?;
            let parsed_host = Host::parse(host).map_err(|_| invalid())?;
            if parsed_host.to_string() != host { return Err(invalid()); }
            let port = if get(2).is_null() { String::new() } else {
                let port = get(2).as_u64().and_then(|n| u16::try_from(n).ok()).ok_or_else(invalid)?;
                format!(":{port}")
            };
            let path = get(3).as_str().filter(|p| p.starts_with('/') && !p.contains(['?', '#', '\\'])).ok_or_else(invalid)?;
            let params = get(4).as_array().ok_or_else(invalid)?.iter()
                .map(|p| p.as_str().map(str::to_owned).ok_or_else(invalid)).collect::<Result<Vec<_>>>()?;
            let count = get(5).as_u64().filter(|n| *n > 0).ok_or_else(invalid)?;
            if !get(6).is_string() || !get(7).as_u64().is_some_and(|n| n > 0) || get(8).as_u64().is_none() { return Err(invalid()); }
            let url = format!("{scheme}://{host}{port}{path}");
            self.add(Candidate { url: &url,
                source: json!({"file":source,"source":get(6),"line":get(7),"byte":get(8)}),
                kind: "url_inventory", asserted_live: false, count, params: Some(params) }, site, keep_locale)?;
        }
        Ok(())
    }
}

fn run() -> Result<()> {
    let options = Options::parse(&["--all", "--keep-locale"], &["--site", "--limit"])?;
    if options.help() {
        println!("bbp-routes [--site DOMAIN] [--keep-locale] [--limit N | --all] FILE...\n\
Offline route families from URL lines, JSON URL arrays, tagged URL candidates, or\n\
bbp-urls reports; - reads stdin. --site is a DNS suffix display filter, not authorization.\n\
Locale prefixes are removed by default. Whole named/template, UUID, long-hex and\n\
numeric segments become :param; static leaf operations, origins and query names remain distinct.\n\
Static assets and literal noise are separate classes, with observation counts in stats.\n\
Each family has at most five path variants and five provenance samples, with totals/omissions.\n\
Query values, userinfo and fragments are not emitted. All routes are inferred unless\n\
input tags asserted_live:true or kind:observed_live; these are source assertions, not verification.\n\
No network requests are made. JSON reports disclose upstream omitted rows.");
        return Ok(());
    }
    options.require_inputs()?;
    let site = options.value("--site").map(site_domain).transpose()?;
    let mut inventory = Inventory::default();
    let mut input_bytes = 0;
    for source in &options.inputs {
        let mut text = String::new();
        input(source)?.read_to_string(&mut text).map_err(|_| format!("{source}: input must be readable UTF-8"))?;
        input_bytes += text.len();
        let trimmed = text.trim_start();
        if trimmed.starts_with(['[', '{', '"']) {
            let stream = serde_json::Deserializer::from_str(&text).into_iter::<Value>();
            for (index, value) in stream.enumerate() {
                let value = value.map_err(|e| format!("{source}: invalid JSON: {e}"))?;
                inventory.json(&value, source, index + 1, "", site.as_deref(), options.flag("--keep-locale"))?;
            }
        } else {
            let mut offset = 0;
            for (index, line) in text.split_inclusive('\n').enumerate() {
                let url = line.trim();
                if !url.is_empty() {
                    let byte = offset + line.len() - line.trim_start().len();
                    inventory.add(Candidate { url, source: json!({"file":source,"line":index+1,"byte":byte}),
                        kind: "url_literal", asserted_live: false, count: 1, params: None }, site.as_deref(), options.flag("--keep-locale"))?;
                }
                offset += line.len();
            }
        }
    }
    let mut class_families = BTreeMap::<&str, usize>::new();
    for key in inventory.families.keys() { *class_families.entry(key.class).or_default() += 1; }
    let rows: Vec<Value> = inventory.families.into_iter().map(|(key, family)| {
        let variants_total = family.variants.len();
        let provenance_total = family.provenance.len();
        let variants: Vec<_> = family.variants.into_iter().take(SAMPLE_LIMIT)
            .map(|(path, count)| json!({"path":path,"count":count})).collect();
        let provenance: Vec<_> = family.provenance.into_values().take(SAMPLE_LIMIT)
            .map(|(mut source, count)| { source["count"] = json!(count); source }).collect();
        json!([key.class, key.origin, key.route, key.params, family.count, family.inferred, family.asserted_live,
            variants, variants_total, variants_total.saturating_sub(SAMPLE_LIMIT),
            provenance, provenance_total, provenance_total.saturating_sub(SAMPLE_LIMIT)])
    }).collect();
    report("bbp-routes", &["class", "origin", "route", "params", "count", "inferred", "asserted_live",
        "variants", "variants_total", "variants_omitted", "provenance", "provenance_total", "provenance_omitted"],
        rows, options.limit()?, json!({"input_bytes":input_bytes,"candidates":inventory.candidates,
            "rejected":inventory.rejected,"filtered":inventory.filtered,"route":inventory.route,
            "static_asset":inventory.static_asset,"noise":inventory.noise,"class_families":class_families,
            "upstream_omitted":inventory.upstream_omitted,"sample_limit":SAMPLE_LIMIT,
            "live_assertions_verified":false}))
}

fn main() { main_result(run); }
