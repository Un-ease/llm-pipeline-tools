use llm_pipeline_tools::{Options, Result, input, main_result, report};
use llm_pipeline_tools::routes::{COLUMNS, Candidate, Inventory, RouteFamily, site_domain};
use serde_json::{Value, json};
use std::io::Read;


fn run() -> Result<()> {
    let options = Options::parse(&["--all", "--keep-locale"], &["--site", "--limit"])?;
    if options.help() {
        println!("bbp-routes [--site DOMAIN] [--keep-locale] [--limit N | --all] FILE...\n\
Offline route families from URL lines, JSON URL arrays, tagged URL candidates, or\n\
bbp-urls reports; - reads stdin. --site is a DNS suffix display filter, not authorization.\n\
Locale prefixes and trailing-slash variants are grouped by default, with original paths retained.\n\
Whole named/template, UUID, long-hex and numeric segments become :param; leaf operations,\n\
origins and query names remain distinct. Static assets and low-confidence literal noise\n\
are separate classes. Each family has at most five variant/provenance samples with totals.\n\
inferred_count and asserted_live_count are counts, not booleans. Input live assertions\n\
are unverified source claims. Query values, userinfo and fragments are not emitted.\n\
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
    let mut reduction = inventory.finish();
    reduction.stats["input_bytes"] = json!(input_bytes);
    report("bbp-routes", COLUMNS, reduction.families.into_iter().map(RouteFamily::into_row),
        options.limit()?, reduction.stats)
}

fn main() { main_result(run); }
