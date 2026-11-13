use llm_pipeline_tools::{Options, Result, input, main_result, report};
use regex::bytes::Regex;
use serde_json::{Value, json};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use url::{Host, Url};

const MAX_LITERAL_BYTES: usize = 8192;

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct Key {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
    params: Vec<String>,
}

struct Occurrences {
    count: usize,
    source: String,
    line: usize,
    byte: usize,
}

#[derive(Default)]
struct Stats {
    input_bytes: usize,
    lines: usize,
    candidates: usize,
    rejected: usize,
    overlong: usize,
    filtered: usize,
    occurrences: usize,
    ignored_lines: usize,
}

// Sentence punctuation is a boundary heuristic, not a JavaScript parser. Keep
// semicolons and balanced URL parentheses/brackets, which can be meaningful.
fn literal_end(bytes: &[u8]) -> usize {
    let mut end = bytes.len();
    loop {
        match bytes.get(end.wrapping_sub(1)) {
            Some(b'.' | b',') => end -= 1,
            Some(&close @ (b')' | b']' | b'}')) => {
                let open = match close { b')' => b'(', b']' => b'[', _ => b'{' };
                let opens = bytes[..end].iter().filter(|&&b| b == open).count();
                let closes = bytes[..end].iter().filter(|&&b| b == close).count();
                if closes > opens { end -= 1; } else { break; }
            }
            _ => break,
        }
    }
    end
}

fn key(literal: &[u8], bare: bool) -> Option<Key> {
    let text = std::str::from_utf8(literal).ok()?;
    let normalized = if bare {
        Cow::Owned(format!("https://{text}"))
    } else if text.contains("\\/") {
        Cow::Owned(text.replace("\\/", "/"))
    } else {
        Cow::Borrowed(text)
    };
    // Unescaped backslashes are not literal URL separators. URL's forgiving
    // browser parser would otherwise silently change their authority/path role.
    if normalized.contains('\\') { return None; }
    let parsed = Url::parse(&normalized).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") { return None; }
    let host = parsed.host_str()?.to_owned();
    // Url normalizes dot segments and some path spellings. Validate with it,
    // but deliberately extract the path from the literal, not Url::path().
    let authority = normalized.find("://")? + 3;
    let suffix = &normalized[authority..];
    let start = suffix.find(['/', '?', '#']).unwrap_or(suffix.len());
    if start == 0 { return None; }
    let remainder = &suffix[start..];
    let path = if remainder.starts_with('/') {
        &remainder[..remainder.find(['?', '#']).unwrap_or(remainder.len())]
    } else {
        "/"
    };
    let mut params: Vec<String> = parsed.query_pairs().map(|(name, _)| name.into_owned()).collect();
    params.sort();
    Some(Key {
        scheme: parsed.scheme().to_owned(), host, port: parsed.port(),
        path: path.to_owned(), params,
    })
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

fn baseline(path: &str) -> Result<BTreeSet<Key>> {
    // A projected delta is not an inventory, even if none of its new rows were
    // omitted. Refuse it instead of silently inventing gone observations.
    let invalid = || "--since requires a complete, unmodified bbp-urls report saved with --all".to_owned();
    if path == "-" { return Err(invalid()); }
    let value: Value = serde_json::from_reader(input(path)?).map_err(|_| invalid())?;
    let rows = value["rows"].as_array().ok_or_else(invalid)?;
    let cols = value["cols"].as_array().ok_or_else(invalid)?;
    if value["v"] != 1 || value["tool"] != "bbp-urls"
        || value["omitted"].as_u64() != Some(0)
        || value["total"].as_u64() != Some(rows.len() as u64)
        || value.get("partial").is_some()
        || value.get("completeness").is_some_and(|v| v != "complete")
        || !value["stats"].is_object() || value["stats"].get("delta").is_some()
        || cols.iter().any(|column| !column.is_string())
        || value["stats"].get("inventory_total").is_some_and(|total| total.as_u64() != Some(rows.len() as u64))
    { return Err(invalid()); }
    let required = ["scheme", "host", "port", "path", "params", "count", "source", "line", "byte"];
    let positions: Vec<usize> = required.iter().map(|name| {
        let found: Vec<_> = cols.iter().enumerate().filter(|(_, c)| c.as_str() == Some(*name)).map(|(n, _)| n).collect();
        if found.len() == 1 { Ok(found[0]) } else { Err(invalid()) }
    }).collect::<Result<_>>()?;
    let mut keys = BTreeSet::new();
    for row in rows {
        let row = row.as_array().filter(|row| row.len() == cols.len()).ok_or_else(invalid)?;
        let get = |index: usize| &row[positions[index]];
        let scheme = get(0).as_str().filter(|s| matches!(*s, "http" | "https")).ok_or_else(invalid)?;
        let host = get(1).as_str().ok_or_else(invalid)?;
        let parsed_host = Host::parse(host).map_err(|_| invalid())?;
        if parsed_host.to_string() != host { return Err(invalid()); }
        let port = if get(2).is_null() { None } else {
            Some(get(2).as_u64().and_then(|n| u16::try_from(n).ok()).ok_or_else(invalid)?)
        };
        if port == Some(if scheme == "https" { 443 } else { 80 }) { return Err(invalid()); }
        let path = get(3).as_str().filter(|p| p.starts_with('/') && !p.contains(['?', '#', '\\']))
            .ok_or_else(invalid)?;
        let params: Vec<String> = get(4).as_array().ok_or_else(invalid)?.iter()
            .map(|p| p.as_str().map(str::to_owned).ok_or_else(invalid)).collect::<Result<_>>()?;
        if params.windows(2).any(|pair| pair[0] > pair[1])
            || !get(5).as_u64().is_some_and(|n| n > 0)
            || !get(6).is_string() || !get(7).as_u64().is_some_and(|n| n > 0)
            || get(8).as_u64().is_none()
        { return Err(invalid()); }
        if !keys.insert(Key { scheme: scheme.into(), host: host.into(), port, path: path.into(), params }) {
            return Err(invalid());
        }
    }
    Ok(keys)
}

fn visit(
    literal: &[u8], bare: bool, source: &str, line: usize, byte: usize,
    host: Option<&str>, site: Option<&str>, entries: &mut BTreeMap<Key, Occurrences>, stats: &mut Stats,
) {
    stats.candidates += 1;
    if literal.len() > MAX_LITERAL_BYTES {
        stats.rejected += 1;
        stats.overlong += 1;
        return;
    }
    let Some(key) = key(literal, bare) else {
        stats.rejected += 1;
        return;
    };
    if host.is_some_and(|expected| key.host != expected) || site.is_some_and(|site| !in_site(&key.host, site)) {
        stats.filtered += 1;
        return;
    }
    stats.occurrences += 1;
    entries.entry(key).and_modify(|entry| entry.count += 1).or_insert_with(|| Occurrences {
        count: 1, source: source.to_owned(), line, byte,
    });
}

fn run() -> Result<()> {
    let options = Options::parse(&["--all"], &["--host", "--site", "--since", "--limit"])?;
    if options.help() {
        println!("bbp-urls [--host HOST | --site DOMAIN] [--since FILE] [--limit N | --all] FILE...\n\
Offline HTTP(S) literal inventory; use - for stdin. No network or finding claims.\n\
Accepts escaped JSON slashes and bare hostname lines (HTTPS). Not a semantic\n\
JavaScript or dynamic-route parser. --host is exact; --site matches DNS label-boundary\n\
suffixes, not eTLD+1 or authorization. --since compares a complete saved --all report,\n\
emits only new endpoint identities and reports new/gone/unchanged observed-set counts.\n\
Delta reports cannot themselves be baselines; no live/dead claims are made.\n\
Paths retain spelling; query names are decoded, sorted, and retain repetitions.\n\
Userinfo, fragments, and query values are omitted. Sentence-final . and , and\n\
unbalanced closing delimiters are trimmed; semicolons are preserved. Literals\n\
over 8192 bytes are rejected. Sources use one-based lines and zero-based byte offsets.\n\
Candidates are HTTP(S) literals and single hostname-like lines; other lines are ignored.");
        return Ok(());
    }
    options.require_inputs()?;
    let limit = options.limit()?;
    let host = options.value("--host").map(|value| {
        Host::parse(value).map(|host| host.to_string()).map_err(|_| "--host requires a hostname or bracketed IP address".to_owned())
    }).transpose()?;
    if host.is_some() && options.value("--site").is_some() {
        return Err("--host and --site are mutually exclusive".into());
    }
    let site = options.value("--site").map(site_domain).transpose()?;
    let previous = options.value("--since").map(baseline).transpose()?;
    let literal = Regex::new(r#"(?i-u)https?:(?:\\?/){2}[^\s<>"'`]*"#)
        .map_err(|error| error.to_string())?;
    let mut entries = BTreeMap::new();
    let mut stats = Stats::default();
    for source in &options.inputs {
        let mut reader = BufReader::new(input(source)?);
        let mut buffer = Vec::new();
        let mut line = 0;
        let mut offset = 0;
        loop {
            buffer.clear();
            let length = reader.read_until(b'\n', &mut buffer)
                .map_err(|error| format!("{source}: read failed: {error}"))?;
            if length == 0 { break; }
            line += 1;
            stats.lines += 1;
            stats.input_bytes += length;
            let mut matched = false;
            for found in literal.find_iter(&buffer) {
                matched = true;
                let candidate = found.as_bytes();
                // Do not scan or echo arbitrarily large literals for boundary cleanup.
                let end = if candidate.len() > MAX_LITERAL_BYTES { candidate.len() } else { literal_end(candidate) };
                visit(&candidate[..end], false, source, line, offset + found.start(), host.as_deref(), site.as_deref(), &mut entries, &mut stats);
            }
            if !matched {
                let start = buffer.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(buffer.len());
                let end = buffer.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(start, |n| n + 1);
                let candidate = &buffer[start..end];
                // A whole hostname-like token is eligible, not arbitrary prose or JS.
                let bare = !candidate.is_empty()
                    && !candidate.iter().any(|b| b.is_ascii_whitespace() || b"/\\@?#\"'`=<>".contains(b))
                    && (candidate.contains(&b'.') || candidate.contains(&b':') || candidate.eq_ignore_ascii_case(b"localhost"));
                if bare {
                    visit(candidate, true, source, line, offset + start, host.as_deref(), site.as_deref(), &mut entries, &mut stats);
                } else {
                    stats.ignored_lines += 1;
                }
            }
            offset += length;
        }
    }
    let inventory_total = entries.len();
    let delta = previous.as_ref().map(|previous| {
        let unchanged = entries.keys().filter(|key| previous.contains(*key)).count();
        json!({"new": inventory_total - unchanged, "gone": previous.len() - unchanged,
            "unchanged": unchanged, "previous_total": previous.len(), "current_total": inventory_total})
    });
    let rows: Vec<Value> = entries.into_iter()
        .filter(|(key, _)| previous.as_ref().is_none_or(|previous| !previous.contains(key)))
        .map(|(key, entry)| json!([
            key.scheme, key.host, key.port, key.path, key.params,
            entry.count, entry.source, entry.line, entry.byte,
        ])).collect();
    let mut metadata = json!({
        "input_bytes": stats.input_bytes, "lines": stats.lines,
        "candidates": stats.candidates, "rejected": stats.rejected,
        "overlong": stats.overlong, "filtered": stats.filtered,
        "occurrences": stats.occurrences, "ignored_lines": stats.ignored_lines,
        "inventory_total": inventory_total,
    });
    if let Some(delta) = delta { metadata["delta"] = delta; }
    report("bbp-urls", &["scheme", "host", "port", "path", "params", "count", "source", "line", "byte"], rows, limit, metadata)
}

fn main() { main_result(run); }
