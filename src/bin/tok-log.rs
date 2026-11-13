use llm_pipeline_tools::{Options, Result, input, main_result, report, sha256};
use regex::Regex;
use serde_json::json;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};

struct Occurrences {
    count: usize,
    first: (usize, usize),
    last: (usize, usize),
    order: usize,
    display_chars: usize,
}

// The timestamp regex checks syntax; impossible calendar dates are still text.
fn valid_date(timestamp: &str) -> bool {
    let year: u32 = timestamp[..4].parse().unwrap();
    let month: u32 = timestamp[5..7].parse().unwrap();
    let day: u32 = timestamp[8..10].parse().unwrap();
    let days = match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    day <= days
}

fn run() -> Result<()> {
    let options = Options::parse(&["--all", "--strip-time"], &["--width", "--limit"])?;
    if options.help() {
        println!("tok-log [--strip-time] [--width N] [--limit N | --all] FILE...\n\
Use - for stdin. Offline exact-line compaction; no semantic classification or secret redaction.\n\
Snippets may contain sensitive data. --width 0 gives hashes/refs/counts without snippets.\n\
Default width: 180 Unicode characters; default limit: 20 unique lines.\n\
Only newline CRLF is normalized by default; an unterminated final CR is preserved.\n\
--strip-time removes only a leading extended ISO8601 date/time (T separator, optional\n\
fraction and zone) or [HH:MM:SS[.fraction]], plus at most one following space/tab.\n\
Impossible calendar dates are not stripped.\n\
All other text, IDs, numbers, and stacktrace indentation remain exact.\n\
Whitespace-only lines are retained and counted as blank; final newlines add no phantom line.\n\
Input must be UTF-8; invalid input fails without a success report.\n\
Rows sort by descending count, then first occurrence across inputs. References are\n\
[path, one-based line]. Hashes cover full normalized lines, excluding newline bytes.\n\
truncated_chars counts omitted Unicode characters per representative;\n\
display_truncations/display_truncated_chars count only displayed representatives,\n\
including snippet suppression at width 0. Omitted rows remain accounted for separately.");
        return Ok(());
    }
    options.require_inputs()?;
    let width = options.number("--width", 180)?;
    // Validate even when --all overrides the numeric limit.
    let requested_limit = options.number("--limit", 20)?;
    let limit = if options.flag("--all") { usize::MAX } else { requested_limit };
    let timestamp = if options.flag("--strip-time") {
        Some(Regex::new(concat!(
            r"^(?:",
            r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])[Tt]",
            r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:(?:[0-5][0-9]|60)",
            r"(?:[.,][0-9]+)?(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):?[0-5][0-9])?",
            r"(?:[ \t]|$)|",
            r"\[(?:[01][0-9]|2[0-3]):[0-5][0-9]:(?:[0-5][0-9]|60)(?:\.[0-9]+)?\][ \t]?",
            r")"
        )).map_err(|e| format!("timestamp pattern: {e}"))?)
    } else {
        None
    };
    let mut groups: HashMap<String, Occurrences> = HashMap::new();
    let mut input_bytes = 0_u64;
    let mut total_lines = 0_usize;
    let mut blank_lines = 0_usize;
    let mut buffer = Vec::new();
    for (source, path) in options.inputs.iter().enumerate() {
        let mut reader = BufReader::new(input(path)?);
        let mut line_number = 0_usize;
        loop {
            buffer.clear();
            let bytes = reader.read_until(b'\n', &mut buffer)
                .map_err(|e| format!("{path}: {e}"))?;
            if bytes == 0 { break; }
            input_bytes += bytes as u64;
            total_lines += 1;
            line_number += 1;
            if buffer.last() == Some(&b'\n') {
                buffer.pop();
                if buffer.last() == Some(&b'\r') { buffer.pop(); }
            }
            let original = std::str::from_utf8(&buffer)
                .map_err(|e| format!("{path}:{line_number}: invalid UTF-8: {e}"))?;
            let line = match &timestamp {
                Some(pattern) => pattern.find(original)
                    .filter(|_| original.starts_with('[') || valid_date(original))
                    .map_or(original, |m| &original[m.end()..]),
                None => original,
            };
            if line.chars().all(char::is_whitespace) { blank_lines += 1; }
            if let Some(group) = groups.get_mut(line) {
                group.count += 1;
                group.last = (source, line_number);
            } else {
                groups.insert(line.to_owned(), Occurrences {
                    count: 1,
                    first: (source, line_number),
                    last: (source, line_number),
                    order: total_lines,
                    display_chars: 0,
                });
            }
        }
    }
    let unique_lines = groups.len();
    let mut groups: Vec<_> = groups.into_iter().collect();
    groups.sort_unstable_by(|a, b| b.1.count.cmp(&a.1.count).then(a.1.order.cmp(&b.1.order)));
    let mut display_truncations = 0_usize;
    let mut display_truncated_chars = 0_usize;
    for (line, group) in groups.iter_mut().take(limit) {
        group.display_chars = line.chars().count();
        let truncated_chars = group.display_chars.saturating_sub(width);
        if truncated_chars > 0 {
            display_truncations += 1;
            display_truncated_chars += truncated_chars;
        }
    }
    let rows = groups.into_iter().enumerate().map(|(_, (line, group))| {
        let chars = group.display_chars;
        let truncated_chars = chars.saturating_sub(width);
        let snippet = if width == 0 {
            None
        } else if truncated_chars == 0 {
            Some(line.as_str())
        } else {
            let end = line.char_indices().nth(width).map_or(line.len(), |(offset, _)| offset);
            Some(&line[..end])
        };
        json!([
            group.count,
            [&options.inputs[group.first.0], group.first.1],
            [&options.inputs[group.last.0], group.last.1],
            sha256(line.as_bytes()),
            chars,
            truncated_chars,
            snippet
        ])
    });
    report("tok-log", &["count", "first", "last", "sha256", "chars", "truncated_chars", "snippet"], rows, limit,
        json!({
            "input_bytes": input_bytes,
            "total_lines": total_lines,
            "unique_lines": unique_lines,
            "repeated_lines": total_lines - unique_lines,
            "blank_lines": blank_lines,
            "display_truncations": display_truncations,
            "display_truncated_chars": display_truncated_chars,
            "strip_time": options.flag("--strip-time"),
            "width": width
        }))
}

fn main() { main_result(run); }
