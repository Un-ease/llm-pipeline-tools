pub mod recon;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufReader, Read, Write};

pub type Result<T, E = String> = std::result::Result<T, E>;

pub struct Options {
    pub flags: BTreeSet<String>,
    pub values: BTreeMap<String, String>,
    pub inputs: Vec<String>,
}

impl Options {
    pub fn parse(flags: &[&str], values: &[&str]) -> Result<Self> {
        let mut result = Self { flags: BTreeSet::new(), values: BTreeMap::new(), inputs: Vec::new() };
        let mut args = std::env::args().skip(1);
        let mut positional = false;
        while let Some(arg) = args.next() {
            if positional || arg == "-" || !arg.starts_with('-') {
                result.inputs.push(arg);
            } else if arg == "--" {
                positional = true;
            } else if arg == "--help" || arg == "-h" || flags.contains(&arg.as_str()) {
                result.flags.insert(arg);
            } else if values.contains(&arg.as_str()) || arg == "--limit" {
                let value = args.next().ok_or_else(|| format!("missing value for {arg}"))?;
                if result.values.insert(arg.clone(), value).is_some() {
                    return Err(format!("duplicate option {arg}"));
                }
            } else {
                return Err(format!("unknown option {arg}"));
            }
        }
        Ok(result)
    }

    pub fn help(&self) -> bool { self.flags.contains("--help") || self.flags.contains("-h") }
    pub fn flag(&self, key: &str) -> bool { self.flags.contains(key) }
    pub fn value(&self, key: &str) -> Option<&str> { self.values.get(key).map(String::as_str) }
    pub fn number(&self, key: &str, default: usize) -> Result<usize> {
        self.value(key).map_or(Ok(default), |v| v.parse().map_err(|_| format!("{key} requires a nonnegative integer")))
    }
    pub fn limit(&self) -> Result<usize> {
        let limit = self.number("--limit", 20)?;
        Ok(if self.flag("--all") { usize::MAX } else { limit })
    }
    pub fn require_inputs(&self) -> Result<()> {
        if self.inputs.is_empty() { Err("provide input paths, or - for stdin; use --help".into()) } else { Ok(()) }
    }
}

pub fn input(path: &str) -> Result<Box<dyn Read>> {
    if path == "-" { Ok(Box::new(io::stdin())) }
    else { std::fs::File::open(path).map(|f| Box::new(f) as Box<dyn Read>).map_err(|e| format!("{path}: {e}")) }
}

/// Accept JSON, JSON arrays, JSONL, and concatenated JSON values. Record IDs are
/// one-based top-level values, not line numbers (pretty JSON can span lines).
pub fn json_values(path: &str, mut visit: impl FnMut(Value, usize) -> Result<()>) -> Result<()> {
    let stream = serde_json::Deserializer::from_reader(BufReader::new(input(path)?)).into_iter::<Value>();
    for (index, value) in stream.enumerate() {
        let value = value.map_err(|e| format!("{path}: {e}"))?;
        visit(value, index + 1)?;
    }
    Ok(())
}

pub fn sha256(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }


/// Column names occur once; data is arrays. Never silently discard rows.
pub fn report<I>(tool: &str, columns: &[&str], rows: I, limit: usize, stats: Value) -> Result<()>
where
    I: IntoIterator<Item = Value>,
    I::IntoIter: ExactSizeIterator,
{
    let rows = rows.into_iter();
    let total = rows.len();
    let rows: Vec<Value> = rows.take(limit).collect();
    let shown = rows.len();
    let mut value = json!({"v":1,"tool":tool,"cols":columns,"total":total,"omitted":total-shown});
    value["rows"] = Value::Array(rows);
    value["stats"] = stats;
    let mut out = io::BufWriter::new(io::stdout().lock());
    serde_json::to_writer(&mut out, &value).map_err(|e| format!("stdout: {e}"))?;
    out.write_all(b"\n").map_err(|e| format!("stdout: {e}"))?;
    out.flush().map_err(|e| format!("stdout: {e}"))
}

pub fn main_result(run: impl FnOnce() -> Result<()>) {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}
