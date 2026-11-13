use llm_pipeline_tools::{Options, Result, input, main_result, report};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufReader, Read};

const HELP: &str = "bbp-gql [--type NAME [--field NAME]] [--limit N | --all] SCHEMA\n\nOffline saved GraphQL introspection lookup; SCHEMA may be - for stdin.\nDefault: list types and member counts. --type: exact field/input/enum lookup.\nTypes retain list/non-null wrappers; arguments include requiredness.\nSelected arguments/input fields require saved defaultValue metadata (string or null).\nMissing members mean absent from this saved schema, not a live authorization verdict.\nDescriptions, default values, response data, and credentials are never emitted.\nOutput: compact JSON with columns once, total and omitted row counts.\n";

struct Counted<R> { inner: R, bytes: u64 }
impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes += n as u64;
        Ok(n)
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(|| format!("schema member missing string {key}"))
}

fn type_ref(value: &Value, depth: usize) -> Result<String> {
    if depth > 64 { return Err("type wrapper nesting exceeds 64".into()); }
    match text(value, "kind")? {
        "NON_NULL" => Ok(format!("{}!", type_ref(&value["ofType"], depth + 1)?)),
        "LIST" => Ok(format!("[{}]", type_ref(&value["ofType"], depth + 1)?)),
        "SCALAR" | "OBJECT" | "INTERFACE" | "UNION" | "ENUM" | "INPUT_OBJECT" => Ok(text(value, "name")?.into()),
        kind => Err(format!("unsupported type kind {kind}")),
    }
}

fn members<'a>(ty: &'a Value, key: &str) -> Result<&'a [Value]> {
    ty.get(key).and_then(Value::as_array).map(Vec::as_slice)
        .ok_or_else(|| format!("{key} unavailable in saved introspection for {}", ty["name"]))
}

fn field_rows(ty: &Value, wanted: Option<&str>) -> Result<Vec<Value>> {
    let kind = text(ty, "kind")?;
    let (key, member_kind) = match kind {
        "OBJECT" | "INTERFACE" => ("fields", "field"),
        "INPUT_OBJECT" => ("inputFields", "input"),
        "ENUM" => ("enumValues", "enum"),
        _ => {
            if wanted.is_some() { return Err(format!("{kind} has no selectable members")); }
            return Ok(Vec::new());
        }
    };
    let mut rows = Vec::new();
    for field in members(ty, key)? {
        let name = text(field, "name")?;
        if wanted.is_some_and(|w| w != name) { continue; }
        let mut args = Vec::new();
        if member_kind == "field" {
            for arg in members(field, "args")? {
                let default = arg.get("defaultValue").ok_or("argument defaultValue unavailable in saved introspection")?;
                if !default.is_null() && !default.is_string() { return Err("argument defaultValue must be a string or null".into()); }
                let has_default = !default.is_null();
                let required = arg["type"]["kind"] == "NON_NULL" && !has_default;
                args.push(json!([text(arg, "name")?, type_ref(&arg["type"], 0)?, required, has_default]));
            }
            args.sort_by(|a, b| a[0].as_str().cmp(&b[0].as_str()));
        }
        let returns = if member_kind == "enum" { Value::Null } else { json!(type_ref(&field["type"], 0)?) };
        let has_default = if member_kind == "input" {
            let default = field.get("defaultValue").ok_or("input field defaultValue unavailable in saved introspection")?;
            if !default.is_null() && !default.is_string() { return Err("input field defaultValue must be a string or null".into()); }
            json!(!default.is_null())
        } else { Value::Null };
        rows.push(json!([name, member_kind, returns, args, field.get("isDeprecated").and_then(Value::as_bool), has_default]));
    }
    if wanted.is_some() && rows.is_empty() { return Err(format!("member {} absent from saved type {}", wanted.unwrap(), ty["name"])); }
    rows.sort_by(|a, b| a[0].as_str().cmp(&b[0].as_str()));
    Ok(rows)
}

fn run() -> Result<()> {
    let opts = Options::parse(&["--all"], &["--type", "--field"])?;
    if opts.help() { print!("{HELP}"); return Ok(()); }
    opts.require_inputs()?;
    if opts.inputs.len() != 1 { return Err("provide exactly one saved introspection schema".into()); }
    if opts.value("--field").is_some() && opts.value("--type").is_none() { return Err("--field requires --type".into()); }
    let limit = opts.limit()?;
    let source = &opts.inputs[0];
    let mut reader = BufReader::new(Counted { inner: input(source)?, bytes: 0 });
    let document: Value = serde_json::from_reader(&mut reader).map_err(|e| format!("{source}: {e}"))?;
    let schema = document.pointer("/data/__schema").or_else(|| document.get("__schema"))
        .or_else(|| document.get("types").map(|_| &document)).ok_or("missing __schema.types introspection")?;
    let types = schema.get("types").and_then(Value::as_array).ok_or("missing __schema.types array")?;
    let mut index = BTreeMap::new();
    for ty in types {
        let name = text(ty, "name")?;
        text(ty, "kind")?;
        if index.insert(name, ty).is_some() { return Err(format!("duplicate schema type {name}")); }
    }
    let mut stats = json!({"source":source,"input_bytes":reader.get_ref().bytes,"types":index.len(),
        "query_root":schema.pointer("/queryType/name"),"mutation_root":schema.pointer("/mutationType/name"),
        "subscription_root":schema.pointer("/subscriptionType/name"),
        "introspection_errors":document.get("errors").and_then(Value::as_array).map_or(0, Vec::len)});
    if let Some(name) = opts.value("--type") {
        let ty = index.get(name).ok_or_else(|| format!("type {name} absent from saved schema"))?;
        let rows = field_rows(ty, opts.value("--field"))?;
        stats["selected_type"] = json!(name);
        stats["argument_cols"] = json!(["name", "type", "required", "has_default"]);
        report("bbp-gql", &["member", "kind", "type", "arguments", "deprecated", "has_default"], rows, limit, stats)
    } else {
        let rows = index.into_iter().map(|(name, ty)| {
            let count = |key| ty.get(key).and_then(Value::as_array).map(|a| json!(a.len())).unwrap_or(Value::Null);
            json!([name, ty["kind"], count("fields"), count("inputFields"), count("enumValues")])
        });
        report("bbp-gql", &["type", "kind", "fields", "input_fields", "enum_values"], rows, limit, stats)
    }
}

fn main() { main_result(run); }
