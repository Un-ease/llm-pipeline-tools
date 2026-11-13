use super::types::CrawlCheckpoint;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

/// An interrupted backend is never a completed observation set.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PartialInfo {
    pub error: String,
    pub cutoff_reason: String,
    pub captured_bytes: usize,
    pub parsed_bytes: usize,
    pub discarded_tail_bytes: usize,
    pub backend_exit: Option<i32>,
    pub backend_signal: Option<i32>,
}

#[derive(Debug)]
pub struct WorkflowResult {
    pub rows: Vec<Value>,
    pub cols: Vec<&'static str>,
    pub coverage: Value,
    pub queue: Option<CrawlCheckpoint>,
    pub partial: Option<PartialInfo>,
}

impl WorkflowResult {
    pub fn complete(rows: Vec<Value>) -> Self {
        Self { rows, cols: Vec::new(), coverage: json!({}), queue: None, partial: None }
    }

    /// Full facts are journaled before a presentation layer limits rows or queues.
    pub fn into_payload(self, tool: &str) -> Value {
        let mut value = Map::new();
        value.insert("v".into(), json!(2));
        value.insert("tool".into(), Value::String(tool.into()));
        value.insert("total".into(), json!(self.rows.len()));
        value.insert("omitted".into(), json!(0));
        value.insert("rows".into(), Value::Array(self.rows));
        value.insert("cols".into(), json!(self.cols));
        value.insert("coverage".into(), self.coverage);
        value.insert("completeness".into(), json!(if self.partial.is_some() { "partial" } else { "complete" }));
        value.insert("queue".into(), json!(self.queue));
        if let Some(partial) = self.partial { value.insert("partial".into(), json!(partial)); }
        Value::Object(value)
    }
}
