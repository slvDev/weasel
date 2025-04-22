use crate::models::severity::Severity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    pub line: usize,
    pub column: Option<usize>,
    pub line_end: Option<usize>,
    pub column_end: Option<usize>,
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub gas_savings: Option<usize>,
    pub example: Option<String>,
    pub locations: Vec<Location>,
}

impl Finding {
    pub fn new(severity: Severity, title: &str, description: &str) -> Self {
        Self {
            severity,
            title: title.to_string(),
            description: description.to_string(),
            gas_savings: None,
            example: None,
            locations: Vec::new(),
        }
    }
}
