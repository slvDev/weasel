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
    pub locations: Vec<Location>,
    pub example: Option<String>,
}

impl Finding {
    pub fn new(severity: Severity, title: &str, description: &str) -> Self {
        Self {
            severity,
            title: title.to_string(),
            description: description.to_string(),
            gas_savings: None,
            locations: Vec::new(),
            example: None,
        }
    }

    pub fn add_location(&mut self, location: Location) {
        self.locations.push(location);
    }

    pub fn with_gas_savings(mut self, savings: usize) -> Self {
        self.gas_savings = Some(savings);
        self
    }

    pub fn with_example(mut self, example: &str) -> Self {
        self.example = Some(example.to_string());
        self
    }
}
