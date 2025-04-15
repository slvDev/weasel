use crate::models::finding::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub gas: usize,
    pub nc: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub comment: String,
    pub footnote: String,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

impl Report {
    pub fn new() -> Self {
        Self {
            comment: String::new(),
            footnote: String::new(),
            findings: Vec::new(),
            metadata: None,
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn with_comment(mut self, comment: &str) -> Self {
        self.comment = comment.to_string();
        self
    }

    pub fn with_footnote(mut self, footnote: &str) -> Self {
        self.footnote = footnote.to_string();
        self
    }

    pub fn add_metadata(&mut self, key: &str, value: &str) {
        if self.metadata.is_none() {
            self.metadata = Some(HashMap::new());
        }

        if let Some(metadata) = &mut self.metadata {
            metadata.insert(key.to_string(), value.to_string());
        }
    }

    pub fn summary(&self) -> Summary {
        let mut summary = Summary {
            high: 0,
            medium: 0,
            low: 0,
            gas: 0,
            nc: 0,
            total: self.findings.len(),
        };

        for finding in &self.findings {
            match finding.severity {
                crate::models::Severity::High => summary.high += 1,
                crate::models::Severity::Medium => summary.medium += 1,
                crate::models::Severity::Low => summary.low += 1,
                crate::models::Severity::Gas => summary.gas += 1,
                crate::models::Severity::NC => summary.nc += 1,
            }
        }

        summary
    }
}
