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

pub struct FindingData {
    pub detector_id: &'static str,
    pub location: Location,
}

impl From<FindingData> for Vec<FindingData> {
    fn from(finding: FindingData) -> Self {
        vec![finding]
    }
}
