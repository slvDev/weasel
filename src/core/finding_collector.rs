use crate::models::finding::Location;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct FindingCollector {
    findings_by_detector: HashMap<&'static str, Vec<Location>>,
}

impl FindingCollector {
    pub fn new() -> Self {
        Self {
            findings_by_detector: HashMap::new(),
        }
    }

    /// Report a finding from a detector
    pub fn report_finding(&mut self, detector_id: &'static str, location: Location) {
        self.findings_by_detector
            .entry(detector_id)
            .or_insert(Vec::new())
            .push(location);
    }

    /// Get findings for a specific detector
    pub fn get_detector_findings(&self, detector_id: &str) -> Option<&Vec<Location>> {
        self.findings_by_detector.get(detector_id)
    }

    /// Get all detector IDs with findings
    pub fn detector_ids_with_findings(&self) -> Vec<&'static str> {
        self.findings_by_detector.keys().copied().collect()
    }

    /// Get total findings count (for user-facing info)
    pub fn total_findings(&self) -> usize {
        self.findings_by_detector.values().map(|v| v.len()).sum()
    }
}
