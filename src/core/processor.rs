use crate::core::finding_collector::FindingCollector;
use crate::core::visitor::ASTVisitor;
use crate::models::Location;
use crate::models::SolidityFile;
use rayon::prelude::*;
use std::collections::HashMap;

pub struct Processor {}

#[allow(dead_code)]
impl Processor {
    pub fn new() -> Self {
        Self {}
    }

    pub fn process_files(&self, files: &[SolidityFile], visitor: &ASTVisitor) -> AnalysisResults {
        let thread_count = self.get_thread_count();
        println!(
            "Processing {} files using {} threads",
            files.len(),
            thread_count
        );

        // Configure Rayon thread pool
        rayon::ThreadPoolBuilder::new()
            .num_threads(thread_count)
            .build_global()
            .expect("Failed to build thread pool");

        // Process files - each file gets its own collector
        let collectors: Vec<FindingCollector> = files
            .par_iter()
            .map(|file| {
                let mut collector = FindingCollector::new();

                // Run traverse on each file and collect findings
                let findings = visitor.traverse(file);

                // Collect findings into thread context
                for finding in findings {
                    collector.report_finding(finding.detector_id, finding.location);
                }

                collector
            })
            .collect();

        let results = self.merge_results(collectors);

        println!(
            "Analysis complete: {} total findings from {} files",
            results.total_findings(),
            files.len()
        );

        results
    }

    /// Merge collectors into final results
    fn merge_results(&self, collectors: Vec<FindingCollector>) -> AnalysisResults {
        let mut findings_by_detector: HashMap<&'static str, Vec<Location>> = HashMap::new();

        for collector in collectors {
            for detector_id in collector.detector_ids_with_findings() {
                if let Some(locations) = collector.get_detector_findings(detector_id) {
                    findings_by_detector
                        .entry(detector_id)
                        .or_insert(Vec::new())
                        .extend(locations.clone());
                }
            }
        }

        AnalysisResults {
            findings_by_detector,
        }
    }

    /// Auto-detect optimal thread count based on available CPU cores
    fn get_thread_count(&self) -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    }
}

#[derive(Debug)]
pub struct AnalysisResults {
    pub findings_by_detector: HashMap<&'static str, Vec<Location>>,
}

impl AnalysisResults {
    /// Get total number of findings across all detectors
    pub fn total_findings(&self) -> usize {
        self.findings_by_detector.values().map(|v| v.len()).sum()
    }

    /// Get findings for a specific detector
    pub fn get_detector_findings(&self, detector_id: &str) -> Option<&Vec<Location>> {
        self.findings_by_detector.get(detector_id)
    }

    /// Get all detector IDs that have findings
    pub fn detector_ids_with_findings(&self) -> Vec<&str> {
        self.findings_by_detector.keys().copied().collect()
    }
}
