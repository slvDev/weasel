use crate::detectors::Detector;
use crate::models::Severity;
use std::collections::HashMap;
use std::sync::Arc;

pub struct DetectorRegistry {
    detectors: Vec<Arc<dyn Detector>>,
    detectors_by_id: HashMap<String, Arc<dyn Detector>>,
    detectors_by_severity: HashMap<Severity, Vec<Arc<dyn Detector>>>,
}

impl DetectorRegistry {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
            detectors_by_id: HashMap::new(),
            detectors_by_severity: HashMap::new(),
        }
    }

    pub fn register(&mut self, detector: Arc<dyn Detector>) {
        let id = detector.id().to_string();
        let severity = detector.severity();

        // Store detector Arc
        self.detectors.push(detector.clone());

        self.detectors_by_id.insert(id, detector.clone());
        self.detectors_by_severity
            .entry(severity)
            .or_default()
            .push(detector);
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Detector>> {
        self.detectors_by_id.get(id).cloned() // Clone the Arc
    }

    pub fn get_by_severity(&self, severity: &Severity) -> Vec<Arc<dyn Detector>> {
        self.detectors_by_severity
            .get(severity)
            .map(|arcs| arcs.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_all(&self) -> Vec<Arc<dyn Detector>> {
        println!("Getting all detectors");
        self.detectors.iter().cloned().collect()
    }

    /// Get the number of rgistered detectors
    pub fn count(&self) -> usize {
        self.detectors.len()
    }
}
