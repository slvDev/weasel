use crate::config::Config;
use crate::core::context::AnalysisContext;
use crate::core::registry::DetectorRegistry;
use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::{Finding, Report};
use std::sync::Arc;

pub struct AnalysisEngine {
    context: AnalysisContext,
    registry: DetectorRegistry,
    visitor: ASTVisitor,
    config: Config,
}

impl AnalysisEngine {
    pub fn new(config: &Config) -> Self {
        Self {
            context: AnalysisContext::new(),
            registry: DetectorRegistry::new(),
            visitor: ASTVisitor::new(),
            config: config.clone(),
        }
    }

    pub fn register_detector(&mut self, detector: Arc<dyn Detector>) {
        if detector.severity().as_value() >= self.config.min_severity.as_value() {
            self.registry.register(detector);
        }
    }

    pub fn register_built_in_detectors(&mut self) {
        // High severity detectors
        // not implemented

        // Medium severity detectors
        // not implemented

        // Low severity detectors
        // not implemented

        // Gas detectors
        // not implemented

        // NC detectors
        self.register_detector(Arc::new(
            crate::detectors::nc::ArrayIndicesDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::AbiEncodeCallDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::UnnecessaryAbiCoderV2Detector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ConstantCaseDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::MagicNumberDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::TwoStepCriticalChangesDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::WhileTrueLoopDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::PreferRequireDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::PreferConcatDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::DefaultVisibilityDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ConsoleLogImportDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::RenounceOwnershipDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::DraftDependencyDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::DuplicateRequireRevertDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::RedundantElseDetector::default(),
        ));
        self.register_detector(Arc::new(crate::detectors::nc::EventArgsDetector::default()));
        self.register_detector(Arc::new(
            crate::detectors::nc::EventMissingIndexedArgsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::FunctionLengthDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::nc::ExplicitNumTypesDetector::default(),
        ));
    }

    pub fn analyze(&mut self) -> Result<Report, String> {
        self.context.load_files(&self.config.scope)?;
        println!("Loaded {} Solidity files", self.context.files.len());

        let mut report = Report::new();
        let detectors = self.registry.get_all();
        for detector_arc in detectors.clone() {
            detector_arc.register_callbacks(&mut self.visitor);
        }
        println!("Traversing AST with visitor...");
        self.visitor.traverse(&self.context.files);

        println!("Collecting findings from detectors...");
        for detector_arc in detectors {
            let collected_locations = detector_arc.locations();
            if !collected_locations.is_empty() {
                let finding = Finding {
                    severity: detector_arc.severity(),
                    title: detector_arc.name().to_string(),
                    description: detector_arc.description().to_string(),
                    gas_savings: detector_arc.gas_savings(),
                    example: detector_arc.example(),
                    locations: collected_locations,
                };
                report.add_finding(finding);
            }
        }

        report.add_metadata("version", crate::core::version());
        report.add_metadata("timestamp", &chrono::Utc::now().to_rfc3339());
        report.add_metadata("files_analyzed", &self.context.files.len().to_string());

        Ok(report)
    }

    // Getters
    pub fn registry(&self) -> &DetectorRegistry {
        &self.registry
    }
}
