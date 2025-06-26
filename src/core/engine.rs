use crate::config::Config;
use crate::core::context::AnalysisContext;
use crate::core::processor::{AnalysisResults, Processor};
use crate::core::registry::DetectorRegistry;
use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::{Finding, Report};
use std::sync::Arc;

pub struct AnalysisEngine {
    context: AnalysisContext,
    registry: DetectorRegistry,
    visitor: ASTVisitor,
    processor: Processor,
    config: Config,
}

impl AnalysisEngine {
    pub fn new(config: &Config) -> Self {
        Self {
            context: AnalysisContext::new(),
            registry: DetectorRegistry::new(),
            visitor: ASTVisitor::new(),
            processor: Processor::new(),
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
        self.register_detector(Arc::new(
            crate::detectors::high::ComparisonWithoutEffectDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::high::DelegatecallInLoopDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::high::CurveSpotPriceOracleDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::high::MsgValueInLoopDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::high::WstethStethPerTokenUsageDetector::default(),
        ));

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
        self.context
            .load_files(&self.config.scope, &self.config.exclude)?;
        println!("Loaded {} Solidity files", self.context.files.len());

        let detectors = self.registry.get_all();
        for detector_arc in detectors.clone() {
            detector_arc.register_callbacks(&mut self.visitor);
        }

        let results = self
            .processor
            .process_files(&self.context.files, &self.visitor);

        let report = self.generate_report_from_results(&results);

        Ok(report)
    }

    fn generate_report_from_results(&self, results: &AnalysisResults) -> Report {
        let mut report = Report::new();

        for (detector_id, locations) in &results.findings_by_detector {
            if let Some(detector) = self.registry.get(detector_id) {
                let finding = Finding {
                    severity: detector.severity(),
                    title: detector.name().to_string(),
                    description: detector.description().to_string(),
                    gas_savings: detector.gas_savings(),
                    example: detector.example(),
                    locations: locations.clone(),
                };
                report.add_finding(finding);
            }
        }

        // Add metadata
        report.add_metadata("version", crate::core::version());
        report.add_metadata("timestamp", &chrono::Utc::now().to_rfc3339());
        report.add_metadata("total_findings", &results.total_findings().to_string());

        report
    }

    // Getters
    pub fn registry(&self) -> &DetectorRegistry {
        &self.registry
    }
}
