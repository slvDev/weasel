use crate::config::Config;
use crate::core::context::AnalysisContext;
use crate::core::processor::{AnalysisResults, Processor};
use crate::core::project_detector::{ProjectConfig, ProjectType};
use crate::core::registry::DetectorRegistry;
use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::{Finding, Report};
use std::collections::HashMap;
use std::path::PathBuf;
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
        self.register_detector(Arc::new(
            crate::detectors::medium::BlockNumberL2Detector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::CentralizationRiskDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::ChainlinkStalePriceDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::DeprecatedChainlinkFunctionDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::DeprecatedTransferDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::DirectSupportsInterfaceDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::Eip712ComplianceDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::FeeOnTransferDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::L2SequencerCheckDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::LibraryFunctionVisibilityDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::NftMintAsymmetryDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::SoladySafeTransferDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::SolmateSafeTransferDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::TxOriginUsageDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::UnboundedFeeDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::UncheckedTransferDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::UnsafeApproveDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::UnsafeErc20OperationsDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::UnsafeMintDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::UnsafeTransferFromDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::medium::UsdtAllowanceDetector::default(),
        ));

        // Low severity detectors
        // not implemented

        // Gas detectors
        self.register_detector(Arc::new(
            crate::detectors::gas::AddressZeroCheckDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::ArrayCompoundAssignmentDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::ArrayLengthInLoopDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::BooleanComparisonDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::CompoundAssignmentDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::MsgSenderUsageDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::UnsafeArrayAccessDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::BoolStorageDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::CalldataInsteadOfMemoryDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::UncheckedLoopIncrementDetector::default(),
        ));
        self.register_detector(Arc::new(
            crate::detectors::gas::CustomErrorsInsteadOfRevertStringsDetector::default(),
        ));

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
        // Determine project root - look for project markers
        let project_root = self
            .config
            .scope
            .first()
            .and_then(|p| {
                // Start from the scope path and walk up to find project root
                let mut current = if p.is_dir() {
                    p.clone()
                } else {
                    p.parent().map(|parent| parent.to_path_buf())?
                };

                // Walk up directories looking for project markers
                loop {
                    // Check for project configuration files
                    if current.join("foundry.toml").exists()
                        || current.join("hardhat.config.js").exists()
                        || current.join("hardhat.config.ts").exists()
                        || current.join("truffle-config.js").exists()
                    {
                        return Some(current);
                    }

                    // Move up one directory
                    match current.parent() {
                        Some(parent) if parent != current => {
                            current = parent.to_path_buf();
                        }
                        _ => break,
                    }
                }

                // If no project marker found, use the original logic
                if p.is_dir() {
                    Some(p.clone())
                } else {
                    p.parent().map(|parent| parent.to_path_buf())
                }
            })
            .unwrap_or_else(|| PathBuf::from("."));

        // Auto-detect project configuration
        let project_config = ProjectConfig::auto_detect(&project_root).unwrap_or_else(|e| {
            println!("Note: Could not auto-detect project type: {}", e);
            // Fallback to custom config
            ProjectConfig::from_manual_config(
                project_root.clone(),
                HashMap::new(),
                vec![PathBuf::from("lib"), PathBuf::from("node_modules")],
            )
        });

        // Display detected project type
        match project_config.project_type {
            ProjectType::Foundry => {
                println!("Detected Foundry project at: {}", project_root.display());
                if !project_config.remappings.is_empty() {
                    println!(
                        "Loaded {} auto-detected remappings from foundry.toml",
                        project_config.remappings.len()
                    );
                }
            }
            ProjectType::Hardhat => println!("Detected Hardhat project"),
            ProjectType::Truffle => println!("Detected Truffle project"),
            ProjectType::Custom => println!("Using custom project configuration"),
        }

        // Merge auto-detected remappings with CLI remappings (CLI takes precedence)
        let mut final_remappings = project_config.remappings.clone();

        // Parse and add CLI remappings (these override auto-detected ones)
        for remapping in &self.config.remappings {
            if let Some((from, to)) = remapping.split_once('=') {
                final_remappings.insert(from.to_string(), PathBuf::from(to));
                println!("Added CLI remapping: {} -> {}", from, to);
            }
        }

        if !final_remappings.is_empty() {
            println!("Total remappings configured: {}", final_remappings.len());
            for (from, to) in &final_remappings {
                println!("  {} -> {}", from, to.display());
            }
        }

        self.context
            .set_import_resolver(final_remappings, project_root.clone());

        // Set library paths in the import resolver
        if let Some(ref mut resolver) = self.context.get_import_resolver_mut() {
            resolver.add_library_paths(project_config.library_paths.clone());
            println!("Added library paths: {:?}", project_config.library_paths);
        }

        self.context
            .load_files(&self.config.scope, &self.config.exclude)?;
        println!("Loaded {} Solidity files", self.context.files.len());

        self.context.build_cache()?;
        // println!("{:?}", &self.context);
        println!(
            "Built inheritance cache for {} contracts",
            self.context.contracts.len()
        );

        if !self.context.missing_contracts.is_empty() {
            println!(
                "\nWarning: {} missing contracts detected:",
                self.context.missing_contracts.len()
            );
            for missing in &self.context.missing_contracts {
                println!("  - {}", missing);
            }
        }

        // Display inheritance summary
        println!("\nInheritance Summary:");
        let mut has_inheritance = false;
        for (name, contract) in &self.context.contracts {
            if !contract.inheritance_chain.is_empty() {
                has_inheritance = true;
                println!("  {} inherits from:", name);
                for base in &contract.inheritance_chain {
                    println!("    -> {}", base);
                }
            }
        }
        if !has_inheritance {
            println!("  No inheritance relationships found");
        }

        let detectors = self.registry.get_all();
        for detector_arc in detectors.clone() {
            detector_arc.register_callbacks(&mut self.visitor);
        }

        let results =
            self.processor
                .process_files(&self.context.files, &self.visitor, &self.context);

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
                    example: detector.example(),
                    locations: locations.clone(),
                };
                report.add_finding(finding);
            }
        }

        // Add metadata
        report.add_metadata("Version:", crate::core::version());
        report.add_metadata(
            "Timestamp:",
            &chrono::Utc::now().format("%d/%m/%Y %H:%M:%S").to_string(),
        );
        report.add_metadata("Total Findings:", &results.total_findings().to_string());

        report
    }

    // Getters
    pub fn registry(&self) -> &DetectorRegistry {
        &self.registry
    }
}
