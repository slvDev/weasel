use crate::core::registry::DetectorRegistry;
use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::{ContractDefinitionInfo, Finding, Report, ScopeFiles, SolidityFile};
use solang_parser::{
    parse,
    pt::{PragmaDirective, SourceUnit, SourceUnitPart, VersionComparator},
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct AnalysisContext {
    pub files: ScopeFiles,
}

impl AnalysisContext {
    pub fn new() -> Self {
        Self { files: Vec::new() }
    }

    pub fn load_files(&mut self, paths: &[PathBuf]) -> Result<(), String> {
        for path in paths {
            if path.is_dir() {
                self.load_directory(path)?;
            } else if path.is_file() && is_solidity_file(path) {
                self.load_file(path)?;
            }
        }
        Ok(())
    }

    fn load_directory(&mut self, dir_path: &Path) -> Result<(), String> {
        let entries =
            fs::read_dir(dir_path).map_err(|e| format!("Failed to read directory: {}", e))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
            let path = entry.path();
            if path.is_dir() {
                self.load_directory(&path)?;
            } else if path.is_file() && is_solidity_file(&path) {
                self.load_file(&path)?;
            }
        }
        Ok(())
    }

    fn load_file(&mut self, file_path: &Path) -> Result<(), String> {
        let content = fs::read_to_string(file_path)
            .map_err(|e| format!("Failed to read file '{}': {}", file_path.display(), e))?;

        let parse_result = parse(&content, 0);
        if let Err(errors) = &parse_result {
            return Err(format!(
                "Failed to parse '{}': {:?}",
                file_path.display(),
                errors
            ));
        }

        let (source_unit, _comments) = parse_result.unwrap();

        let mut solidity_file = SolidityFile::new(file_path.to_path_buf(), content);

        let (version, contracts) = extract_file_metadata(&source_unit);

        solidity_file.set_solidity_version(version);
        solidity_file.set_contract_definitions(contracts);
        solidity_file.set_source_unit_ast(source_unit);

        self.files.push(solidity_file);
        Ok(())
    }
}

pub struct AnalysisEngine {
    context: AnalysisContext,
    registry: DetectorRegistry,
    visitor: ASTVisitor,
}

impl AnalysisEngine {
    pub fn new() -> Self {
        Self {
            context: AnalysisContext::new(),
            registry: DetectorRegistry::new(),
            visitor: ASTVisitor::new(),
        }
    }

    pub fn register_detector(&mut self, detector: Arc<dyn Detector>) {
        self.registry.register(detector);
    }

    /// Register all built-in detectors
    pub fn register_built_in_detectors(&mut self) {
        // Medium severity detectors
        // not implemented

        // Low severity detectors
        // not implemented

        // Non-critical detectors
        self.register_detector(Arc::new(crate::detectors::nc::ArrayIndicesDetector::new()));

        // Gas optimization detectors
        // not implemented
    }

    pub fn analyze(&mut self, paths: Vec<PathBuf>) -> Result<Report, String> {
        self.context.load_files(&paths)?;
        println!("Loaded {} Solidity files", self.context.files.len());

        let mut report = Report::new();
        let detectors = self.registry.get_all();
        for detector_arc in detectors.clone() {
            println!(
                "Registering callbacks for detector: {}",
                detector_arc.name()
            );
            detector_arc.register_callbacks(&mut self.visitor);
        }
        println!("Traversing AST with visitor...");
        self.visitor.traverse(&self.context.files);

        println!("Collecting findings from detectors...");
        for detector_arc in detectors {
            let collected_locations = detector_arc.locations();
            if !collected_locations.is_empty() {
                println!(
                    "Found {} locations for detector {}",
                    collected_locations.len(),
                    detector_arc.id()
                );
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

    pub fn visitor_mut(&mut self) -> &mut ASTVisitor {
        &mut self.visitor
    }

    pub fn visitor(&self) -> &ASTVisitor {
        &self.visitor
    }
}

// Helper functions
fn is_solidity_file(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext.to_string_lossy().to_lowercase() == "sol")
        .unwrap_or(false)
}

fn extract_solidity_version_from_pragma(pragma: &PragmaDirective) -> Option<String> {
    match pragma {
        PragmaDirective::Version(_loc, ident, version_req) => {
            if ident.name == "solidity" {
                // Simple string reconstruction
                let version_str = version_req
                    .iter()
                    .map(|comp| match comp {
                        VersionComparator::Operator { op, version, .. } => {
                            // Need Display impl for VersionOp or manual mapping
                            // For now, using debug representation or placeholder
                            format!("{:?}{}", op, version.join(".")) // Placeholder format
                        }
                        VersionComparator::Plain { version, .. } => version.join("."),
                        _ => "complex_version_req".to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                Some(version_str)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn extract_file_metadata(
    source_unit: &SourceUnit,
) -> (Option<String>, Vec<ContractDefinitionInfo>) {
    let mut found_version: Option<String> = None;
    let mut contract_defs: Vec<ContractDefinitionInfo> = Vec::new();

    for part in &source_unit.0 {
        match part {
            SourceUnitPart::PragmaDirective(pragma) => {
                if found_version.is_none() {
                    // Take the first version pragma
                    found_version = extract_solidity_version_from_pragma(pragma);
                }
            }
            SourceUnitPart::ContractDefinition(contract_def) => {
                if let Some(name_ident) = &contract_def.name {
                    let contract_info = ContractDefinitionInfo {
                        name: name_ident.name.clone(),
                        ty: (&contract_def.ty).into(), // Use From trait
                    };
                    contract_defs.push(contract_info);
                } else {
                    // Ignore unnamed contracts
                }
            }
            _ => {} // Ignore other for now
        }
    }

    (found_version, contract_defs)
}
