// src/core/context.rs
// Manages the analysis scope, file loading, and provides context for detectors.

use crate::models::{ContractDefinitionInfo, ScopeFiles, SolidityFile};
use solang_parser::{
    parse,
    pt::{PragmaDirective, SourceUnit, SourceUnitPart, VersionComparator},
};
use std::fs;
use std::path::{Path, PathBuf};

pub struct AnalysisContext {
    pub files: ScopeFiles,
}

impl AnalysisContext {
    pub fn new() -> Self {
        Self { files: Vec::new() }
    }

    /// Loads files from specified paths, handling directories recursively.
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

    /// Recursively loads Solidity files from a directory.
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

    /// Loads and parses a single Solidity file, extracting metadata.
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

/// Checks if a path points to a Solidity file.
fn is_solidity_file(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext.to_string_lossy().to_lowercase() == "sol")
        .unwrap_or(false)
}

/// Extracts the solidity version string from a pragma directive.
fn extract_solidity_version_from_pragma(pragma: &PragmaDirective) -> Option<String> {
    match pragma {
        PragmaDirective::Version(_loc, ident, version_req) => {
            if ident.name == "solidity" {
                let version_str = version_req
                    .iter()
                    .map(|comp| match comp {
                        VersionComparator::Operator { op, version, .. } => {
                            // TODO: Improve VersionOp display
                            format!("{:?}{}", op, version.join("."))
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

/// Extracts top-level metadata (version, contracts) from a SourceUnit.
pub fn extract_file_metadata(
    source_unit: &SourceUnit,
) -> (Option<String>, Vec<ContractDefinitionInfo>) {
    let mut found_version: Option<String> = None;
    let mut contract_defs: Vec<ContractDefinitionInfo> = Vec::new();

    for part in &source_unit.0 {
        match part {
            SourceUnitPart::PragmaDirective(pragma) => {
                if found_version.is_none() {
                    found_version = extract_solidity_version_from_pragma(pragma);
                }
            }
            SourceUnitPart::ContractDefinition(contract_def) => {
                if let Some(name_ident) = &contract_def.name {
                    let contract_info = ContractDefinitionInfo {
                        name: name_ident.name.clone(),
                        ty: (&contract_def.ty).into(),
                    };
                    contract_defs.push(contract_info);
                } // Ignore unnamed contracts
            }
            _ => {} // Ignore other parts for now
        }
    }

    (found_version, contract_defs)
}
