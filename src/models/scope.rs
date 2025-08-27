use serde::{Deserialize, Serialize};
use solang_parser::pt::{ContractTy, SourceUnit, SourceUnitPart};
use std::path::PathBuf;

use crate::utils::ast_utils::{
    extract_contract_info, extract_solidity_version_from_pragma, process_import_directive,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractDefinitionInfo {
    pub name: String,
    pub ty: ContractType,
}

#[derive(Debug, Clone, Serialize)]
pub struct SolidityFile {
    pub path: PathBuf,
    pub content: String,

    pub solidity_version: Option<String>,
    pub imports: Vec<ImportInfo>,
    pub contract_definitions: Vec<ContractInfo>,

    #[serde(skip)]
    pub source_unit: SourceUnit,
    #[serde(skip)]
    pub line_starts: Vec<usize>,
}

impl SolidityFile {
    pub fn new(path: PathBuf, content: String, source_unit: SourceUnit) -> Self {
        let mut line_starts = vec![0]; // Line 1 starts at offset 0
        for (i, byte) in content.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(i + 1);
            }
        }

        Self {
            path,
            content,
            source_unit,
            solidity_version: None,
            contract_definitions: Vec::new(),
            imports: Vec::new(),
            line_starts,
        }
    }

    pub fn extract_metadata(&mut self) {
        for part in &self.source_unit.0 {
            match part {
                SourceUnitPart::PragmaDirective(pragma) => {
                    if let Some(version) = extract_solidity_version_from_pragma(pragma) {
                        self.solidity_version = Some(version);
                    }
                }
                SourceUnitPart::ImportDirective(import) => {
                    if let Ok(import_info) = process_import_directive(import) {
                        self.imports.push(import_info);
                    }
                }
                SourceUnitPart::ContractDefinition(contract_def) => {
                    if let Ok(contract) = extract_contract_info(contract_def, &self.path) {
                        self.contract_definitions.push(contract);
                    }
                }
                _ => {}
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContractType {
    Contract,
    Abstract,
    Interface,
    Library,
}

// Convert from ContractTy since it's not serializable
impl From<&ContractTy> for ContractType {
    fn from(ty: &ContractTy) -> Self {
        match ty {
            ContractTy::Abstract(_) => ContractType::Abstract,
            ContractTy::Contract(_) => ContractType::Contract,
            ContractTy::Interface(_) => ContractType::Interface,
            ContractTy::Library(_) => ContractType::Library,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContractInfo {
    pub name: String,
    pub contract_type: ContractType,
    pub file_path: String,
    pub direct_bases: Vec<String>,
    pub inheritance_chain: Vec<String>,
    pub state_variables: Vec<String>,
    pub function_definitions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    pub import_path: String,
    pub resolved_path: Option<PathBuf>,
    pub symbols: Vec<String>,
}

pub type ScopeFiles = Vec<SolidityFile>;
