use serde::{Deserialize, Serialize};
use solang_parser::pt::{ContractTy, SourceUnit, SourceUnitPart};
use std::path::PathBuf;

use crate::utils::ast_utils::{
    extract_contract_info, extract_enum_info, extract_error_info, extract_event_info,
    extract_solidity_version_from_pragma, extract_struct_info, process_import_directive,
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
    pub enums: Vec<EnumInfo>,
    pub errors: Vec<ErrorInfo>,
    pub events: Vec<EventInfo>,
    pub structs: Vec<StructInfo>,

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
            enums: Vec::new(),
            errors: Vec::new(),
            events: Vec::new(),
            structs: Vec::new(),
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
                SourceUnitPart::EnumDefinition(enum_def) => {
                    let enum_info = extract_enum_info(enum_def);
                    self.enums.push(enum_info);
                }
                SourceUnitPart::ErrorDefinition(error_def) => {
                    let error_info = extract_error_info(error_def);
                    self.errors.push(error_info);
                }
                SourceUnitPart::EventDefinition(event_def) => {
                    let event_info = extract_event_info(event_def);
                    self.events.push(event_info);
                }
                SourceUnitPart::StructDefinition(struct_def) => {
                    let struct_info = extract_struct_info(struct_def);
                    self.structs.push(struct_info);
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
    pub enums: Vec<EnumInfo>,
    pub errors: Vec<ErrorInfo>,
    pub events: Vec<EventInfo>,
    pub structs: Vec<StructInfo>,
    pub modifiers: Vec<ModifierInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    pub import_path: String,
    pub resolved_path: Option<PathBuf>,
    pub symbols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnumInfo {
    pub name: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorInfo {
    pub name: String,
    pub parameters: Vec<ErrorParameter>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorParameter {
    pub name: Option<String>,
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventInfo {
    pub name: String,
    pub parameters: Vec<EventParameter>,
    pub anonymous: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventParameter {
    pub name: Option<String>,
    pub type_name: String,
    pub indexed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StructInfo {
    pub name: String,
    pub fields: Vec<StructField>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StructField {
    pub name: Option<String>,
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModifierInfo {
    pub name: String,
    pub parameters: Vec<ModifierParameter>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModifierParameter {
    pub name: Option<String>,
    pub type_name: String,
}

pub type ScopeFiles = Vec<SolidityFile>;
