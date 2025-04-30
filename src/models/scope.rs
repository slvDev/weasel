use serde::{Deserialize, Serialize};
use solang_parser::pt::{ContractTy, SourceUnit};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContractTyInfo {
    Abstract,
    Contract,
    Interface,
    Library,
}

// Convert from ContractTy since it's not serializable
impl From<&ContractTy> for ContractTyInfo {
    fn from(ty: &ContractTy) -> Self {
        match ty {
            ContractTy::Abstract(_) => ContractTyInfo::Abstract,
            ContractTy::Contract(_) => ContractTyInfo::Contract,
            ContractTy::Interface(_) => ContractTyInfo::Interface,
            ContractTy::Library(_) => ContractTyInfo::Library,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractDefinitionInfo {
    pub name: String,
    pub ty: ContractTyInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidityFile {
    pub path: PathBuf,
    pub content: String,

    pub solidity_version: Option<String>,
    pub contract_definitions: Vec<ContractDefinitionInfo>,

    #[serde(skip)]
    pub source_unit: Option<SourceUnit>,
    #[serde(skip)]
    pub line_starts: Vec<usize>,
}

impl SolidityFile {
    pub fn new(path: PathBuf, content: String) -> Self {
        let mut line_starts = vec![0]; // Line 1 starts at offset 0
        for (i, byte) in content.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(i + 1);
            }
        }

        Self {
            path,
            content,
            source_unit: None,
            solidity_version: None,
            contract_definitions: Vec::new(),
            line_starts,
        }
    }

    pub fn set_solidity_version(&mut self, version: Option<String>) {
        self.solidity_version = version;
    }

    pub fn set_contract_definitions(&mut self, definitions: Vec<ContractDefinitionInfo>) {
        self.contract_definitions = definitions;
    }

    pub fn set_source_unit_ast(&mut self, source_unit: SourceUnit) {
        self.source_unit = Some(source_unit);
    }
}

pub type ScopeFiles = Vec<SolidityFile>;
