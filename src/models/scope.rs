use serde::{Deserialize, Serialize};
use solang_parser::pt::SourceUnit;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidityFile {
    pub path: PathBuf,
    pub content: String,

    pub solidity_version: Option<String>,
    pub contracts: Vec<String>,
    pub interfaces: Vec<String>,
    pub libraries: Vec<String>,

    #[serde(skip)]
    pub source_unit: Option<SourceUnit>,
}

impl SolidityFile {
    pub fn new(path: PathBuf, content: String) -> Self {
        Self {
            path,
            content,
            source_unit: None,
            solidity_version: None,
            contracts: Vec::new(),
            interfaces: Vec::new(),
            libraries: Vec::new(),
        }
    }

    pub fn with_version(mut self, version: String) -> Self {
        self.solidity_version = Some(version);
        self
    }

    pub fn add_contract(&mut self, name: String) {
        self.contracts.push(name);
    }

    pub fn add_interface(&mut self, name: String) {
        self.interfaces.push(name);
    }

    pub fn add_library(&mut self, name: String) {
        self.libraries.push(name);
    }

    pub fn with_source_unit(mut self, source_unit: SourceUnit) -> Self {
        self.source_unit = Some(source_unit);
        self
    }
}

pub type ScopeFiles = Vec<SolidityFile>;
