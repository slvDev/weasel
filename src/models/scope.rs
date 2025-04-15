use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidityFile {
    pub path: PathBuf,
    pub content: String,

    pub solidity_version: Option<String>,
    pub contracts: Vec<String>,
    pub interfaces: Vec<String>,
    pub libraries: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ast: Option<String>,
}

impl SolidityFile {
    pub fn new(path: PathBuf, content: String) -> Self {
        Self {
            path,
            content,
            ast: None,
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

    pub fn with_ast(mut self, ast: String) -> Self {
        self.ast = Some(ast);
        self
    }
}

pub type ScopeFiles = Vec<SolidityFile>;
