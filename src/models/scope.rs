use serde::{Deserialize, Serialize};
use solang_parser::pt::{ContractTy, SourceUnit, SourceUnitPart};
use std::path::PathBuf;

use crate::models::finding::Location;
use crate::utils::ast_utils::{
    extract_contract_info, extract_enum_info, extract_error_info, extract_event_info,
    extract_function_info, extract_solidity_version_from_pragma, extract_struct_info,
    extract_type_definition_info, extract_using_directive_info, extract_variable_info,
    process_import_directive,
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
    pub type_definitions: Vec<TypeDefinitionInfo>,
    pub using_directives: Vec<UsingDirectiveInfo>,
    pub variables: Vec<StateVariableInfo>,
    pub functions: Vec<FunctionInfo>,

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
            type_definitions: Vec::new(),
            using_directives: Vec::new(),
            variables: Vec::new(),
            functions: Vec::new(),
            line_starts,
        }
    }

    pub fn extract_metadata(&mut self) {
        let metadata = Self::collect_metadata(&self.source_unit, self);

        self.solidity_version = metadata.solidity_version;
        self.imports = metadata.imports;
        self.contract_definitions = metadata.contract_definitions;
        self.enums = metadata.enums;
        self.errors = metadata.errors;
        self.events = metadata.events;
        self.structs = metadata.structs;
        self.type_definitions = metadata.type_definitions;
        self.using_directives = metadata.using_directives;
        self.variables = metadata.variables;
        self.functions = metadata.functions;
    }

    fn collect_metadata(source_unit: &SourceUnit, file: &SolidityFile) -> FileMetadata {
        let mut metadata = FileMetadata::default();

        for part in &source_unit.0 {
            match part {
                SourceUnitPart::PragmaDirective(pragma) => {
                    if let Some(version) = extract_solidity_version_from_pragma(pragma) {
                        metadata.solidity_version = Some(version);
                    }
                }
                SourceUnitPart::ImportDirective(import) => {
                    if let Ok(import_info) = process_import_directive(import, file) {
                        metadata.imports.push(import_info);
                    }
                }
                SourceUnitPart::ContractDefinition(contract_def) => {
                    if let Ok(contract) = extract_contract_info(contract_def, file) {
                        metadata.contract_definitions.push(contract);
                    }
                }
                SourceUnitPart::EnumDefinition(enum_def) => {
                    metadata.enums.push(extract_enum_info(enum_def, file));
                }
                SourceUnitPart::ErrorDefinition(error_def) => {
                    metadata.errors.push(extract_error_info(error_def, file));
                }
                SourceUnitPart::EventDefinition(event_def) => {
                    metadata.events.push(extract_event_info(event_def, file));
                }
                SourceUnitPart::StructDefinition(struct_def) => {
                    metadata.structs.push(extract_struct_info(struct_def, file));
                }
                SourceUnitPart::TypeDefinition(type_def) => {
                    metadata.type_definitions.push(extract_type_definition_info(type_def, file));
                }
                SourceUnitPart::Using(using) => {
                    metadata.using_directives.push(extract_using_directive_info(using, file));
                }
                SourceUnitPart::VariableDefinition(var_def) => {
                    metadata.variables.push(extract_variable_info(var_def, file));
                }
                SourceUnitPart::FunctionDefinition(func_def) => {
                    metadata.functions.push(extract_function_info(func_def, file));
                }
                _ => {}
            }
        }

        metadata
    }
}

#[derive(Default)]
struct FileMetadata {
    solidity_version: Option<String>,
    imports: Vec<ImportInfo>,
    contract_definitions: Vec<ContractInfo>,
    enums: Vec<EnumInfo>,
    errors: Vec<ErrorInfo>,
    events: Vec<EventInfo>,
    structs: Vec<StructInfo>,
    type_definitions: Vec<TypeDefinitionInfo>,
    using_directives: Vec<UsingDirectiveInfo>,
    variables: Vec<StateVariableInfo>,
    functions: Vec<FunctionInfo>,
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
    pub loc: Location,
    pub name: String,
    pub contract_type: ContractType,
    pub file_path: String,
    pub direct_bases: Vec<String>,
    pub inheritance_chain: Vec<String>,
    pub state_variables: Vec<StateVariableInfo>,
    pub function_definitions: Vec<FunctionInfo>,
    pub enums: Vec<EnumInfo>,
    pub errors: Vec<ErrorInfo>,
    pub events: Vec<EventInfo>,
    pub structs: Vec<StructInfo>,
    pub modifiers: Vec<ModifierInfo>,
    pub type_definitions: Vec<TypeDefinitionInfo>,
    pub using_directives: Vec<UsingDirectiveInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    pub loc: Location,
    pub import_path: String,
    pub resolved_path: Option<PathBuf>,
    pub symbols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnumInfo {
    pub loc: Location,
    pub name: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErrorInfo {
    pub loc: Location,
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
    pub loc: Location,
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
    pub loc: Location,
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
    pub loc: Location,
    pub name: String,
    pub parameters: Vec<ModifierParameter>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModifierParameter {
    pub name: Option<String>,
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TypeDefinitionInfo {
    pub loc: Location,
    pub name: String,
    pub underlying_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsingDirectiveInfo {
    pub loc: Location,
    pub library_name: Option<String>,
    pub functions: Vec<String>,
    pub target_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateVariableInfo {
    pub loc: Location,
    pub name: String,
    pub type_name: String,
    pub visibility: VariableVisibility,
    pub mutability: VariableMutability,
    pub is_constant: bool,
    pub is_immutable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VariableVisibility {
    Public,
    Private,
    Internal,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VariableMutability {
    Mutable,
    Constant,
    Immutable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FunctionInfo {
    pub loc: Location,
    pub name: String,
    pub parameters: Vec<FunctionParameter>,
    pub return_parameters: Vec<FunctionParameter>,
    pub visibility: FunctionVisibility,
    pub mutability: FunctionMutability,
    pub function_type: FunctionType,
    pub modifiers: Vec<String>,
    pub is_virtual: bool,
    pub is_override: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FunctionParameter {
    pub name: Option<String>,
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FunctionVisibility {
    Public,
    Private,
    Internal,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FunctionMutability {
    Pure,
    View,
    Payable,
    Nonpayable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FunctionType {
    Function,
    Constructor,
    Fallback,
    Receive,
}

pub type ScopeFiles = Vec<SolidityFile>;
