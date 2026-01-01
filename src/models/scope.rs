use serde::{Deserialize, Serialize};
use solang_parser::pt::{ContractTy, Expression, SourceUnit, SourceUnitPart, Type};
use std::fmt;
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
pub enum TypeInfo {
    Address,
    AddressPayable,
    Payable,
    Bool,
    String,
    Int(u16),
    Uint(u16),
    Bytes(u8),
    Rational,
    DynamicBytes,
    Mapping {
        key: Box<TypeInfo>,
        value: Box<TypeInfo>,
    },
    Array {
        base: Box<TypeInfo>,
        size: Option<u64>,
    },
    UserDefined(String),
    Function,
    Unknown,
}

impl TypeInfo {
    pub fn from_solang_type(ty: &Type) -> Self {
        match ty {
            Type::Address => TypeInfo::Address,
            Type::AddressPayable => TypeInfo::AddressPayable,
            Type::Payable => TypeInfo::Payable,
            Type::Bool => TypeInfo::Bool,
            Type::String => TypeInfo::String,
            Type::Int(size) => TypeInfo::Int(*size),
            Type::Uint(size) => TypeInfo::Uint(*size),
            Type::Bytes(size) => TypeInfo::Bytes(*size),
            Type::Rational => TypeInfo::Rational,
            Type::DynamicBytes => TypeInfo::DynamicBytes,
            Type::Mapping { key, value, .. } => {
                let key_type = Box::new(TypeInfo::from_expression(key));
                let value_type = Box::new(TypeInfo::from_expression(value));
                TypeInfo::Mapping {
                    key: key_type,
                    value: value_type,
                }
            }
            Type::Function { .. } => TypeInfo::Function,
        }
    }

    /// Convert from Expression to TypeInfo
    pub fn from_expression(expr: &Expression) -> Self {
        match expr {
            Expression::Type(_, ty) => TypeInfo::from_solang_type(ty),
            Expression::Variable(ident) => TypeInfo::UserDefined(ident.name.clone()),
            Expression::MemberAccess(_, base, member) => {
                // Handle namespaced types like LibraryName.StructName
                let base_str = match base.as_ref() {
                    Expression::Variable(id) => id.name.as_str(),
                    _ => return TypeInfo::Unknown,
                };
                TypeInfo::UserDefined(format!("{}.{}", base_str, member.name))
            }
            Expression::ArraySubscript(_, base, size_expr) => {
                let base_type = Box::new(TypeInfo::from_expression(base));
                let size = size_expr.as_ref().and_then(|expr| {
                    // Try to extract numeric literal from size expression
                    if let Expression::NumberLiteral(_, val, _, _) = expr.as_ref() {
                        val.parse::<u64>().ok()
                    } else {
                        None
                    }
                });
                TypeInfo::Array {
                    base: base_type,
                    size,
                }
            }
            _ => TypeInfo::Unknown,
        }
    }

    pub fn is_int(&self) -> bool {
        matches!(self, TypeInfo::Int(_))
    }

    pub fn is_uint(&self) -> bool {
        matches!(self, TypeInfo::Uint(_))
    }

    pub fn is_address(&self) -> bool {
        matches!(self, TypeInfo::Address | TypeInfo::AddressPayable)
    }

    pub fn is_bytes(&self) -> bool {
        matches!(self, TypeInfo::Bytes(_) | TypeInfo::DynamicBytes)
    }
}

impl fmt::Display for TypeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeInfo::Address => write!(f, "address"),
            TypeInfo::AddressPayable => write!(f, "address payable"),
            TypeInfo::Payable => write!(f, "payable"),
            TypeInfo::Bool => write!(f, "bool"),
            TypeInfo::String => write!(f, "string"),
            TypeInfo::Int(size) => write!(f, "int{}", size),
            TypeInfo::Uint(size) => write!(f, "uint{}", size),
            TypeInfo::Bytes(size) => write!(f, "bytes{}", size),
            TypeInfo::Rational => write!(f, "fixed"),
            TypeInfo::DynamicBytes => write!(f, "bytes"),
            TypeInfo::Mapping { key, value } => write!(f, "mapping({} => {})", key, value),
            TypeInfo::Array { base, size } => {
                if let Some(s) = size {
                    write!(f, "{}[{}]", base, s)
                } else {
                    write!(f, "{}[]", base)
                }
            }
            TypeInfo::UserDefined(name) => write!(f, "{}", name),
            TypeInfo::Function => write!(f, "function"),
            TypeInfo::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateVariableInfo {
    pub loc: Location,
    pub name: String,
    pub type_info: TypeInfo,
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
