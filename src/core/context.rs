use crate::core::c3_linearization::c3_linearize;
use crate::core::import_resolver::ImportResolver;
use crate::models::{
    ContractInfo, EnumInfo, ErrorInfo, EventInfo, FunctionInfo, ModifierInfo, ScopeFiles,
    SolidityFile, StateVariableInfo, StructInfo, TypeDefinitionInfo, UsingDirectiveInfo,
};
use solang_parser::parse;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct AnalysisContext {
    pub files: ScopeFiles,
    pub contracts: HashMap<String, ContractInfo>, // "file_path:contract_name" -> info
    pub missing_contracts: HashSet<String>,
    import_resolver: Option<ImportResolver>,
}

impl AnalysisContext {
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            contracts: HashMap::new(),
            missing_contracts: HashSet::new(),
            import_resolver: None,
        }
    }

    /// Set up import resolver with remappings
    pub fn set_import_resolver(
        &mut self,
        remappings: HashMap<String, PathBuf>,
        project_root: PathBuf,
    ) {
        let mut resolver = ImportResolver::new(project_root);
        resolver.set_remappings(remappings);
        self.import_resolver = Some(resolver);
    }

    /// Get mutable reference to import resolver
    pub fn get_import_resolver_mut(&mut self) -> Option<&mut ImportResolver> {
        self.import_resolver.as_mut()
    }

    /// Loads files from specified paths, handling directories recursively.
    /// Excludes paths that match any of the exclude patterns.
    pub fn load_files(&mut self, paths: &[PathBuf], exclude: &[PathBuf]) -> Result<(), String> {
        for path in paths {
            if self.is_excluded(path, exclude) {
                continue;
            }

            if path.is_dir() {
                self.load_directory(path, exclude)?;
            } else if path.is_file() && is_solidity_file(path) {
                self.load_file(path)?;
            }
        }
        Ok(())
    }

    /// Recursively loads Solidity files from a directory.
    /// Excludes paths that match any of the exclude patterns.
    fn load_directory(&mut self, dir_path: &Path, exclude: &[PathBuf]) -> Result<(), String> {
        let entries =
            fs::read_dir(dir_path).map_err(|e| format!("Failed to read directory: {}", e))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("Failed to read directory entry: {}", e))?;
            let path = entry.path();

            if self.is_excluded(&path, exclude) {
                continue;
            }

            if path.is_dir() {
                self.load_directory(&path, exclude)?;
            } else if path.is_file() && is_solidity_file(&path) {
                self.load_file(&path)?;
            }
        }
        Ok(())
    }

    /// Returns true if the path matches any exclude pattern.
    fn is_excluded(&self, path: &Path, exclude: &[PathBuf]) -> bool {
        exclude
            .iter()
            .any(|exclude_pattern| path.starts_with(exclude_pattern))
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

        let mut solidity_file = SolidityFile::new(file_path.to_path_buf(), content, source_unit);
        solidity_file.extract_metadata();
        self.files.push(solidity_file);
        Ok(())
    }

    /// Builds cache tables after all files are loaded.
    pub fn build_cache(&mut self) -> Result<(), String> {
        let contracts_to_register: Vec<_> = self
            .files
            .iter()
            .flat_map(|file| file.contract_definitions.iter().cloned())
            .collect();

        for contract in contracts_to_register {
            self.register_contract(contract);
        }

        self.resolve_inheritance()?;
        Ok(())
    }

    fn resolve_inheritance(&mut self) -> Result<(), String> {
        let mut visited = HashSet::new();
        let mut temp_visited = HashSet::new();
        let initial_contract_names: Vec<String> = self.contracts.keys().cloned().collect();

        for contract_name in &initial_contract_names {
            if !visited.contains(contract_name) {
                self.resolve_contract_inheritance(contract_name, &mut visited, &mut temp_visited)?;
            }
        }

        let missing_contracts: Vec<String> = self.missing_contracts.iter().cloned().collect();

        for missing_contract in missing_contracts {
            if let Some(contract_info) = self.find_contract_in_imports(&missing_contract, None)? {
                self.register_contract(contract_info);
                self.missing_contracts.remove(&missing_contract);

                let qualified_name = self.get_qualified_name_for_contract(&missing_contract);
                if !visited.contains(&qualified_name) {
                    self.resolve_contract_inheritance(
                        &qualified_name,
                        &mut visited,
                        &mut temp_visited,
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Builds inheritance chain using C3 linearization.
    fn resolve_contract_inheritance(
        &mut self,
        contract_name: &str,
        visited: &mut HashSet<String>,
        temp_visited: &mut HashSet<String>,
    ) -> Result<(), String> {
        if temp_visited.contains(contract_name) {
            return Err(format!(
                "Circular inheritance detected involving contract: {}",
                contract_name
            ));
        }

        if visited.contains(contract_name) {
            return Ok(());
        }

        temp_visited.insert(contract_name.to_string());

        let direct_bases = if let Some(contract) = self.contracts.get(contract_name) {
            contract.direct_bases.clone()
        } else {
            Vec::new()
        };

        let mut qualified_bases = Vec::new();

        let current_file_path = if contract_name.contains(':') {
            let parts: Vec<&str> = contract_name.split(':').collect();
            Some(PathBuf::from(parts[0]))
        } else {
            None
        };

        for base_name in &direct_bases {
            let qualified_base_name = self.get_qualified_name_for_contract(base_name);

            if self.contracts.contains_key(&qualified_base_name) {
                self.resolve_contract_inheritance(&qualified_base_name, visited, temp_visited)?;
                qualified_bases.push(qualified_base_name);
            } else if let Some(ref file_path) = current_file_path {
                if let Some(contract_info) =
                    self.find_contract_in_imports(base_name, Some(&file_path))?
                {
                    self.register_contract(contract_info);

                    let new_qualified_name = self.get_qualified_name_for_contract(base_name);
                    if !visited.contains(&new_qualified_name) {
                        self.resolve_contract_inheritance(
                            &new_qualified_name,
                            visited,
                            temp_visited,
                        )?;
                    }
                    qualified_bases.push(new_qualified_name);
                    self.missing_contracts.remove(base_name);
                } else {
                    self.missing_contracts.insert(base_name.clone());
                }
            } else {
                self.missing_contracts.insert(base_name.clone());
            }
        }

        let inheritance_chain = if !qualified_bases.is_empty() {
            let get_linearization = |base: &str| -> Result<Vec<String>, String> {
                self.contracts
                    .get(base)
                    .map(|c| c.inheritance_chain.clone())
                    .ok_or_else(|| format!("Contract {} not found", base))
            };

            match c3_linearize(contract_name, &qualified_bases, get_linearization) {
                Ok(chain) => chain,
                Err(_) => {
                    // Fallback to simple linearization when C3 fails
                    let mut simple_chain = Vec::new();
                    for base in &qualified_bases {
                        if let Some(base_contract) = self.contracts.get(base) {
                            for inherited in &base_contract.inheritance_chain {
                                if !simple_chain.contains(inherited) {
                                    simple_chain.push(inherited.clone());
                                }
                            }
                            if !simple_chain.contains(base) {
                                simple_chain.push(base.clone());
                            }
                        }
                    }
                    simple_chain
                }
            }
        } else {
            Vec::new()
        };

        if let Some(contract) = self.contracts.get_mut(contract_name) {
            contract.inheritance_chain = inheritance_chain;
        }

        temp_visited.remove(contract_name);
        visited.insert(contract_name.to_string());

        Ok(())
    }

    pub fn get_inheritance_chain(&self, contract: &str) -> Option<&[String]> {
        self.contracts
            .get(contract)
            .map(|c| c.inheritance_chain.as_slice())
    }

    fn register_contract(&mut self, contract: ContractInfo) {
        let qualified_name = format!("{}:{}", contract.file_path, contract.name);
        self.contracts.insert(qualified_name, contract);
    }

    pub fn get_contract(&self, qualified_name: &str) -> Option<&ContractInfo> {
        self.contracts.get(qualified_name)
    }

    fn load_imported_file(
        &mut self,
        import_path: &str,
        current_file: &Path,
    ) -> Result<bool, String> {
        let resolver = match &self.import_resolver {
            Some(r) => r.clone(),
            None => return Ok(false),
        };

        let resolved_path = match resolver.resolve_import(import_path, current_file) {
            Ok(path) => path,
            Err(_) => return Ok(false),
        };

        if self.files.iter().any(|f| f.path == resolved_path) {
            return Ok(false);
        }

        self.load_file(&resolved_path)?;

        let contracts_to_register: Vec<_> = self
            .files
            .iter()
            .find(|f| f.path == resolved_path)
            .map(|file| file.contract_definitions.clone())
            .unwrap_or_default();

        for contract in contracts_to_register {
            self.register_contract(contract);
        }

        Ok(true)
    }

    fn find_contract_in_imports(
        &mut self,
        contract_name: &str,
        current_file: Option<&Path>,
    ) -> Result<Option<ContractInfo>, String> {
        for file in &self.files {
            for contract in &file.contract_definitions {
                if contract.name == contract_name {
                    return Ok(Some(contract.clone()));
                }
            }
        }

        if let Some(current) = current_file {
            let imports: Vec<_> = self
                .files
                .iter()
                .find(|f| f.path == current)
                .map(|f| f.imports.clone())
                .unwrap_or_default();

            for import_info in imports {
                if self.load_imported_file(&import_info.import_path, current)? {
                    for file in &self.files {
                        for contract in &file.contract_definitions {
                            if contract.name == contract_name {
                                return Ok(Some(contract.clone()));
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Converts simple contract name to qualified name if found.
    pub fn get_qualified_name_for_contract(&self, contract_name: &str) -> String {
        if contract_name.contains(':') {
            return contract_name.to_string();
        }

        for file in &self.files {
            for contract in &file.contract_definitions {
                if contract.name == contract_name {
                    return format!("{}:{}", contract.file_path, contract.name);
                }
            }
        }

        contract_name.to_string()
    }

    /// Get all state variables from a contract including inherited ones.
    /// Returns in inheritance order (base first, derived last) matching Solidity storage layout.
    pub fn get_all_state_variables(&self, qualified_name: &str) -> Vec<&StateVariableInfo> {
        let mut result = Vec::new();

        let contract = match self.contracts.get(qualified_name) {
            Some(c) => c,
            None => return result,
        };

        for inherited_name in &contract.inheritance_chain {
            if let Some(inherited) = self.contracts.get(inherited_name) {
                result.extend(inherited.state_variables.iter());
            }
        }

        result.extend(contract.state_variables.iter());
        result
    }

    /// Get all functions from a contract including inherited ones.
    pub fn get_all_functions(&self, qualified_name: &str) -> Vec<&FunctionInfo> {
        let mut result = Vec::new();

        let contract = match self.contracts.get(qualified_name) {
            Some(c) => c,
            None => return result,
        };

        for inherited_name in &contract.inheritance_chain {
            if let Some(inherited) = self.contracts.get(inherited_name) {
                result.extend(inherited.function_definitions.iter());
            }
        }

        result.extend(contract.function_definitions.iter());
        result
    }

    /// Get all enums from a contract including inherited ones.
    pub fn get_all_enums(&self, qualified_name: &str) -> Vec<&EnumInfo> {
        let mut result = Vec::new();

        let contract = match self.contracts.get(qualified_name) {
            Some(c) => c,
            None => return result,
        };

        for inherited_name in &contract.inheritance_chain {
            if let Some(inherited) = self.contracts.get(inherited_name) {
                result.extend(inherited.enums.iter());
            }
        }

        result.extend(contract.enums.iter());
        result
    }

    /// Get all errors from a contract including inherited ones.
    pub fn get_all_errors(&self, qualified_name: &str) -> Vec<&ErrorInfo> {
        let mut result = Vec::new();

        let contract = match self.contracts.get(qualified_name) {
            Some(c) => c,
            None => return result,
        };

        for inherited_name in &contract.inheritance_chain {
            if let Some(inherited) = self.contracts.get(inherited_name) {
                result.extend(inherited.errors.iter());
            }
        }

        result.extend(contract.errors.iter());
        result
    }

    /// Get all events from a contract including inherited ones.
    pub fn get_all_events(&self, qualified_name: &str) -> Vec<&EventInfo> {
        let mut result = Vec::new();

        let contract = match self.contracts.get(qualified_name) {
            Some(c) => c,
            None => return result,
        };

        for inherited_name in &contract.inheritance_chain {
            if let Some(inherited) = self.contracts.get(inherited_name) {
                result.extend(inherited.events.iter());
            }
        }

        result.extend(contract.events.iter());
        result
    }

    /// Get all structs from a contract including inherited ones.
    pub fn get_all_structs(&self, qualified_name: &str) -> Vec<&StructInfo> {
        let mut result = Vec::new();

        let contract = match self.contracts.get(qualified_name) {
            Some(c) => c,
            None => return result,
        };

        for inherited_name in &contract.inheritance_chain {
            if let Some(inherited) = self.contracts.get(inherited_name) {
                result.extend(inherited.structs.iter());
            }
        }

        result.extend(contract.structs.iter());
        result
    }

    /// Get all modifiers from a contract including inherited ones.
    pub fn get_all_modifiers(&self, qualified_name: &str) -> Vec<&ModifierInfo> {
        let mut result = Vec::new();

        let contract = match self.contracts.get(qualified_name) {
            Some(c) => c,
            None => return result,
        };

        for inherited_name in &contract.inheritance_chain {
            if let Some(inherited) = self.contracts.get(inherited_name) {
                result.extend(inherited.modifiers.iter());
            }
        }

        result.extend(contract.modifiers.iter());
        result
    }

    /// Get all type definitions from a contract including inherited ones.
    pub fn get_all_type_definitions(&self, qualified_name: &str) -> Vec<&TypeDefinitionInfo> {
        let mut result = Vec::new();

        let contract = match self.contracts.get(qualified_name) {
            Some(c) => c,
            None => return result,
        };

        for inherited_name in &contract.inheritance_chain {
            if let Some(inherited) = self.contracts.get(inherited_name) {
                result.extend(inherited.type_definitions.iter());
            }
        }

        result.extend(contract.type_definitions.iter());
        result
    }

    /// Get all using directives from a contract including inherited ones.
    pub fn get_all_using_directives(&self, qualified_name: &str) -> Vec<&UsingDirectiveInfo> {
        let mut result = Vec::new();

        let contract = match self.contracts.get(qualified_name) {
            Some(c) => c,
            None => return result,
        };

        for inherited_name in &contract.inheritance_chain {
            if let Some(inherited) = self.contracts.get(inherited_name) {
                result.extend(inherited.using_directives.iter());
            }
        }

        result.extend(contract.using_directives.iter());
        result
    }

    pub fn get_file_by_path(&self, path: &Path) -> Option<&SolidityFile> {
        self.files.iter().find(|f| f.path == path)
    }

    /// Check if a contract inherits from a specific base contract
    pub fn inherits_from(&self, qualified_name: &str, base_pattern: &str) -> bool {
        let contract = match self.contracts.get(qualified_name) {
            Some(c) => c,
            None => return false,
        };

        contract
            .inheritance_chain
            .iter()
            .any(|inherited| inherited.contains(base_pattern))
    }

    /// Check if a contract inherits from a base
    pub fn contract_inherits_from(
        &self,
        contract_def: &solang_parser::pt::ContractDefinition,
        file: &SolidityFile,
        base_pattern: &str,
    ) -> bool {
        let contract_name = match contract_def.name.as_ref() {
            Some(name) => name.name.as_str(),
            None => return false,
        };
        let qualified_name = format!("{}:{}", file.path.display(), contract_name);
        self.inherits_from(&qualified_name, base_pattern)
    }

    /// Check if a contract defines a specific function
    pub fn contract_defines_function(
        &self,
        contract_def: &solang_parser::pt::ContractDefinition,
        file: &SolidityFile,
        function_name: &str,
    ) -> bool {
        let contract_name = match contract_def.name.as_ref() {
            Some(name) => name.name.as_str(),
            None => return false,
        };
        let qualified_name = format!("{}:{}", file.path.display(), contract_name);

        if let Some(contract_info) = self.contracts.get(&qualified_name) {
            contract_info
                .function_definitions
                .iter()
                .any(|f| f.name == function_name)
        } else {
            false
        }
    }
}

/// Checks if a path points to a Solidity file.
fn is_solidity_file(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext.to_string_lossy().to_lowercase() == "sol")
        .unwrap_or(false)
}
