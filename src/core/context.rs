use crate::core::c3_linearization::c3_linearize;
use crate::core::import_resolver::ImportResolver;
use crate::models::{ContractInfo, ScopeFiles, SolidityFile};
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

    /// Builds cache tables after all files are loaded
    pub fn build_cache(&mut self) -> Result<(), String> {
        // First pass: Register all contracts from files to cache
        let contracts_to_register: Vec<_> = self
            .files
            .iter()
            .flat_map(|file| file.contract_definitions.iter().cloned())
            .collect();

        for contract in contracts_to_register {
            let qualified_name = format!("{}:{}", contract.file_path, contract.name);
            self.register_contract(contract);
        }

        // Second pass: Resolve inheritance
        self.resolve_inheritance()?;

        Ok(())
    }

    /// Second pass: Resolve inheritance
    fn resolve_inheritance(&mut self) -> Result<(), String> {
        // First, resolve inheritance for contracts already in the cache
        let mut visited = HashSet::new();
        let mut temp_visited = HashSet::new();
        let initial_contract_names: Vec<String> = self.contracts.keys().cloned().collect();

        for contract_name in &initial_contract_names {
            if !visited.contains(contract_name) {
                self.resolve_contract_inheritance(contract_name, &mut visited, &mut temp_visited)?;
            }
        }

        // Now, check if we need to load any missing contracts from imported files
        let missing_contracts: Vec<String> = self.missing_contracts.iter().cloned().collect();

        for missing_contract in missing_contracts {
            // Try to find the contract in imported files
            // Note: We don't have specific file context here, so pass None
            if let Some(contract_info) = self.find_contract_in_imports(&missing_contract, None)? {
                // Add the found contract to our cache
                self.register_contract(contract_info);

                // Remove from missing contracts set
                self.missing_contracts.remove(&missing_contract);

                // Resolve inheritance for the newly added contract
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

    /// Recursively resolve inheritance for a single contract
    /// Builds inheritance chain following Solidity's linearization order (most derived to base)
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

        // Get direct bases for this contract
        let direct_bases = if let Some(contract) = self.contracts.get(contract_name) {
            contract.direct_bases.clone()
        } else {
            Vec::new()
        };

        // First, ensure all base contracts are resolved
        let mut qualified_bases = Vec::new();

        // Extract the file path from the qualified contract name
        let current_file_path = if contract_name.contains(':') {
            let parts: Vec<&str> = contract_name.split(':').collect();
            Some(PathBuf::from(parts[0]))
        } else {
            None
        };

        for base_name in &direct_bases {
            let qualified_base_name = self.get_qualified_name_for_contract(base_name);

            if self.contracts.contains_key(&qualified_base_name) {
                // Recursively resolve base contract first
                self.resolve_contract_inheritance(&qualified_base_name, visited, temp_visited)?;
                qualified_bases.push(qualified_base_name);
            } else {
                // Base contract not found - try dynamic loading via imports

                // Try to find and load the contract from imports
                if let Some(ref file_path) = current_file_path {
                    if let Some(contract_info) =
                        self.find_contract_in_imports(base_name, Some(&file_path))?
                    {
                        // Register the newly found contract
                        self.register_contract(contract_info);

                        // Get the qualified name and resolve its inheritance
                        let new_qualified_name = self.get_qualified_name_for_contract(base_name);
                        if !visited.contains(&new_qualified_name) {
                            self.resolve_contract_inheritance(
                                &new_qualified_name,
                                visited,
                                temp_visited,
                            )?;
                        }
                        qualified_bases.push(new_qualified_name);

                        // Remove from missing contracts if it was there
                        self.missing_contracts.remove(base_name);
                    } else {
                        // Still not found after dynamic loading attempt
                        self.missing_contracts.insert(base_name.clone());
                    }
                } else {
                    // No file context, can't load imports
                    self.missing_contracts.insert(base_name.clone());
                }
            }
        }

        // Use C3 linearization to compute the inheritance chain
        let inheritance_chain = if !qualified_bases.is_empty() {
            // Create a closure to get linearization of base contracts
            let get_linearization = |base: &str| -> Result<Vec<String>, String> {
                self.contracts
                    .get(base)
                    .map(|c| c.inheritance_chain.clone())
                    .ok_or_else(|| format!("Contract {} not found", base))
            };

            // Perform C3 linearization
            match c3_linearize(contract_name, &qualified_bases, get_linearization) {
                Ok(chain) => chain,
                Err(_e) => {
                    // Fallback to simple linearization (better than nothing)
                    let mut simple_chain = Vec::new();
                    for base in &qualified_bases {
                        if let Some(base_contract) = self.contracts.get(base) {
                            // Add base's chain
                            for inherited in &base_contract.inheritance_chain {
                                if !simple_chain.contains(inherited) {
                                    simple_chain.push(inherited.clone());
                                }
                            }
                            // Add base itself
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

        // Update the contract's inheritance chain
        if let Some(contract) = self.contracts.get_mut(contract_name) {
            contract.inheritance_chain = inheritance_chain;
        }

        temp_visited.remove(contract_name);
        visited.insert(contract_name.to_string());

        Ok(())
    }

    /// Public query methods

    /// Get inheritance chain for a contract
    pub fn get_inheritance_chain(&self, contract: &str) -> Option<&[String]> {
        self.contracts
            .get(contract)
            .map(|c| c.inheritance_chain.as_slice())
    }

    /// Register a contract using qualified name as key
    fn register_contract(&mut self, contract: ContractInfo) {
        let qualified_name = format!("{}:{}", contract.file_path, contract.name);
        self.contracts.insert(qualified_name, contract);
    }

    /// Get contract by qualified name ("file_path:contract_name")
    pub fn get_contract(&self, qualified_name: &str) -> Option<&ContractInfo> {
        self.contracts.get(qualified_name)
    }

    /// Load a file dynamically from an import path
    fn load_imported_file(
        &mut self,
        import_path: &str,
        current_file: &Path,
    ) -> Result<bool, String> {
        // Check if we have an import resolver
        let resolver = match &self.import_resolver {
            Some(r) => r.clone(),
            None => return Ok(false), // No resolver, can't load imports
        };

        // Try to resolve the import path
        let resolved_path = match resolver.resolve_import(import_path, current_file) {
            Ok(path) => path,
            Err(_e) => {
                return Ok(false);
            }
        };

        // Check if already loaded
        if self.files.iter().any(|f| f.path == resolved_path) {
            return Ok(false); // Already loaded
        }

        // Load the file
        self.load_file(&resolved_path)?;

        // Extract and register contracts from the newly loaded file
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

    /// Find a contract by name in imported files
    fn find_contract_in_imports(
        &mut self,
        contract_name: &str,
        current_file: Option<&Path>,
    ) -> Result<Option<ContractInfo>, String> {
        // First, search through all loaded files
        for file in &self.files {
            for contract in &file.contract_definitions {
                if contract.name == contract_name {
                    // Found the contract, return a clone
                    return Ok(Some(contract.clone()));
                }
            }
        }

        // If we have a current file context, try to load its imports
        if let Some(current) = current_file {
            // Get the imports from the current file
            let imports: Vec<_> = self
                .files
                .iter()
                .find(|f| f.path == current)
                .map(|f| f.imports.clone())
                .unwrap_or_default();

            // Try each import
            for import_info in imports {
                // Try to load the imported file
                if self.load_imported_file(&import_info.import_path, current)? {
                    // Search again in the newly loaded files
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

    /// Get qualified name for a contract (tries to find it in loaded contracts)
    fn get_qualified_name_for_contract(&self, contract_name: &str) -> String {
        // First, check if it's already a qualified name
        if contract_name.contains(':') {
            return contract_name.to_string();
        }

        // Search for the contract in our files to get its file path
        for file in &self.files {
            for contract in &file.contract_definitions {
                if contract.name == contract_name {
                    return format!("{}:{}", contract.file_path, contract.name);
                }
            }
        }

        // If not found, return the name as-is (will be handled as missing)
        contract_name.to_string()
    }

    /// Get all state variables from a contract including inherited ones
    /// Returns variables in inheritance order (base contracts first, derived last)
    /// This matches Solidity's storage layout where base contract variables come first
    pub fn get_all_state_variables(&self, contract_name: &str) -> Vec<String> {
        let mut all_variables = Vec::new();

        // Get the contract (try both as qualified name and search by simple name)
        let contract = if let Some(contract) = self.contracts.get(contract_name) {
            contract
        } else {
            // Try to find by simple name
            let qualified_name = self.get_qualified_name_for_contract(contract_name);
            if let Some(contract) = self.contracts.get(&qualified_name) {
                contract
            } else {
                return all_variables; // Contract not found
            }
        };

        // Add state variables from inheritance chain
        // The chain is now in correct order (most base to most derived)
        // So we traverse it as-is to get proper storage layout order
        for inherited_contract_name in &contract.inheritance_chain {
            if let Some(inherited_contract) = self.contracts.get(inherited_contract_name) {
                all_variables.extend(inherited_contract.state_variables.clone());
            }
        }

        // Finally, add state variables from the contract itself (most derived)
        all_variables.extend(contract.state_variables.clone());

        // TODO: Handle variable shadowing and visibility modifiers
        // Currently returns all variables including potentially shadowed ones

        all_variables
    }

    /// Check if a contract inherits from a specific base contract
    /// Searches through the entire inheritance chain for a pattern match
    pub fn inherits_from(&self, contract_name: &str, base_pattern: &str) -> bool {
        // Get the contract (try both as qualified name and search by simple name)
        let contract = if let Some(contract) = self.contracts.get(contract_name) {
            contract
        } else {
            // Try to find by simple name
            let qualified_name = self.get_qualified_name_for_contract(contract_name);
            if let Some(contract) = self.contracts.get(&qualified_name) {
                contract
            } else {
                return false; // Contract not found
            }
        };

        // Check if any contract in the inheritance chain matches the pattern
        contract.inheritance_chain.iter().any(|inherited| {
            // Check if the inherited contract name contains the pattern
            // This handles cases like "Ownable", "Ownable2Step", etc.
            inherited.contains(base_pattern)
        })
    }

    /// Check if a contract inherits from a base - using contract definition and file directly
    /// This is the preferred method for detectors to use
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
                .any(|f| f == function_name)
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
