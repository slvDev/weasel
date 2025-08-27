use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub enum ImportError {
    NotFound(String),
    InvalidPath(String),
    CircularDependency(Vec<PathBuf>),
    IoError(String),
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportError::NotFound(path) => write!(f, "Import not found: {}", path),
            ImportError::InvalidPath(path) => write!(f, "Invalid import path: {}", path),
            ImportError::CircularDependency(cycle) => {
                write!(
                    f,
                    "Circular dependency detected: {}",
                    cycle
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(" -> ")
                )
            }
            ImportError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImportResolver {
    remappings: HashMap<String, PathBuf>,
    library_paths: Vec<PathBuf>,
    project_root: PathBuf,
}

impl ImportResolver {
    pub fn new(project_root: PathBuf) -> Self {
        Self {
            remappings: HashMap::new(),
            library_paths: vec![PathBuf::from("lib"), PathBuf::from("node_modules")],
            project_root,
        }
    }

    /// Set remappings with clear precedence handling
    pub fn set_remappings(&mut self, remappings: HashMap<String, PathBuf>) {
        self.remappings = remappings;
    }

    /// Add additional library search paths
    pub fn add_library_paths(&mut self, paths: Vec<PathBuf>) {
        self.library_paths.extend(paths);
    }

    /// Resolve an import path to an actual file path
    pub fn resolve_import(
        &self,
        import_path: &str,
        current_file: &Path,
    ) -> Result<PathBuf, ImportError> {
        // 1. Try relative imports first (./Token.sol, ../base/Contract.sol)
        if let Some(resolved) = self.resolve_relative_import(import_path, current_file)? {
            return Ok(resolved);
        }

        // 2. Try remappings (@openzeppelin/ -> lib/openzeppelin-contracts/contracts/)
        if let Some(resolved) = self.resolve_remapped_import(import_path)? {
            return Ok(resolved);
        }

        // 3. Try library paths (lib/, node_modules/)
        if let Some(resolved) = self.resolve_library_import(import_path)? {
            return Ok(resolved);
        }

        // 4. Try project root relative
        if let Some(resolved) = self.resolve_project_root_import(import_path)? {
            return Ok(resolved);
        }

        Err(ImportError::NotFound(import_path.to_string()))
    }

    /// Resolve relative imports like "./Token.sol" or "../base/Contract.sol"
    fn resolve_relative_import(
        &self,
        import_path: &str,
        current_file: &Path,
    ) -> Result<Option<PathBuf>, ImportError> {
        if !import_path.starts_with("./") && !import_path.starts_with("../") {
            return Ok(None);
        }

        let current_dir = current_file.parent().ok_or_else(|| {
            ImportError::InvalidPath(format!("Cannot get parent of {}", current_file.display()))
        })?;

        let resolved = current_dir.join(import_path);
        let canonical = self.canonicalize_if_exists(&resolved)?;

        Ok(canonical)
    }

    /// Resolve remapped imports like "@openzeppelin/contracts/token/ERC20/ERC20.sol"
    fn resolve_remapped_import(&self, import_path: &str) -> Result<Option<PathBuf>, ImportError> {
        for (prefix, target_path) in &self.remappings {
            if import_path.starts_with(prefix) {
                let suffix = &import_path[prefix.len()..];
                let resolved = target_path.join(suffix);
                let canonical = self.canonicalize_if_exists(&resolved)?;

                if canonical.is_some() {
                    return Ok(canonical);
                }
            }
        }
        Ok(None)
    }

    /// Resolve library imports from lib/ or node_modules/
    fn resolve_library_import(&self, import_path: &str) -> Result<Option<PathBuf>, ImportError> {
        for lib_path in &self.library_paths {
            let full_lib_path = self.project_root.join(lib_path);
            let resolved = full_lib_path.join(import_path);
            let canonical = self.canonicalize_if_exists(&resolved)?;

            if canonical.is_some() {
                return Ok(canonical);
            }
        }
        Ok(None)
    }

    /// Resolve imports relative to project root
    fn resolve_project_root_import(
        &self,
        import_path: &str,
    ) -> Result<Option<PathBuf>, ImportError> {
        let resolved = self.project_root.join(import_path);
        self.canonicalize_if_exists(&resolved)
    }

    /// Helper to canonicalize path if it exists, handling symlinks
    fn canonicalize_if_exists(&self, path: &Path) -> Result<Option<PathBuf>, ImportError> {
        if path.exists() {
            match fs::canonicalize(path) {
                Ok(canonical) => Ok(Some(canonical)),
                Err(e) => Err(ImportError::IoError(format!(
                    "Cannot canonicalize {}: {}",
                    path.display(),
                    e
                ))),
            }
        } else {
            Ok(None)
        }
    }

    /// Get current remappings for debugging/reporting
    pub fn get_remappings(&self) -> &HashMap<String, PathBuf> {
        &self.remappings
    }

    /// Get library paths for debugging/reporting
    pub fn get_library_paths(&self) -> &[PathBuf] {
        &self.library_paths
    }
}

// Note: Import resolution is tested indirectly through AnalysisContext tests
// in src/core/context.rs where actual file loading and import resolution
// occurs during inheritance chain building. Direct unit tests would require
// filesystem mocking with the tempfile crate (not currently a dependency).
