use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub enum ProjectType {
    Foundry, // foundry.toml detected
    Hardhat, // hardhat.config.js or hardhat.config.ts detected
    Truffle, // truffle-config.js detected
    Custom,  // Manual configuration
}

#[derive(Debug, Clone)]
pub struct ProjectConfig {
    pub project_type: ProjectType,
    pub remappings: HashMap<String, PathBuf>,
    pub library_paths: Vec<PathBuf>,
    pub project_root: PathBuf,
    pub default_scope: Vec<PathBuf>,
}

#[derive(Debug, Deserialize, Default)]
struct FoundryToml {
    #[serde(default)]
    profile: FoundryProfiles,
    #[serde(default)]
    remappings: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct FoundryProfiles {
    #[serde(default)]
    default: FoundryProfile,
}

#[derive(Debug, Deserialize)]
struct FoundryProfile {
    #[serde(default = "default_src")]
    src: String,
    #[serde(default = "default_libs")]
    libs: Vec<String>,
    #[serde(default)]
    remappings: Vec<String>,
}

fn default_src() -> String {
    "src".to_string()
}

fn default_libs() -> Vec<String> {
    vec!["lib".to_string()]
}

impl Default for FoundryProfile {
    fn default() -> Self {
        Self {
            src: default_src(),
            libs: default_libs(),
            remappings: Vec::new(),
        }
    }
}

impl ProjectConfig {
    /// Auto-detect project configuration from the given root directory
    pub fn auto_detect(root: &Path) -> Result<ProjectConfig, String> {
        let project_type = Self::detect_project_type(root);
        let project_root = root.to_path_buf();

        match project_type {
            ProjectType::Foundry => Self::load_foundry_config(&project_root),
            ProjectType::Hardhat => Self::load_hardhat_config(&project_root),
            ProjectType::Truffle => Self::load_truffle_config(&project_root),
            ProjectType::Custom => Self::load_default_config(&project_root),
        }
    }

    /// Create project config from manual settings
    pub fn from_manual_config(
        project_root: PathBuf,
        remappings: HashMap<String, PathBuf>,
        library_paths: Vec<PathBuf>,
        default_scope: Vec<PathBuf>,
    ) -> ProjectConfig {
        ProjectConfig {
            project_type: ProjectType::Custom,
            remappings,
            library_paths,
            project_root,
            default_scope,
        }
    }

    /// Load remappings with clear precedence order
    pub fn load_remappings_with_precedence(
        project_root: &Path,
        manual_remappings: &HashMap<String, String>,
    ) -> Result<HashMap<String, PathBuf>, String> {
        let mut final_remappings = HashMap::new();

        // Load in reverse precedence order (later overwrites earlier)

        // 1. Auto-detected defaults (lowest priority)
        final_remappings.extend(Self::parse_default_remappings(project_root)?);

        // 2. remappings.txt (legacy support)
        final_remappings.extend(Self::parse_remappings_txt(project_root)?);

        // 3. foundry.toml remappings (project-specific)
        final_remappings.extend(Self::parse_foundry_remappings(project_root)?);

        // 4. Manual config (highest priority)
        final_remappings.extend(
            manual_remappings
                .iter()
                .map(|(k, v)| (k.clone(), PathBuf::from(v))),
        );

        Ok(final_remappings)
    }

    /// Detect project type based on configuration files
    fn detect_project_type(root: &Path) -> ProjectType {
        if root.join("foundry.toml").exists() {
            return ProjectType::Foundry;
        }

        if root.join("hardhat.config.js").exists() || root.join("hardhat.config.ts").exists() {
            return ProjectType::Hardhat;
        }

        if root.join("truffle-config.js").exists() {
            return ProjectType::Truffle;
        }

        ProjectType::Custom
    }

    /// Load Foundry project configuration
    fn load_foundry_config(project_root: &PathBuf) -> Result<ProjectConfig, String> {
        let foundry_toml_path = project_root.join("foundry.toml");

        let foundry_toml = if foundry_toml_path.exists() {
            let content = fs::read_to_string(&foundry_toml_path)
                .map_err(|e| format!("Failed to read foundry.toml: {}", e))?;

            toml::from_str::<FoundryToml>(&content)
                .map_err(|e| format!("Failed to parse foundry.toml: {}", e))?
        } else {
            FoundryToml::default()
        };

        // Get profile.default settings
        let profile = &foundry_toml.profile.default;

        // Collect remappings from both root-level and profile-level
        let mut remappings = HashMap::new();

        // root-level remappings
        for remapping in &foundry_toml.remappings {
            if let Some((from, to)) = remapping.split_once('=') {
                let to_path = if to.starts_with('/') {
                    PathBuf::from(to)
                } else {
                    project_root.join(to)
                };
                remappings.insert(from.to_string(), to_path);
            }
        }

        // profile-level remappings
        for remapping in &profile.remappings {
            if let Some((from, to)) = remapping.split_once('=') {
                let to_path = if to.starts_with('/') {
                    PathBuf::from(to)
                } else {
                    project_root.join(to)
                };
                remappings.insert(from.to_string(), to_path);
            }
        }

        // Library paths from profile config
        let library_paths: Vec<PathBuf> = profile.libs.iter().map(|s| PathBuf::from(s)).collect();

        let default_scope = if profile.src.is_empty() {
            vec![PathBuf::from("src")]
        } else {
            vec![PathBuf::from(&profile.src)]
        };

        Ok(ProjectConfig {
            project_type: ProjectType::Foundry,
            remappings,
            library_paths,
            project_root: project_root.clone(),
            default_scope,
        })
    }

    /// Load Hardhat project configuration
    fn load_hardhat_config(project_root: &PathBuf) -> Result<ProjectConfig, String> {
        let library_paths = vec![PathBuf::from("node_modules")];
        let default_scope = vec![PathBuf::from("contracts")];

        let mut remappings = HashMap::new();
        let openzeppelin_path = project_root.join("node_modules/@openzeppelin");
        if openzeppelin_path.exists() {
            remappings.insert("@openzeppelin/".to_string(), openzeppelin_path);
        }

        Ok(ProjectConfig {
            project_type: ProjectType::Hardhat,
            remappings,
            library_paths,
            project_root: project_root.clone(),
            default_scope,
        })
    }

    /// Load Truffle project configuration
    fn load_truffle_config(project_root: &PathBuf) -> Result<ProjectConfig, String> {
        let library_paths = vec![PathBuf::from("node_modules")];
        let remappings = HashMap::new();
        let default_scope = vec![PathBuf::from("contracts")];

        Ok(ProjectConfig {
            project_type: ProjectType::Truffle,
            remappings,
            library_paths,
            project_root: project_root.clone(),
            default_scope,
        })
    }

    /// Load default configuration for unrecognized projects
    fn load_default_config(project_root: &PathBuf) -> Result<ProjectConfig, String> {
        let library_paths = vec![PathBuf::from("lib"), PathBuf::from("node_modules")];
        let remappings = HashMap::new();
        let default_scope = vec![PathBuf::from("src")];

        Ok(ProjectConfig {
            project_type: ProjectType::Custom,
            remappings,
            library_paths,
            project_root: project_root.clone(),
            default_scope,
        })
    }

    /// Parse default remappings (common conventions)
    fn parse_default_remappings(project_root: &Path) -> Result<HashMap<String, PathBuf>, String> {
        let mut remappings = HashMap::new();

        // Common default remappings if directories exist
        let common_remappings = [
            ("@openzeppelin/", "lib/openzeppelin-contracts/contracts/"),
            ("@solmate/", "lib/solmate/src/"),
            ("ds-test/", "lib/ds-test/src/"),
            ("forge-std/", "lib/forge-std/src/"),
        ];

        for (prefix, path) in &common_remappings {
            let full_path = project_root.join(path);
            if full_path.exists() {
                remappings.insert(prefix.to_string(), full_path);
            }
        }

        Ok(remappings)
    }

    /// Parse remappings.txt file (legacy Foundry support)
    fn parse_remappings_txt(project_root: &Path) -> Result<HashMap<String, PathBuf>, String> {
        let remappings_path = project_root.join("remappings.txt");
        let mut remappings = HashMap::new();

        if remappings_path.exists() {
            let content = fs::read_to_string(&remappings_path)
                .map_err(|e| format!("Failed to read remappings.txt: {}", e))?;

            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                if let Some((from, to)) = line.split_once('=') {
                    let to_path = if to.starts_with('/') {
                        PathBuf::from(to)
                    } else {
                        project_root.join(to)
                    };
                    remappings.insert(from.to_string(), to_path);
                }
            }
        }

        Ok(remappings)
    }

    /// Parse remappings from foundry.toml
    fn parse_foundry_remappings(project_root: &Path) -> Result<HashMap<String, PathBuf>, String> {
        let foundry_toml_path = project_root.join("foundry.toml");

        if !foundry_toml_path.exists() {
            return Ok(HashMap::new());
        }

        let content = fs::read_to_string(&foundry_toml_path)
            .map_err(|e| format!("Failed to read foundry.toml: {}", e))?;

        let foundry_toml: FoundryToml =
            toml::from_str(&content).map_err(|e| format!("Failed to parse foundry.toml: {}", e))?;

        let mut remappings = HashMap::new();

        // root-level remappings
        for remapping in &foundry_toml.remappings {
            if let Some((from, to)) = remapping.split_once('=') {
                let to_path = if to.starts_with('/') {
                    PathBuf::from(to)
                } else {
                    project_root.join(to)
                };
                remappings.insert(from.to_string(), to_path);
            }
        }

        // profile.default remappings
        for remapping in &foundry_toml.profile.default.remappings {
            if let Some((from, to)) = remapping.split_once('=') {
                let to_path = if to.starts_with('/') {
                    PathBuf::from(to)
                } else {
                    project_root.join(to)
                };
                remappings.insert(from.to_string(), to_path);
            }
        }

        Ok(remappings)
    }
}

// Note: Project detection and configuration loading is tested through
// integration tests when AnalysisEngine initializes projects. Direct
// unit tests would require creating temporary project structures with
// the tempfile crate (not currently a dependency). The functionality
// is validated through actual project analysis in the engine.
