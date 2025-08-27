use crate::models::Severity;
use crate::output::ReportFormat;
use serde::Deserialize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_CONTENT: &str = r#"# weasel.toml

# Paths to include in the analysis.
# If omitted, it defaults to ["src"]
# scope = ["src"]

# Paths to exclude from the analysis.
# These can be directories (including subdirectories) or specific files.
# If omitted, it defaults to [] (no exclusions)
# exclude = ["lib", "test"]

# Minimum severity level of detectors to *run* during analysis.
# Only detectors with this severity or higher will be executed.
# Options: "High", "Medium", "Low", "Gas", "NC" (case-insensitive)
# If omitted, it defaults to "NC" (run all detectors).
# min_severity = "NC"

# Output format for the report.
# Options: "json", "md" (or "markdown")
# If omitted, it defaults to "md".
# output_format = "md"

# Manual remappings for import resolution
# Format: "prefix=target_path"
# Example: remappings = ["@openzeppelin/=lib/openzeppelin-contracts/contracts/", "@solmate/=lib/solmate/src/"]
# remappings = [
#     "@openzeppelin/=lib/openzeppelin-contracts/contracts/",
#     "@solmate/=lib/solmate/src/"
# ]
"#;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_scope")]
    pub scope: Vec<PathBuf>,
    #[serde(default = "default_exclude")]
    pub exclude: Vec<PathBuf>,
    #[serde(default)]
    pub min_severity: Severity,
    #[serde(default)]
    pub format: ReportFormat,
    #[serde(default)]
    pub remappings: Vec<String>,
}

fn default_scope() -> Vec<PathBuf> {
    vec![PathBuf::from("src")]
}

fn default_exclude() -> Vec<PathBuf> {
    vec![PathBuf::from("lib"), PathBuf::from("test")]
}

impl Default for Config {
    fn default() -> Self {
        Config {
            scope: default_scope(),
            exclude: default_exclude(),
            min_severity: Severity::default(),
            format: ReportFormat::default(),
            remappings: Vec::new(),
        }
    }
}

pub fn load_config(
    scope: Option<Vec<PathBuf>>,
    exclude: Option<Vec<PathBuf>>,
    min_severity: Option<String>,
    format: Option<String>,
    remappings: Option<Vec<String>>,
    config_path: Option<PathBuf>,
) -> Config {
    let default_path = PathBuf::from("weasel.toml");
    let config_path = config_path.unwrap_or(default_path);

    let config = if !config_path.exists() {
        Config::default()
    } else {
        let content = match fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "Error reading config file '{}': {}",
                    config_path.display(),
                    e
                );
                std::process::exit(1);
            }
        };
        match toml::from_str::<Config>(&content) {
            Ok(config) => config,
            Err(e) => {
                eprintln!(
                    "Error parsing config file '{}': {}",
                    config_path.display(),
                    e
                );
                std::process::exit(1);
            }
        }
    };

    Config {
        scope: scope.unwrap_or(config.scope),
        exclude: exclude.unwrap_or(config.exclude),
        min_severity: min_severity.map_or(config.min_severity, |s| {
            s.parse().unwrap_or_else(|e| {
                eprintln!("Warning: {}. Using default severity.", e);
                Severity::default()
            })
        }),
        format: format.map_or(config.format, |s| {
            s.parse().unwrap_or_else(|e| {
                eprintln!("Warning: {}. Using default format.", e);
                ReportFormat::default()
            })
        }),
        remappings: remappings.unwrap_or(config.remappings),
    }
}

pub fn initialize_config_file(config_path_override: Option<&Path>) -> Result<(), String> {
    let default_path = Path::new("weasel.toml");
    let config_path = config_path_override.unwrap_or(default_path);

    if config_path.exists() {
        println!("INFO: '{}' already exists.", config_path.display());
        Ok(())
    } else {
        println!(
            "Creating default config file at '{}'",
            config_path.display()
        );
        match fs::File::create(config_path) {
            Ok(mut file) => match file.write_all(DEFAULT_CONFIG_CONTENT.as_bytes()) {
                Ok(_) => {
                    println!(
                        "SUCCESS: Created default '{}' configuration file.",
                        config_path.display()
                    );
                    Ok(())
                }
                Err(e) => Err(format!(
                    "Error writing to '{}': {}",
                    config_path.display(),
                    e
                )),
            },
            Err(e) => Err(format!("Error creating '{}': {}", config_path.display(), e)),
        }
    }
}
