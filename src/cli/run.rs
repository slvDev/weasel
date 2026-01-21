use crate::config::load_config;
use crate::core::engine::AnalysisEngine;
use crate::output;
use std::path::PathBuf;

pub fn handle_run_command(
    scope: Option<Vec<PathBuf>>,
    exclude: Option<Vec<PathBuf>>,
    min_severity: Option<String>,
    format: Option<String>,
    output: Option<PathBuf>,
    config_path: Option<PathBuf>,
    remappings: Option<Vec<String>>,
    exclude_detectors: Option<Vec<String>>,
) {
    let config = load_config(
        scope,
        exclude,
        min_severity,
        format,
        remappings,
        config_path,
        exclude_detectors,
    );

    let mut engine = AnalysisEngine::new(&config);
    engine.register_built_in_detectors();

    match engine.analyze() {
        Ok(report) => {
            println!(
                "Analysis complete: {} findings",
                report.findings.iter().map(|f| f.locations.len()).sum::<usize>()
            );
            if let Err(e) = output::generate_report(&report, &config.format, output) {
                eprintln!("Error generating report: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error during analysis: {}", e);
            std::process::exit(1);
        }
    }
}
