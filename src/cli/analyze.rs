use crate::config::load_config;
use crate::core::engine::AnalysisEngine;
use crate::output;
use std::path::PathBuf;

// Define a placeholder for a potential custom error type later
pub fn handle_analyze_command(
    scope: Option<Vec<PathBuf>>,
    min_severity: Option<String>,
    format: Option<String>,
    output: Option<PathBuf>,
    config_path: Option<PathBuf>,
) {
    let config = load_config(scope, min_severity, format, config_path);

    let mut engine = AnalysisEngine::new(&config);
    engine.register_built_in_detectors();

    match engine.analyze() {
        Ok(mut report) => {
            report = report
                .with_comment("This analysis was performed with the Weasel Static Analysis Tool.");
            report = report.with_footnote(
                "Note: This tool is in development. For questions or feedback, please contact the Weasel team.",
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
