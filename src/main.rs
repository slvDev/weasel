// Weasel - Smart Contract Static Analysis Tool
// Entry point for the CLI application

mod core;
mod detectors;
mod models;
mod output;
mod utils;

use crate::core::engine::AnalysisEngine;
use crate::output::ReportFormat;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Smart Contract Static Analysis Tool
#[derive(Parser)]
#[command(name = "weasel")]
#[command(about = "Smart Contract Static Analysis Tool for Solidity")]
#[command(version = core::version())]
struct Cli {
    /// Subcommand to execute
    #[command(subcommand)]
    command: Commands,
}

/// Available commands
#[derive(Subcommand)]
enum Commands {
    /// Analyze smart contracts for vulnerabilities
    Analyze {
        /// Directory or file paths to analyze
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// Path to output report file
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Report format (json, md)
        #[arg(short, long, default_value = "json")]
        format: String,
    },
    /// List available detectors
    Detectors {
        /// Filter by severity level
        #[arg(short, long)]
        severity: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze {
            paths,
            output,
            format,
        } => {
            println!("Analyzing {:?} paths", paths.len());
            println!(
                "Output: {:?}",
                output
                    .as_deref()
                    .unwrap_or_else(|| std::path::Path::new("stdout"))
            );
            println!("Format: {}", format);

            // Create the analysis engine
            let mut engine = AnalysisEngine::new();

            // Register built-in detectors
            engine.register_built_in_detectors();

            // Run the analysis
            match engine.analyze(paths) {
                Ok(mut report) => {
                    // Add a comment about the analysis
                    report = report.with_comment(
                        "This analysis was performed with the Weasel Static Analysis Tool.",
                    );

                    // Add a footnote
                    report = report.with_footnote("Note: This tool is in development. For questions or feedback, please contact the Weasel team.");

                    // Generate the report
                    let report_format = match format.as_str() {
                        "json" => ReportFormat::Json,
                        "md" | "markdown" => ReportFormat::Markdown,
                        _ => {
                            eprintln!("Unsupported format: {}. Using JSON instead.", format);
                            ReportFormat::Json
                        }
                    };

                    // Output the report
                    if let Err(e) =
                        output::generate_report(&report, &report_format, output.as_deref())
                    {
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
        Commands::Detectors { severity } => {
            let mut engine = AnalysisEngine::new();
            engine.register_built_in_detectors();
            let registry = engine.registry();

            let detectors = if let Some(sev_str) = &severity {
                // Convert string to Severity enum
                let sev = match sev_str.to_lowercase().as_str() {
                    "high" => Some(crate::models::Severity::High),
                    "medium" => Some(crate::models::Severity::Medium),
                    "low" => Some(crate::models::Severity::Low),
                    "gas" => Some(crate::models::Severity::Gas),
                    "nc" => Some(crate::models::Severity::NC),
                    _ => None,
                };

                if let Some(s) = sev {
                    println!("Detectors filtered by severity: {}", s);
                    registry.get_by_severity(&s)
                } else {
                    println!("Invalid severity: {}.", sev_str);
                    println!("Acceptable severities are: high, medium, low, gas, nc");
                    Vec::new()
                }
            } else {
                println!("\nAvailable detectors:");
                registry.get_all()
            };

            for detector in detectors {
                println!(
                    "- {}: {} ({})",
                    detector.id(),
                    detector.name(),
                    detector.severity()
                );
            }
        }
    }
}
