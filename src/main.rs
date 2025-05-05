mod config;
mod core;
mod detectors;
mod models;
mod output;
mod utils;

use crate::config::{initialize_config_file, load_config, Config};
use crate::core::engine::AnalysisEngine;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "weasel")]
#[command(about = "Smart Contract Static Analysis Tool for Solidity")]
#[command(version = core::version())]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Analyze {
        #[arg(short, long)]
        scope: Option<Vec<PathBuf>>,

        #[arg(short, long)]
        min_severity: Option<String>,

        #[arg(short, long)]
        format: Option<String>,

        #[arg(short, long, value_name = "REPORT_FILE_NAME")]
        output: Option<PathBuf>,

        #[arg(short, long, value_name = "PATH_TO_CONFIG")]
        config: Option<PathBuf>,
    },
    Detectors {
        #[arg(short, long)]
        severity: Option<String>,

        #[arg(short, long)]
        details: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => match initialize_config_file(None) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error during initialization: {}", e);
                std::process::exit(1);
            }
        },

        Commands::Analyze {
            scope,
            min_severity,
            format,
            output,
            config,
        } => {
            let config = load_config(scope, min_severity, format, config);

            let mut engine = AnalysisEngine::new(&config);
            engine.register_built_in_detectors();

            match engine.analyze() {
                Ok(mut report) => {
                    report = report.with_comment(
                        "This analysis was performed with the Weasel Static Analysis Tool.",
                    );
                    report = report.with_footnote("Note: This tool is in development. For questions or feedback, please contact the Weasel team.");

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

        Commands::Detectors { severity, details } => {
            let config = Config::default();
            let mut engine = AnalysisEngine::new(&config);
            engine.register_built_in_detectors();
            let registry = engine.registry();

            if let Some(detector_id) = details {
                if let Some(detector) = registry.get(&detector_id) {
                    println!("{}", detector);
                } else {
                    eprintln!("Error: Detector with ID '{}' not found.", detector_id);
                }
                return;
            }

            let detectors = if let Some(sev_str) = &severity {
                match sev_str.parse() {
                    Ok(sev) => {
                        println!("\nAvailable detectors filtered by severity: {}", sev);
                        registry.get_by_severity(&sev)
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        eprintln!("Acceptable values: high, medium, low, gas, nc");
                        std::process::exit(1);
                    }
                }
            } else {
                println!("\nAvailable detectors (Total: {}):", registry.count());
                registry.get_all()
            };

            if detectors.is_empty() {
                println!("No detectors found");
            } else {
                for detector in detectors {
                    println!(
                        "({}) - {}: {}",
                        detector.severity(),
                        detector.id(),
                        detector.name(),
                    );
                }
            }
        }
    }
}
