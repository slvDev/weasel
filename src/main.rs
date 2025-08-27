mod cli;
mod config;
mod core;
mod detectors;
mod models;
mod output;
mod utils;

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
    Run {
        #[arg(short, long)]
        scope: Option<Vec<PathBuf>>,

        #[arg(short, long)]
        exclude: Option<Vec<PathBuf>>,

        #[arg(short, long)]
        min_severity: Option<String>,

        #[arg(short, long)]
        format: Option<String>,

        #[arg(short, long, value_name = "REPORT_FILE_NAME")]
        output: Option<PathBuf>,

        #[arg(short, long, value_name = "PATH_TO_CONFIG")]
        config: Option<PathBuf>,

        #[arg(short, long)]
        remappings: Option<Vec<String>>,
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
        Commands::Init => {
            cli::init::handle_init_command();
        }
        Commands::Run {
            scope,
            exclude,
            min_severity,
            format,
            output,
            config,
            remappings,
        } => {
            cli::run::handle_run_command(
                scope,
                exclude,
                min_severity,
                format,
                output,
                config,
                remappings,
            );
        }
        Commands::Detectors { severity, details } => {
            cli::detectors::handle_detectors_command(severity, details);
        }
    }
}
