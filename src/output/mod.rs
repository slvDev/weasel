use crate::models::finding::Location;
use crate::models::Report;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Clone, Deserialize, Default)]
pub enum ReportFormat {
    Json,
    #[default]
    Markdown,
}

impl FromStr for ReportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(ReportFormat::Json),
            "md" | "markdown" => Ok(ReportFormat::Markdown),
            _ => Err(format!("Invalid report format: {}", s)),
        }
    }
}

impl fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReportFormat::Json => write!(f, "Json"),
            ReportFormat::Markdown => write!(f, "Markdown"),
        }
    }
}

pub fn generate_report(
    report: &Report,
    format: &ReportFormat,
    output: Option<PathBuf>,
) -> io::Result<()> {
    match format {
        ReportFormat::Json => {
            if let Some(path) = output {
                let path_with_extension = path.with_extension("json");
                let file = File::create(path_with_extension)?;
                serde_json::to_writer_pretty(file, report)?;
            } else {
                let stdout = io::stdout();
                let handle = stdout.lock();
                serde_json::to_writer_pretty(handle, report)?;
            }
        }
        ReportFormat::Markdown => {
            let markdown = generate_markdown_report(report);

            if let Some(path) = output {
                let path_with_extension = path.with_extension("md");
                let mut file = File::create(path_with_extension)?;
                write!(file, "{}", markdown)?;
            } else {
                println!("{}", markdown);
            }
        }
    }

    Ok(())
}

/// Generate a markdown report
fn generate_markdown_report(report: &Report) -> String {
    let mut markdown = String::new();

    // Add title
    markdown.push_str("# Smart Contract Analysis Report\n\n");

    // Add metadata if present
    if let Some(metadata) = &report.metadata {
        markdown.push_str("## Metadata\n\n");
        for (key, value) in metadata {
            markdown.push_str(&format!("- **{}**: {}\n", key, value));
        }
        markdown.push_str("\n");
    }

    // Add comment if present
    if !report.comment.is_empty() {
        markdown.push_str(&format!("## Overview\n\n{}\n\n", report.comment));
    }

    // Add summary
    let summary = report.summary();
    markdown.push_str("## Summary\n\n");
    markdown.push_str(&format!("- **High**: {}\n", summary.high));
    markdown.push_str(&format!("- **Medium**: {}\n", summary.medium));
    markdown.push_str(&format!("- **Low**: {}\n", summary.low));
    markdown.push_str(&format!("- **Gas**: {}\n", summary.gas));
    markdown.push_str(&format!("- **NC**: {}\n", summary.nc));
    markdown.push_str(&format!("- **Total**: {}\n\n", summary.total));

    // Add findings
    if !report.findings.is_empty() {
        markdown.push_str("## Findings\n\n");

        for (i, finding) in report.findings.iter().enumerate() {
            // Finding header with severity
            markdown.push_str(&format!(
                "### {}. {} ({})\n\n",
                i + 1,
                finding.title,
                finding.severity
            ));

            // Description
            markdown.push_str(&format!("**Description**:\n{}\n\n", finding.description));

            // Gas savings if applicable
            if let Some(gas) = finding.gas_savings {
                markdown.push_str(&format!("**Gas Savings**: {} gas\n\n", gas));
            }

            // Example code if present
            if let Some(example) = &finding.example {
                markdown.push_str(&format!("**Recommendation**:\n{}\n\n", example));
            }

            // **Locations - Grouped by file**
            if !finding.locations.is_empty() {
                // Group locations by file path
                let mut locations_by_file: HashMap<String, Vec<&Location>> = HashMap::new();
                for loc in &finding.locations {
                    locations_by_file
                        .entry(loc.file.clone())
                        .or_default()
                        .push(loc);
                }

                let num_files = locations_by_file.len();
                let file_plural = if num_files == 1 { "file" } else { "files" };
                let total_instances = finding.locations.len();
                let instance_plural = if total_instances == 1 {
                    "instance"
                } else {
                    "instances"
                };

                // Use <details> for collapsibility
                markdown.push_str(&format!(
                    "<details>\n<summary><i>{} {} in {} {}</i></summary>\n\n",
                    total_instances, instance_plural, num_files, file_plural
                ));

                // Iterate through each file group
                for (file_path, locations_in_file) in &locations_by_file {
                    markdown.push_str("```solidity\n"); // Start code block for the file
                    markdown.push_str(&format!("File: {}\n\n", file_path));

                    // Print each location within the file
                    for loc in locations_in_file {
                        let snippet = loc.snippet.as_deref().unwrap_or("..."); // Use snippet or fallback
                        markdown.push_str(&format!("{}: {}\n", loc.line, snippet));
                    }

                    markdown.push_str("```\n"); // End code block for the file
                    markdown.push_str("\n"); // Add a newline after the code block
                }

                markdown.push_str("</details>\n\n"); // Close details tag
            }

            markdown.push_str("---\n\n");
        }
    } else {
        markdown.push_str("## Findings\n\n");
        markdown.push_str("No issues found.\n\n");
    }

    // Add footnote if present
    if !report.footnote.is_empty() {
        markdown.push_str(&format!("## Note\n\n{}\n", report.footnote));
    }

    markdown
}
