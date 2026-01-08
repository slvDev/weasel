use crate::config::load_config;
use crate::core::engine::AnalysisEngine;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

pub fn execute_analyze(arguments: &Value) -> Result<Value, JsonRpcError> {
    let path = arguments
        .get("path")
        .and_then(|v| v.as_str())
        .map(PathBuf::from);

    // Validate path exists if provided
    if let Some(ref p) = path {
        if !p.exists() {
            return Err(JsonRpcError {
                code: -32602,
                message: format!("Path not found: {}", p.display()),
                data: None,
            });
        }
    }

    let severity = arguments
        .get("severity")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let exclude: Option<Vec<PathBuf>> = arguments
        .get("exclude")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(PathBuf::from))
                .collect()
        });

    let scope = path.map(|p| vec![p]);
    let config = load_config(scope, exclude, severity, None, None, None);

    let mut engine = AnalysisEngine::new(&config);
    engine.register_built_in_detectors();

    match engine.analyze() {
        Ok(report) => {
            // Count by severity
            let mut counts: HashMap<String, usize> = HashMap::new();
            for finding in &report.findings {
                *counts
                    .entry(format!("{:?}", finding.severity))
                    .or_default() += finding.locations.len();
            }

            // Build compact output
            let mut output = String::new();

            // Summary line
            if report.findings.is_empty() {
                output.push_str("Found: 0 issues\n");
            } else {
                let mut parts = Vec::new();
                for sev in &["High", "Medium", "Low", "Gas", "NC"] {
                    if let Some(count) = counts.get(*sev) {
                        if *count > 0 {
                            parts.push(format!("{} {}", count, sev));
                        }
                    }
                }
                output.push_str(&format!("Found: {}\n\n", parts.join(", ")));

                // Compact one-liner per finding
                for finding in &report.findings {
                    let sev_char = match format!("{:?}", finding.severity).as_str() {
                        "High" => "H",
                        "Medium" => "M",
                        "Low" => "L",
                        "Gas" => "G",
                        "NC" => "NC",
                        _ => "?",
                    };

                    let detector_id = &finding.detector_id;

                    // Short description (first 60 chars)
                    let short_desc: String = finding
                        .description
                        .chars()
                        .take(60)
                        .collect::<String>()
                        .split('\n')
                        .next()
                        .unwrap_or("")
                        .to_string();

                    for location in &finding.locations {
                        output.push_str(&format!(
                            "[{}] {} | {}:{} | {}\n",
                            sev_char,
                            detector_id,
                            location.file,
                            location.line,
                            short_desc
                        ));
                    }
                }
            }

            Ok(json!({
                "content": [
                    {
                        "type": "text",
                        "text": output
                    }
                ]
            }))
        }
        Err(e) => Err(JsonRpcError {
            code: -32000,
            message: format!("Analysis failed: {}", e),
            data: None,
        }),
    }
}

pub fn execute_finding_details(arguments: &Value) -> Result<Value, JsonRpcError> {
    let detector = arguments
        .get("detector")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "Missing 'detector' parameter".to_string(),
            data: None,
        })?;

    let path = arguments
        .get("path")
        .and_then(|v| v.as_str())
        .map(PathBuf::from);

    // Validate path exists if provided
    if let Some(ref p) = path {
        if !p.exists() {
            return Err(JsonRpcError {
                code: -32602,
                message: format!("Path not found: {}", p.display()),
                data: None,
            });
        }
    }

    let scope = path.map(|p| vec![p]);
    let config = load_config(scope, None, None, None, None, None);

    let mut engine = AnalysisEngine::new(&config);
    engine.register_built_in_detectors();

    match engine.analyze() {
        Ok(report) => {
            // Find matching finding by detector_id
            let matching: Vec<_> = report
                .findings
                .iter()
                .filter(|f| f.detector_id == detector)
                .collect();

            if matching.is_empty() {
                return Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": format!("No findings found for detector: {}", detector)
                    }]
                }));
            }

            let mut output = format!("# Finding Details: {}\n\n", detector);

            for finding in matching {
                output.push_str(&format!("## {}\n\n", finding.title));
                output.push_str(&format!("**Severity:** {:?}\n\n", finding.severity));
                output.push_str(&format!("**Description:** {}\n\n", finding.description));

                if let Some(example) = &finding.example {
                    output.push_str(&format!(
                        "**Example:**\n```solidity\n{}\n```\n\n",
                        example
                    ));
                }

                output.push_str("### Locations\n\n");
                for location in &finding.locations {
                    output.push_str(&format!("**{}:{}**\n", location.file, location.line));
                    if let Some(snippet) = &location.snippet {
                        output.push_str(&format!("```solidity\n{}\n```\n\n", snippet.trim()));
                    }
                }
            }

            Ok(json!({
                "content": [{
                    "type": "text",
                    "text": output
                }]
            }))
        }
        Err(e) => Err(JsonRpcError {
            code: -32000,
            message: format!("Analysis failed: {}", e),
            data: None,
        }),
    }
}

pub fn execute_detectors(arguments: &Value) -> Result<Value, JsonRpcError> {
    let severity_filter = arguments
        .get("severity")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Create a temporary engine to get detector list
    let config = load_config(None, None, severity_filter, None, None, None);
    let mut engine = AnalysisEngine::new(&config);
    engine.register_built_in_detectors();

    let detectors = engine.get_detector_info();

    // Group by severity
    let mut by_severity: HashMap<String, Vec<_>> = HashMap::new();
    for detector in &detectors {
        by_severity
            .entry(detector.severity.clone())
            .or_default()
            .push(detector);
    }

    // Compact format: ID + short name grouped by severity
    let mut output = format!("Detectors: {}\n\n", detectors.len());

    for severity in &["High", "Medium", "Low", "Gas", "NC"] {
        if let Some(dets) = by_severity.get(*severity) {
            output.push_str(&format!("[{}]\n", severity));
            for d in dets {
                output.push_str(&format!("  {}: {}\n", d.id, d.name));
            }
            output.push('\n');
        }
    }

    output.push_str("Use weasel_finding_details with detector ID for full description.");

    Ok(json!({
        "content": [
            {
                "type": "text",
                "text": output
            }
        ]
    }))
}
