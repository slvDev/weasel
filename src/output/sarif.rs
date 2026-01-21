use crate::models::{Report, Severity};
use serde_sarif::sarif::{
    self, ArtifactLocation, Message, MultiformatMessageString, PhysicalLocation,
    ReportingDescriptor, Result as SarifResult, ResultLevel, Run, Sarif, ToolComponent, Version,
    SCHEMA_URL,
};
use fnv::FnvHasher;
use std::collections::{BTreeMap, HashMap};
use std::hash::{Hash, Hasher};

/// Convert Weasel Severity to SARIF ResultLevel
fn severity_to_level(severity: &Severity) -> ResultLevel {
    match severity {
        Severity::High => ResultLevel::Error,
        Severity::Medium => ResultLevel::Warning,
        Severity::Low => ResultLevel::Note,
        Severity::Gas => ResultLevel::Note,
        Severity::NC => ResultLevel::Note,
    }
}

/// Convert Weasel Severity to security-severity score (for GitHub)
fn severity_to_score(severity: &Severity) -> &'static str {
    match severity {
        Severity::High => "9.0",
        Severity::Medium => "6.0",
        Severity::Low => "3.0",
        Severity::Gas => "1.0",
        Severity::NC => "0.0",
    }
}

/// Generate a fingerprint hash for tracking results across runs
/// Uses detector_id + file + line + snippet to create stable identifier
/// Note: Uses FnvHasher for stability across Rust versions (DefaultHasher is not guaranteed stable)
fn generate_fingerprint(detector_id: &str, file: &str, line: usize, snippet: Option<&str>) -> String {
    let mut hasher = FnvHasher::default();
    detector_id.hash(&mut hasher);
    file.hash(&mut hasher);
    line.hash(&mut hasher);
    if let Some(s) = snippet {
        // Hash trimmed snippet to avoid whitespace changes affecting fingerprint
        s.trim().hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

/// Generate SARIF report from Weasel Report
pub fn generate_sarif_report(report: &Report) -> Sarif {
    let mut rules: Vec<ReportingDescriptor> = Vec::new();
    let mut rule_indices: HashMap<String, i64> = HashMap::new();
    let mut results: Vec<SarifResult> = Vec::new();

    // Process each finding
    for finding in &report.findings {
        // Register rule if not already registered
        if !rule_indices.contains_key(&finding.detector_id) {
            let rule_index = rules.len() as i64;
            rule_indices.insert(finding.detector_id.clone(), rule_index);

            // Build help text from example/recommendation if available
            let help_text = finding
                .example
                .as_ref()
                .map(|e| format!("**Recommendation:**\n\n{}", e))
                .unwrap_or_else(|| finding.description.clone());

            let rule = ReportingDescriptor::builder()
                .id(&finding.detector_id)
                .name(&finding.title)
                .short_description(&finding.title)
                .full_description(&finding.description)
                .help(
                    MultiformatMessageString::builder()
                        .text(&help_text)
                        .build(),
                )
                .help_uri("https://github.com/slvDev/weasel")
                .properties(
                    sarif::PropertyBag::builder()
                        .additional_properties({
                            let mut props = std::collections::BTreeMap::new();
                            props.insert(
                                "security-severity".to_string(),
                                serde_json::json!(severity_to_score(&finding.severity)),
                            );
                            props.insert("precision".to_string(), serde_json::json!("high"));
                            props.insert(
                                "tags".to_string(),
                                serde_json::json!(["security", "solidity", "smart-contract"]),
                            );
                            props
                        })
                        .build(),
                )
                .build();

            rules.push(rule);
        }

        // Create a result for each location
        for location in &finding.locations {
            // Strip ./ prefix for GitHub compatibility
            let file_path = location.file.strip_prefix("./").unwrap_or(&location.file);
            let artifact_location = ArtifactLocation::builder().uri(file_path).build();

            // Build region - SARIF requires columns >= 1
            let start_col = location.column.unwrap_or(1).max(1) as i64;
            let end_col = location.column_end.unwrap_or(location.column.unwrap_or(1)).max(1) as i64;

            let region = sarif::Region::builder()
                .start_line(location.line as i64)
                .start_column(start_col)
                .end_line(location.line_end.unwrap_or(location.line) as i64)
                .end_column(end_col)
                .build();

            let physical_location = PhysicalLocation::builder()
                .artifact_location(artifact_location)
                .region(region)
                .build();

            let sarif_location = sarif::Location::builder()
                .physical_location(physical_location)
                .build();

            // Generate fingerprint for tracking across runs
            let fingerprint = generate_fingerprint(
                &finding.detector_id,
                &location.file,
                location.line,
                location.snippet.as_deref(),
            );

            let mut partial_fingerprints = BTreeMap::new();
            partial_fingerprints.insert("primaryLocationLineHash".to_string(), fingerprint);

            let result = SarifResult::builder()
                .rule_id(&finding.detector_id)
                .rule_index(*rule_indices.get(&finding.detector_id).unwrap())
                .level(severity_to_level(&finding.severity))
                .message(Message::builder().text(&finding.description).build())
                .locations(vec![sarif_location])
                .partial_fingerprints(partial_fingerprints)
                .build();

            results.push(result);
        }
    }

    // Build tool component
    let tool_component = ToolComponent::builder()
        .name("Weasel")
        .semantic_version(env!("CARGO_PKG_VERSION"))
        .information_uri("https://github.com/slvDev/weasel")
        .rules(rules)
        .build();

    // Build run
    let run = Run::builder()
        .tool(tool_component)
        .results(results)
        .build();

    // Build SARIF document
    Sarif::builder()
        .version(Version::V2_1_0.to_string())
        .schema(SCHEMA_URL)
        .runs(vec![run])
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::finding::{Finding, Location};

    #[test]
    fn test_sarif_generation_basic() {
        let report = Report {
            comment: String::new(),
            footnote: String::new(),
            findings: vec![Finding {
                detector_id: "test-detector".to_string(),
                severity: Severity::High,
                title: "Test Finding".to_string(),
                description: "Test description".to_string(),
                example: None,
                locations: vec![Location {
                    file: "test.sol".to_string(),
                    line: 10,
                    column: Some(5),
                    line_end: Some(10),
                    column_end: Some(20),
                    snippet: Some("uint x = 1;".to_string()),
                }],
            }],
            metadata: None,
        };

        let sarif = generate_sarif_report(&report);

        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);

        let run = &sarif.runs[0];
        assert_eq!(run.tool.driver.name, "Weasel");
        assert_eq!(run.tool.driver.rules.as_ref().unwrap().len(), 1);
        assert_eq!(run.results.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_severity_mapping() {
        assert!(matches!(
            severity_to_level(&Severity::High),
            ResultLevel::Error
        ));
        assert!(matches!(
            severity_to_level(&Severity::Medium),
            ResultLevel::Warning
        ));
        assert!(matches!(
            severity_to_level(&Severity::Low),
            ResultLevel::Note
        ));
        assert!(matches!(
            severity_to_level(&Severity::Gas),
            ResultLevel::Note
        ));
        assert!(matches!(severity_to_level(&Severity::NC), ResultLevel::Note));
    }

    #[test]
    fn test_sarif_empty_report() {
        let report = Report::new();
        let sarif = generate_sarif_report(&report);

        assert_eq!(sarif.version, "2.1.0");
        assert_eq!(sarif.runs.len(), 1);
        assert!(sarif.runs[0].results.as_ref().unwrap().is_empty());
    }
}
