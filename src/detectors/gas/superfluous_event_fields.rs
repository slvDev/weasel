use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::ast_utils::get_contract_info;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct SuperfluousEventFieldsDetector;

impl Detector for SuperfluousEventFieldsDetector {
    fn id(&self) -> &'static str {
        "superfluous-event-fields"
    }

    fn name(&self) -> &str {
        "Superfluous event fields"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "`block.timestamp` and `block.number` are added to event information by default so \
        adding them manually wastes gas"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - wastes gas
event Transfer(address from, address to, uint256 value, uint256 timestamp);
event Update(uint256 value, uint256 blockNumber);

// Good - timestamp/blocknumber already in event metadata
event Transfer(address from, address to, uint256 value);
event Update(uint256 value);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let self_clone = self.clone();

        visitor.on_source_unit(move |_source_unit, file, _context| {
            let mut findings = Vec::new();

            for event in &file.events {
                if Self::has_superfluous_field(event) {
                    findings.push(FindingData {
                        detector_id: self_clone.id(),
                        location: event.loc.clone(),
                    });
                }
            }

            findings
        });

        visitor.on_contract(move |contract_def, file, _context| {
            let mut findings = Vec::new();

            let contract_info = match get_contract_info(contract_def, file) {
                Some(info) => info,
                None => return Vec::new(),
            };

            for event in &contract_info.events {
                if Self::has_superfluous_field(event) {
                    findings.push(FindingData {
                        detector_id: self.id(),
                        location: event.loc.clone(),
                    });
                }
            }

            findings
        });
    }
}

impl SuperfluousEventFieldsDetector {
    fn has_superfluous_field(event: &crate::models::EventInfo) -> bool {
        event.parameters.iter().any(|param| {
            if let Some(name) = &param.name {
                let lower = name.to_lowercase();
                lower.contains("timestamp") || lower.contains("blocknumber")
            } else {
                false
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_issues() {
        let code = r#"
            pragma solidity ^0.8.0;

            // File-level event
            event GlobalEvent(uint256 value, uint256 timestamp);

            contract Test {
                event Transfer(address from, address to, uint256 value, uint256 timestamp);
                event Update(uint256 value, uint256 blockNumber);
                event Action(address user, uint256 timeStamp, uint256 data);
                event MultipleFields(uint256 timestamp, uint256 blockNumber, uint256 value);
            }
        "#;

        let detector = Arc::new(SuperfluousEventFieldsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 5);
        assert_eq!(locations[0].line, 5, "file-level event with timestamp");
        assert_eq!(locations[1].line, 8, "timestamp");
        assert_eq!(locations[2].line, 9, "blockNumber");
        assert_eq!(locations[3].line, 10, "timeStamp");
        assert_eq!(locations[4].line, 11, "both timestamp and blockNumber");
    }

    #[test]
    fn test_skips_valid_cases() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                // Valid events without timestamp/blocknumber
                event Transfer(address indexed from, address indexed to, uint256 value);
                event Update(uint256 indexed id, uint256 newValue);

                // Different names - should not be flagged
                event Action(uint256 time, uint256 blockHeight);
            }
        "#;

        let detector = Arc::new(SuperfluousEventFieldsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
