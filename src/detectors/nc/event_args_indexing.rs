use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::SolidityFile};
use solang_parser::pt::{ContractPart, EventDefinition, SourceUnitPart};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct EventMissingIndexedArgsDetector;

impl Detector for EventMissingIndexedArgsDetector {
    fn id(&self) -> &'static str {
        "event-args-indexing"
    }

    fn name(&self) -> &str {
        "Event Arguments Indexing Convention"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Events should follow indexing best practices: index up to three fields if possible, or all fields if less than three are available. Indexed fields allow off-chain tools to filter events efficiently."
    }


    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity

// Bad
event ValueSet(uint256 value);
// Good
event ValueSet(uint256 indexed value);

// Bad
event Approval(address indexed owner, address indexed spender, uint256 value);
// Good
event Approval(address indexed owner, address indexed spender, uint256 indexed value);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_id = self.id();
        visitor.on_source_unit_part(move |part, file| {
            if let SourceUnitPart::EventDefinition(event_def) = part {
                return check_event_indexing(event_def, file, detector_id);
            }
            Vec::new()
        });

        visitor.on_contract_part(move |part, file| {
            if let ContractPart::EventDefinition(event_def) = part {
                return check_event_indexing(event_def, file, detector_id);
            }
            Vec::new()
        });
    }
}

fn check_event_indexing(
    event_def: &EventDefinition,
    file: &SolidityFile,
    detector_id: &'static str,
) -> Vec<FindingData> {
    let num_params = event_def.fields.len();
    if num_params == 0 {
        return Vec::new();
    }

    let num_indexed = event_def.fields.iter().filter(|p| p.indexed).count();
    let should_flag = if num_params >= 3 {
        num_indexed != 3
    } else {
        num_indexed != num_params
    };

    if should_flag {
        return FindingData {
            detector_id,
            location: loc_to_location(&event_def.loc, file),
        }
        .into();
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;
    use std::sync::Arc;

    #[test]
    fn test_event_indexing_detector() {
        let code = r#"
            pragma solidity ^0.8.0;

            event Event0(); // Negative

            event Event1_0(uint a); // Positive
            event Event1_1(uint indexed a); // Negative

            event Event2_0(uint a, bool b); // Positive
            event Event2_1(uint indexed a, bool b); // Positive
            event Event2_2(uint indexed a, bool indexed b); // Negative

            event Event3_0(uint a, bool b, address c); // Positive
            event Event3_1(uint indexed a, bool b, address c); // Positive
            event Event3_2(uint indexed a, bool indexed b, address c); // Positive
            event Event3_3(uint indexed a, bool indexed b, address indexed c); // Negative

            event Event4_0(uint a, bool b, address c, bytes32 d); // Positive
            event Event4_1(uint indexed a, bool b, address c, bytes32 d); // Positive
            event Event4_2(uint indexed a, bool indexed b, address c, bytes32 d); // Positive
            event Event4_3(uint indexed a, bool indexed b, address indexed c, bytes32 d); // Negative
            event Event4_4(uint indexed a, bool indexed b, address indexed c, bytes32 indexed d); // Negative

            contract Test {
                 event C_Event1_0(uint a); // Positive
                 event C_Event3_3(uint indexed a, bool indexed b, address indexed c); // Negative
            }
        "#;
        let detector = Arc::new(EventMissingIndexedArgsDetector::default());
        let locations = run_detector_on_code(detector, code, "indexing.sol");
        assert_eq!(
            locations.len(),
            11,
            "Should detect 11 indexing convention violations"
        );

        assert_eq!(locations[0].line, 6); // Event1_0
        assert_eq!(locations[1].line, 9); // Event2_0
        assert_eq!(locations[2].line, 10); // Event2_1
        assert_eq!(locations[3].line, 13); // Event3_0
        assert_eq!(locations[10].line, 25); // C_Event1_0

        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("event Event1_0(uint a)"),
            "Snippet for first assert is incorrect"
        );
    }
}
