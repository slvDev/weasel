use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{ContractPart, SourceUnitPart};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct EventArgsDetector;

impl Detector for EventArgsDetector {
    fn id(&self) -> &'static str {
        "event-missing-args"
    }

    fn name(&self) -> &str {
        "Events should use parameters"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Events without parameters provide less context. Consider adding parameters (indexed where appropriate) to convey more information about the event, rather than using separate events for simple state changes."
    }

    fn gas_savings(&self) -> Option<usize> {
        None
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Less informative:
event Paused();
event Unpaused();

// More informative:
event PauseStateChanged(bool isPaused);
// Or:
event PauseStateChanged(address indexed changedBy, bool isPaused);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_id = self.id();
        visitor.on_source_unit_part(move |part, file| {
            if let SourceUnitPart::EventDefinition(event_def) = part {
                if event_def.fields.is_empty() {
                    return FindingData {
                        detector_id,
                        location: loc_to_location(&event_def.loc, file),
                    }
                    .into();
                }
            }
            Vec::new()
        });

        visitor.on_contract_part(move |part, file| {
            if let ContractPart::EventDefinition(event_def) = part {
                if event_def.fields.is_empty() {
                    return FindingData {
                        detector_id,
                        location: loc_to_location(&event_def.loc, file),
                    }
                    .into();
                }
            }
            Vec::new()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;
    use std::sync::Arc;

    #[test]
    fn test_event_args_detector() {
        let code_positive = r#"
            pragma solidity ^0.8.0;

            event FileLevelEvent(); // Positive
            event FileLevelEventWithArgs(uint indexed value); // Negative

            contract Test {
                event ContractLevelEvent(); // Positive
                event ContractLevelEventWithArgs(address indexed sender); // Negative

                function doSomething() public {
                    emit ContractLevelEvent();
                }
            }
        "#;
        let detector = Arc::new(EventArgsDetector::default());
        let locations = run_detector_on_code(detector, code_positive, "positive.sol");
        assert_eq!(locations.len(), 2, "Should detect 2 events missing args");
        assert_eq!(locations[0].line, 4); // FileLevelEvent
        assert_eq!(locations[1].line, 8); // ContractLevelEvent
        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("event FileLevelEvent()"),
            "Snippet for first event is incorrect"
        );
    }
}
