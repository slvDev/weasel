use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{ContractPart, SourceUnitPart};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ErrorDefinitionNoArgsDetector;

impl Detector for ErrorDefinitionNoArgsDetector {
    fn id(&self) -> &'static str {
        "error-definition-no-args"
    }

    fn name(&self) -> &str {
        "Custom error has no error details"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Custom Errors can include values such as address, tokenID, or msg.value in their \
         definition. This provides valuable debugging information in tools like Tenderly \
         when examining reverted transactions."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no useful information in definition
error InsufficientBalance();

// Good - includes debugging parameters
error InsufficientBalance(address account, uint256 balance, uint256 required);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_id = self.id();
        visitor.on_source_unit_part(move |part, file, _context| {
            if let SourceUnitPart::ErrorDefinition(error_def) = part {
                if error_def.fields.is_empty() {
                    return FindingData {
                        detector_id,
                        location: loc_to_location(&error_def.loc, file),
                    }
                    .into();
                }
            }
            Vec::new()
        });

        visitor.on_contract_part(move |part, file, _context| {
            if let ContractPart::ErrorDefinition(error_def) = part {
                if error_def.fields.is_empty() {
                    return FindingData {
                        detector_id,
                        location: loc_to_location(&error_def.loc, file),
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
    fn test_detects_error_definitions_without_args() {
        let code = r#"
            pragma solidity ^0.8.0;

            error FileLevelError();
            error FileLevelErrorWithArgs(uint256 value);

            contract Test {
                error ContractLevelError();
                error ContractLevelErrorWithArgs(address sender);
            }
        "#;
        let detector = Arc::new(ErrorDefinitionNoArgsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2, "Should detect 2 error definitions without args");
        assert_eq!(locations[0].line, 4, "FileLevelError");
        assert_eq!(locations[1].line, 8, "ContractLevelError");
    }

    #[test]
    fn test_skips_errors_with_args() {
        let code = r#"
            pragma solidity ^0.8.0;

            error InsufficientBalance(address account, uint256 balance);
            error Unauthorized(address caller);

            contract Test {
                error TransferFailed(address from, address to, uint256 amount);
            }
        "#;
        let detector = Arc::new(ErrorDefinitionNoArgsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect errors with args");
    }
}
