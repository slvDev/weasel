use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::{FindingData, VariableVisibility};
use crate::utils::ast_utils::get_contract_info;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct PrivateConstantsDetector;

impl Detector for PrivateConstantsDetector {
    fn id(&self) -> &'static str {
        "private-constants"
    }

    fn name(&self) -> &str {
        "Using `private` rather than `public` for constants, saves gas"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "If needed, the values can be read from the verified contract source code, or if there \
        are multiple values there can be a single getter function that returns a tuple of the \
        values of all currently-public constants. Saves **3406-3606 gas** in deployment gas due \
        to the compiler not having to create non-payable getter functions for deployment calldata, \
        not having to store the bytes of the value outside of where it's used, and not adding \
        another entry to the method ID table."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - creates unnecessary getter function
contract Bad {
    uint256 public constant MAX_SUPPLY = 1000;
}

// Good - saves deployment gas
contract Good {
    uint256 private constant MAX_SUPPLY = 1000;
    // Or just omit visibility (defaults to internal)
    uint256 constant MAX_SUPPLY_2 = 2000;
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            let mut findings = Vec::new();

            let contract_info = match get_contract_info(contract_def, file) {
                Some(info) => info,
                None => return Vec::new(),
            };

            // Find public constants
            for var in &contract_info.state_variables {
                if var.is_constant && var.visibility == VariableVisibility::Public {
                    findings.push(FindingData {
                        detector_id: self.id(),
                        location: var.loc.clone(),
                    });
                }
            }

            findings
        });
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

            contract Test {
                uint256 public constant MAX_SUPPLY = 1000;
                address public constant OWNER = address(0x123);
                bytes32 public constant HASH = keccak256("test");
            }
        "#;

        let detector = Arc::new(PrivateConstantsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 5, "MAX_SUPPLY");
        assert_eq!(locations[1].line, 6, "OWNER");
        assert_eq!(locations[2].line, 7, "HASH");
    }

    #[test]
    fn test_skips_valid_cases() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                // Private/internal constants - no issue
                uint256 private constant MAX_SUPPLY = 1000;
                uint256 internal constant MAX_VALUE = 2000;
                uint256 constant IMPLIED_INTERNAL = 3000;

                // Public non-constant - no issue
                uint256 public value = 100;
                uint256 public immutable owner;

                constructor(uint256 _owner) {
                    owner = _owner;
                }
            }
        "#;

        let detector = Arc::new(PrivateConstantsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
