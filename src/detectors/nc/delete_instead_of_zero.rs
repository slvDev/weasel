use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DeleteInsteadOfZeroDetector;

impl Detector for DeleteInsteadOfZeroDetector {
    fn id(&self) -> &'static str {
        "delete-instead-of-zero"
    }

    fn name(&self) -> &str {
        "Consider using `delete` rather than assigning `zero`"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Rather than merely setting a variable to zero, you can use the `delete` keyword to \
         reset it to its default value. This action is especially relevant for complex data \
         types like arrays or mappings where the default is not necessarily zero. Using \
         `delete` provides explicit clarity that you intend to reset a variable."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - assigning zero to clear value
balance = 0;

// Good - using delete to clear value
delete balance;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_id = self.id();
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::Assign(loc, _, right) = expr {
                if let Expression::NumberLiteral(_, value, _, _) = right.as_ref() {
                    if value == "0" {
                        return FindingData {
                            detector_id,
                            location: loc_to_location(loc, file),
                        }
                        .into();
                    }
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

    #[test]
    fn test_detects_issue() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256 balance;
                mapping(address => uint256) public balances;

                function reset() public {
                    balance = 0;                // Line 9 - assignment to zero
                }

                function clear(address user) public {
                    balances[user] = 0;         // Line 13 - mapping assignment to zero
                }
            }
        "#;
        let detector = Arc::new(DeleteInsteadOfZeroDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 assignments to zero");
        assert_eq!(locations[0].line, 9, "balance = 0");
        assert_eq!(locations[1].line, 13, "balances[user] = 0");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256 balance;
                bool isActive;
                string name;

                function setup() public {
                    balance = 100;              // Assignment to non-zero
                    isActive = true;            // Assignment to bool
                    name = "test";              // Assignment to string
                }

                function clear() public {
                    delete balance;             // Using delete is correct
                }
            }
        "#;
        let detector = Arc::new(DeleteInsteadOfZeroDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should only detect assignments to zero");
    }
}
