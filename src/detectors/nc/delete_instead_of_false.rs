use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DeleteInsteadOfFalseDetector;

impl Detector for DeleteInsteadOfFalseDetector {
    fn id(&self) -> &'static str {
        "delete-instead-of-false"
    }

    fn name(&self) -> &str {
        "Consider using `delete` rather than assigning `false`"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "The `delete` keyword more accurately reflects the intent of clearing or resetting a \
         variable. Using `delete` instead of assigning `false` makes the code more readable \
         and highlights the change in state, which may encourage a more thorough audit of \
         the surrounding logic."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - assigning false to clear value
isActive = false;

// Good - using delete to clear value
delete isActive;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_id = self.id();
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::Assign(loc, _, right) = expr {
                if let Expression::BoolLiteral(_, value) = right.as_ref() {
                    if !value {
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
                bool isActive;
                mapping(address => bool) public isAllowed;

                function deactivate() public {
                    isActive = false;               // Line 9 - assignment to false
                }

                function revoke(address user) public {
                    isAllowed[user] = false;        // Line 13 - mapping assignment to false
                }
            }
        "#;
        let detector = Arc::new(DeleteInsteadOfFalseDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 assignments to false");
        assert_eq!(locations[0].line, 9, "isActive = false");
        assert_eq!(locations[1].line, 13, "isAllowed[user] = false");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                bool isActive;
                uint256 count;
                string name;

                function setup() public {
                    isActive = true;            // Assignment to true
                    count = 10;                 // Assignment to number
                    name = "test";              // Assignment to string
                }

                function clear() public {
                    delete isActive;            // Using delete is correct
                }
            }
        "#;
        let detector = Arc::new(DeleteInsteadOfFalseDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should only detect assignments to false");
    }
}
