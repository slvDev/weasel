use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::FunctionTy;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct NamedReturnsDetector;

impl Detector for NamedReturnsDetector {
    fn id(&self) -> &'static str {
        "named-returns"
    }

    fn name(&self) -> &str {
        "Consider using named returns"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Using named returns makes the code more self-documenting, makes it easier to fill out \
         NatSpec, and in some cases can save gas."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - unnamed return
function getBalance() public view returns (uint256) {
    return balances[msg.sender];
}

// Good - named return
function getBalance() public view returns (uint256 balance) {
    balance = balances[msg.sender];
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            // Skip constructors, fallback, receive
            if !matches!(func_def.ty, FunctionTy::Function | FunctionTy::Modifier) {
                return Vec::new();
            }

            // Check if function has return parameters
            if func_def.returns.is_empty() {
                return Vec::new();
            }

            // Check if any return parameter is unnamed
            let has_unnamed_return = func_def
                .returns
                .iter()
                .any(|(_, param)| param.as_ref().map_or(true, |p| p.name.is_none()));

            if has_unnamed_return {
                return FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&func_def.loc, file),
                }
                .into();
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
                function unnamed1() public returns (bool) {         // Line 5 - unnamed
                    return false;
                }
                function unnamed2() public returns (uint256, bool) { // Line 8 - both unnamed
                    return (1, true);
                }
            }
        "#;
        let detector = Arc::new(NamedReturnsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 issues");
        assert_eq!(locations[0].line, 5, "unnamed1");
        assert_eq!(locations[1].line, 8, "unnamed2");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function named1() public returns (uint256 value) {   // Named - OK
                    value = 10;
                }
                function named2() public returns (bool ok, uint256 val) { // Both named - OK
                    ok = true;
                    val = 1;
                }
                function noReturn() public {                         // No return - OK
                    // do something
                }
                constructor() {}                                     // Constructor - OK
                receive() external payable {}                        // Receive - OK
                fallback() external {}                               // Fallback - OK
            }
        "#;
        let detector = Arc::new(NamedReturnsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
