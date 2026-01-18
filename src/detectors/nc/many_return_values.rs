use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ManyReturnValuesDetector;

impl Detector for ManyReturnValuesDetector {
    fn id(&self) -> &'static str {
        "many-return-values"
    }

    fn name(&self) -> &str {
        "Consider returning a struct rather than multiple return values"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Functions that return many variables can become difficult to read and maintain. \
         Using a struct to encapsulate these return values can improve code readability, \
         increase reusability, and reduce the likelihood of errors. Consider refactoring \
         functions that return more than three variables to use a struct instead."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - multiple return values
function getPosition() external view returns (uint256, uint256, uint256, bool) {
    return (x, y, z, isActive);
}

// Good - use a struct
struct Position {
    uint256 x;
    uint256 y;
    uint256 z;
    bool isActive;
}

function getPosition() external view returns (Position memory) {
    return Position(x, y, z, isActive);
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            if func_def.returns.len() >= 4 {
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
                function fourReturns() public returns (uint, uint, uint, bool) {}   // Line 5
                function fiveReturns() public returns (uint, uint, uint, bool, address) {} // Line 6
            }
        "#;
        let detector = Arc::new(ManyReturnValuesDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 issues");
        assert_eq!(locations[0].line, 5, "fourReturns");
        assert_eq!(locations[1].line, 6, "fiveReturns");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function noReturn() public {}                                // No returns - OK
                function oneReturn() public returns (uint) {}                // 1 return - OK
                function twoReturns() public returns (uint, bool) {}         // 2 returns - OK
                function threeReturns() public returns (uint, bool, address) {} // 3 returns - OK
            }
        "#;
        let detector = Arc::new(ManyReturnValuesDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
