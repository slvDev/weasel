use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{FunctionTy, Loc, Statement};
use std::sync::Arc;

const MAX_PARAMS: usize = 5;

#[derive(Debug, Default)]
pub struct ManyFunctionParamsDetector;

impl Detector for ManyFunctionParamsDetector {
    fn id(&self) -> &'static str {
        "many-function-params"
    }

    fn name(&self) -> &str {
        "Consider using a `struct` rather than having many function input parameters"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Functions with many parameters can become difficult to read and maintain. Using a struct \
         to encapsulate these parameters can improve code readability, increase reusability, and \
         reduce the likelihood of errors. Consider refactoring functions that take more than four \
         parameters to use a struct instead."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - too many parameters
function createOrder(
    address buyer,
    address seller,
    uint256 amount,
    uint256 price,
    uint256 deadline
) public {}

// Good - use a struct
struct OrderParams {
    address buyer;
    address seller;
    uint256 amount;
    uint256 price;
    uint256 deadline;
}

function createOrder(OrderParams calldata params) public {}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            // Skip modifiers
            if matches!(func_def.ty, FunctionTy::Modifier) {
                return Vec::new();
            }

            if func_def.params.len() >= MAX_PARAMS {
                // Report function signature only, not the body
                let issue_loc = if let Some(Statement::Block { loc: body_loc, .. }) = &func_def.body
                {
                    Loc::default()
                        .with_start(func_def.loc.start())
                        .with_end(body_loc.start())
                } else {
                    func_def.loc
                };

                return FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&issue_loc, file),
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
                function test1(uint a, uint b, uint c, uint d, uint e) public {}           // Line 5 - 5 params
                function test2(uint a, uint b, uint c, uint d, uint e, uint f) public {}   // Line 6 - 6 params
            }
        "#;
        let detector = Arc::new(ManyFunctionParamsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 issues");
        assert_eq!(locations[0].line, 5, "test1 with 5 params");
        assert_eq!(locations[1].line, 6, "test2 with 6 params");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test1() public {}                              // 0 params - OK
                function test2(uint a) public {}                        // 1 param - OK
                function test3(uint a, uint b, uint c, uint d) public {} // 4 params - OK
            }
        "#;
        let detector = Arc::new(ManyFunctionParamsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
