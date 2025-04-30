use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Loc, Statement};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct RedundantElseDetector {
    locations: Arc<Mutex<Vec<Location>>>,
}

fn true_branch_unconditionally_exits(stmt: &Statement) -> Option<Loc> {
    match stmt {
        Statement::Return(loc, ..) => Some(loc.clone()),
        Statement::Revert(loc, ..) => Some(loc.clone()),
        Statement::Block { statements, .. } => statements
            .last()
            .and_then(true_branch_unconditionally_exits),
        _ => None,
    }
}

impl Detector for RedundantElseDetector {
    fn id(&self) -> &str {
        "redundant-else"
    }

    fn name(&self) -> &str {
        "`else` block is redundant when `if` block exits unconditionally"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "When an `if` block is guaranteed to exit the function (e.g., via `return` or `revert`), the subsequent `else` block is unnecessary. The code within the `else` can be moved outside and after the `if` statement to reduce nesting."
    }

    fn gas_savings(&self) -> Option<usize> {
        None
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad:
function checkValue(uint x) public pure returns (string memory) {
    if (x < 10) {
        revert("Value too low");
    } else {
        // ... logic for x >= 10 ...
        return "Valid";
    }
}

// Good:
function checkValueFixed(uint x) public pure returns (string memory) {
    if (x < 10) {
        revert("Value too low");
    }
    // No else needed, this code only runs if x >= 10
    // ... logic for x >= 10 ...
    return "Valid";
}
```"#
                .to_string(),
        )
    }

    fn get_locations_arc(&self) -> &Arc<Mutex<Vec<Location>>> {
        &self.locations
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_arc = self.clone();

        visitor.on_statement(move |stmt, file| {
            if let Statement::If(_if_loc, _condition, true_body, else_body_opt) = stmt {
                if else_body_opt.is_some() {
                    if let Some(exit_loc) = true_branch_unconditionally_exits(true_body.as_ref()) {
                        detector_arc.add_location(loc_to_location(&exit_loc, file));
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;
    use std::sync::Arc;

    #[test]
    fn test_redundant_else_detector() {
        let code_positive = r#"
            pragma solidity ^0.8.0;
            contract Test {
                function checkReturn(uint x) public pure returns(bool) {
                    if (x == 0) {
                        return true; // Positive
                    } else {
                        return false;
                    } 
                }

                function checkRevert(uint x) public pure {
                    if (x == 1) {
                        revert("Is one"); // Positive
                    } else {
                        // do something
                    } 
                }

                 function checkBlockReturn(uint x) public pure returns(bool) {
                    if (x == 2) {
                         uint y = x + 1;
                         return false; // Positive
                    } else {
                         return true;
                    } 
                 }

                 function checkNestedNoExit(uint x) public pure returns(bool) {
                     if (x == 3) {
                         if (x % 2 == 0) {
                              // No return/revert here
                         } else {
                             return true; // Exits only one path
                         }
                         // Does not exit here
                     } else {
                          return false;
                     } // Negative
                 }
            }
        "#;
        let detector = Arc::new(RedundantElseDetector::default());
        let locations = run_detector_on_code(detector, code_positive, "positive.sol");
        assert_eq!(locations.len(), 3, "Should detect 3 redundant else blocks");
        assert_eq!(
            locations[0].line, 6,
            "checkReturn should report return line"
        );
        assert_eq!(
            locations[1].line, 14,
            "checkRevert should report revert line"
        );
        assert_eq!(
            locations[2].line, 23,
            "checkBlockReturn should report return line"
        );

        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .contains("return true;"),
            "Snippet for first assert is incorrect"
        );
    }
}
