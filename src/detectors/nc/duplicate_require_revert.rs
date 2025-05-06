use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Statement};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct DuplicateRequireRevertDetector {
    require_revert_map: Mutex<HashMap<String, Vec<Location>>>,
    locations: Arc<Mutex<Vec<Location>>>,
}

impl DuplicateRequireRevertDetector {
    fn process_findings(&self) {
        let mut final_locations = Vec::new();
        let map = self.require_revert_map.lock().unwrap();

        for (_, loc_vec) in map.iter() {
            if loc_vec.len() > 1 {
                final_locations.extend(loc_vec.iter().cloned());
            }
        }

        final_locations.sort_by_key(|loc| (loc.file.clone(), loc.line));

        let mut locked_locations = self.locations.lock().unwrap();
        *locked_locations = final_locations;
    }
}

impl Detector for DuplicateRequireRevertDetector {
    fn id(&self) -> &str {
        "duplicate-require-revert"
    }

    fn name(&self) -> &str {
        "Duplicate `require`/`revert` Checks"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Identical `require` or `revert` statements (based on the full statement snippet for require, and the error string for revert) found in multiple places. Consider refactoring into a modifier or a reusable internal function for clarity and maintainability."
    }

    fn gas_savings(&self) -> Option<usize> {
        None
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Duplicate requires (based on full snippet):
require(msg.sender == owner, "Not owner");
// ... later ...
require(msg.sender == owner, "Not owner"); // Identical call

// Duplicate reverts (based on string):
revert("Action failed");
// ... later ...
revert("Action failed");

// Refactored require using modifier:
modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}

// Refactored revert using custom error:
error ActionFailed();
// ...
revert ActionFailed();
```"#
                .to_string(),
        )
    }

    fn get_locations_arc(&self) -> &Arc<Mutex<Vec<Location>>> {
        self.process_findings();
        &self.locations
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let expr_clone = self.clone();
        visitor.on_expression(move |expr, file| {
            let map_mutex = &expr_clone.require_revert_map;
            if let Expression::FunctionCall(call_loc, func_expr, _) = expr {
                if matches!(func_expr.as_ref(), Expression::Variable(ident) if ident.name.as_str() == "require") {
                        let require_call_loc = loc_to_location(call_loc, file);
                        if let Some(key) = require_call_loc.snippet.clone() {
                            if !key.is_empty() && key != "<code snippet unavailable>" {
                                map_mutex
                                    .lock()
                                    .unwrap()
                                    .entry(key)
                                    .or_default()
                                    .push(require_call_loc);
                            }
                        }
                }
            }
        });

        let stmt_clone = self.clone();
        visitor.on_statement(move |stmt, file| {
            let map_mutex = &stmt_clone.require_revert_map;
            if let Statement::Revert(loc, _, _) = stmt {
                let revert_loc = loc_to_location(loc, file);
                if let Some(key) = revert_loc.snippet.clone() {
                    if !key.is_empty() && key != "<code snippet unavailable>" {
                        map_mutex
                            .lock()
                            .unwrap()
                            .entry(key)
                            .or_default()
                            .push(revert_loc);
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
    fn test_duplicate_require_revert_detector() {
        let code = r#"
            pragma solidity ^0.8.0;
            contract Test {
                address owner = msg.sender;
                uint value = 10;

                function action1(uint x) public {
                    require(msg.sender == owner, "Not owner"); // Dup Call 1a (Require Snippet)
                    require(x > value, "Bad input"); // Dup Call 2a (Require Snippet)
                }

                function action2() public {
                    require(msg.sender == owner, "Not owner"); // Dup Call 1b (Require Snippet)
                    revert("Action not allowed"); // Dup Revert String 1a
                }

                function action3(uint x) public {
                     require(value > 0, "Value positive"); // Unique Call
                     require(msg.sender == owner, "Not owner"); // Dup Call 1c (Require Snippet)
                     require(x > value, "Bad input"); // Dup Call 2b (Require Snippet)
                }

                 function action4() public {
                     revert("Action not allowed"); // Dup Revert String 1b
                }
                 function action5() public {
                     revert("Different error"); // Unique revert string
                 }
                 function action6(uint x) public {
                     require(msg.sender == owner, "Not owner msg"); // Unique Call (different msg)
                 }
            }
        "#;
        let detector = Arc::new(DuplicateRequireRevertDetector::default());
        let locations = run_detector_on_code(detector, code, "duplicates.sol");

        assert_eq!(
            locations.len(),
            7,
            "Should report all 7 instances of duplicates based on full snippet/revert string"
        );

        // Check line numbers (sorted by lne)
        assert_eq!(locations[0].line, 8); // require(msg.sender == owner, "Not owner") 1a
        assert_eq!(locations[1].line, 9); // require(x > value, "Bad input") 2a
        assert_eq!(locations[2].line, 13); // require(msg.sender == owner, "Not owner") 1b
        assert_eq!(locations[3].line, 14); // revert("Action not allowed") 1a
        assert_eq!(locations[4].line, 19); // require(msg.sender == owner, "Not owner") 1c
        assert_eq!(locations[5].line, 20); // require(x > value, "Bad input") 2b
        assert_eq!(locations[6].line, 24); // revert("Action not allowed") 1b

        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("require(msg.sender == owner, \"Not owner\")"),
            "Snippet for first assert is incorrect"
        );
    }
}
