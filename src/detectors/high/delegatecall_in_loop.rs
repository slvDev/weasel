use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Loc, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DelegatecallInLoopDetector;

impl Detector for DelegatecallInLoopDetector {
    fn id(&self) -> &'static str {
        "delegatecall-in-loop"
    }

    fn name(&self) -> &str {
        "Use of `delegatecall` inside a loop"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &str {
        "Executing `delegatecall` inside a loop is highly dangerous. It multiplies reentrancy risks, as external code runs with the caller's storage and permissions repeatedly. Malicious targets or manipulated loop iterations can corrupt state or cause denial of service via gas exhaustion. Refactor to avoid `delegatecall` in loops unless the targets and loop bounds are strictly controlled and understood."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad:
function processDelegated(address[] calldata targets, bytes[] calldata data) external {
    for (uint i = 0; i < targets.length; i++) {
        (bool success, ) = targets[i].delegatecall(data[i]); // delegatecall inside loop
        require(success, "Delegatecall failed");
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file, _context| {
            // Extract loop body if this is a loop statement
            let loop_body = match stmt {
                Statement::For(_, _, _, _, Some(body)) => Some(body.as_ref()),
                Statement::While(_, _, body) | Statement::DoWhile(_, body, _) => {
                    Some(body.as_ref())
                }
                _ => None,
            };

            // If not a loop, nothing to check
            let Some(body) = loop_body else {
                return Vec::new();
            };

            // Define predicate to find delegatecall expressions
            let mut is_delegatecall = |expr: &Expression, _: &_| -> Option<Loc> {
                if let Expression::FunctionCall(loc, func_expr, _) = expr {
                    if let Expression::MemberAccess(_, _, member) = func_expr.as_ref() {
                        if member.name == "delegatecall" {
                            return Some(loc.clone());
                        }
                    }
                }
                None
            };

            // Search for delegatecall in the loop body
            let mut delegatecall_locations = Vec::new();
            ast_utils::find_locations_in_statement(
                body,
                file,
                &mut is_delegatecall,
                &mut delegatecall_locations,
            );

            // Convert found locations to findings
            delegatecall_locations
                .into_iter()
                .map(|location| FindingData {
                    detector_id: self.id(),
                    location,
                })
                .collect()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_delegatecall_in_loop_detector() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract TestDelegatecallInLoop {
                address impl;

                function delegatedFor(address[] calldata targets, bytes[] calldata data) external {
                    for (uint i = 0; i < targets.length; i++) {
                        (bool s, ) = targets[i].delegatecall(data[i]); // Positive
                        require(s);
                    }
                }

                function delegatedWhile(address t, bytes calldata d) external {
                    uint i = 0;
                    while (i < 3) {
                        (bool s, ) = t.delegatecall(d); // Positive
                        require(s);
                        i++;
                    }
                }

                function delegatedDoWhile(address t, bytes calldata d) external {
                    uint i = 0;
                    do {
                        (bool s, ) = t.delegatecall(d); // Positive
                        require(s);
                        i++;
                    } while (i < 3);
                }
                
                function delegatecallInIfInLoop(address t, bytes calldata d) external {
                    for (uint i = 0; i < 2; i++) {
                        if (i == 1) {
                             (bool s, ) = t.delegatecall(d); // Positive
                             require(s);
                        }
                    }
                }

                function noDelegatecallInLoop(address[] calldata targets, bytes[] calldata data) external {
                    for (uint i = 0; i < targets.length; i++) {
                        (bool s, ) = targets[i].call(data[i]); // Negative: regular call
                        require(s);
                    }
                }

                function delegatecallOutsideLoop(address t, bytes calldata d) external {
                    (bool s, ) = t.delegatecall(d); // Negative
                    require(s);
                }
            }
        "#;

        let detector = Arc::new(DelegatecallInLoopDetector::default());
        let locations = run_detector_on_code(detector.clone(), code, "delegatecall_loop_test.sol");

        assert_eq!(locations.len(), 4, "Should detect 4 issues");
        assert_eq!(
            locations[0].line, 9,
            "Line number for location[0] should be 8"
        );
        assert_eq!(
            locations[1].line, 17,
            "Line number for location[0] should be 8"
        );
        assert_eq!(
            locations[2].line, 26,
            "Line number for location[0] should be 8"
        );
        assert_eq!(
            locations[3].line, 35,
            "Line number for location[0] should be 8"
        );

        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("targets[i].delegatecall(data[i])"),
            "Snippet for loc[0] is incorrect"
        );
    }
}
