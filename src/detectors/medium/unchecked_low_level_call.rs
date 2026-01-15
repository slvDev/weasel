use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::ast_utils::find_variable_uses;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Identifier, Parameter, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UncheckedLowLevelCallDetector;

impl Detector for UncheckedLowLevelCallDetector {
    fn id(&self) -> &'static str {
        "unchecked-low-level-call"
    }

    fn name(&self) -> &str {
        "Unchecked return value of low-level `call()`/`delegatecall()`/`staticcall()`"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "The return value of `call()`, `delegatecall()`, or `staticcall()` should always be checked to ensure \
        the call was successful. Unchecked return values allow execution to continue even if the call failed, \
        which can lead to unexpected behavior, loss of funds, or security vulnerabilities."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no success check at all
payable(addr).call{value: 1 ether}("");

// Bad - success captured but never used
(bool success, ) = addr.call{value: 1 ether}("");

// Good - success checked with require
(bool success, ) = addr.call{value: 1 ether}("");
require(success, "Transfer failed");

// Good - success checked with if or custom handler
(bool success, ) = addr.call{value: 1 ether}("");
if (!success) revert TransferFailed();
handleCallResult(success); // Custom handler is also fine
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            let Some(body) = &func_def.body else {
                return Vec::new();
            };

            let mut findings = Vec::new();
            find_unchecked_low_level_calls(body, body, file, self.id(), &mut findings);
            findings
        });
    }
}

/// Recursively find low-level calls and check if they're properly handled
fn find_unchecked_low_level_calls(
    stmt: &Statement,
    full_body: &Statement,
    file: &crate::models::SolidityFile,
    detector_id: &'static str,
    findings: &mut Vec<FindingData>,
) {
    match stmt {
        Statement::Block { statements, .. } => {
            for s in statements {
                find_unchecked_low_level_calls(s, full_body, file, detector_id, findings);
            }
        }

        // Case 1: Direct call without assignment - addr.call{value: 1}("")
        Statement::Expression(loc, Expression::FunctionCall(_, func_expr, _)) => {
            if is_low_level_call(func_expr) {
                findings.push(FindingData {
                    detector_id,
                    location: loc_to_location(loc, file),
                });
            }
        }

        // Case 2: Assignment with call - (bool success, ) = addr.call(...)
        Statement::Expression(loc, Expression::Assign(_, left, right)) => {
            if let Expression::FunctionCall(_, func_expr, _) = right.as_ref() {
                if is_low_level_call(func_expr) {
                    if let Some(success_var) = get_success_variable(left) {
                        // Check if success variable is used anywhere in function body
                        let uses = find_variable_uses(&success_var, full_body, file);
                        if uses.is_empty() {
                            findings.push(FindingData {
                                detector_id,
                                location: loc_to_location(loc, file),
                            });
                        }
                    } else {
                        // No success variable captured - flag it
                        findings.push(FindingData {
                            detector_id,
                            location: loc_to_location(loc, file),
                        });
                    }
                }
            }
        }

        // Recurse into control flow
        Statement::If(_, _, then_stmt, else_stmt) => {
            find_unchecked_low_level_calls(then_stmt, full_body, file, detector_id, findings);
            if let Some(else_s) = else_stmt {
                find_unchecked_low_level_calls(else_s, full_body, file, detector_id, findings);
            }
        }
        Statement::For(_, _, _, _, Some(body)) => {
            find_unchecked_low_level_calls(body, full_body, file, detector_id, findings);
        }
        Statement::While(_, _, body) => {
            find_unchecked_low_level_calls(body, full_body, file, detector_id, findings);
        }
        Statement::DoWhile(_, body, _) => {
            find_unchecked_low_level_calls(body, full_body, file, detector_id, findings);
        }

        _ => {}
    }
}

/// Check if expression is a low-level call (call, delegatecall, or staticcall)
fn is_low_level_call(expr: &Expression) -> bool {
    match expr {
        Expression::MemberAccess(_, _, Identifier { name, .. }) => {
            name == "call" || name == "delegatecall" || name == "staticcall"
        }
        Expression::FunctionCallBlock(_, inner, _) => {
            matches!(inner.as_ref(), Expression::MemberAccess(_, _, Identifier { name, .. }) if name == "call" || name == "delegatecall" || name == "staticcall")
        }
        _ => false,
    }
}

/// Get the success variable name from tuple assignment
/// e.g., (bool success, ) = ... -> returns "success"
fn get_success_variable(left: &Expression) -> Option<String> {
    if let Expression::List(_, params) = left {
        if let Some((_, Some(param))) = params.first() {
            if let Parameter { name: Some(id), .. } = param {
                return Some(id.name.clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_unchecked_calls() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(address payable addr) external {
                    // No success variable at all
                    payable(addr).call{value: 1 ether}("");

                    // Success captured but never checked
                    (bool success, ) = addr.call{value: 1 ether}("");

                    // Inside loop without check
                    for (uint i = 0; i < 5; i++) {
                        (bool loopSuccess, ) = addr.call{value: i}("");
                    }
                }
            }
        "#;

        let detector = Arc::new(UncheckedLowLevelCallDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 7, "call without success variable");
        assert_eq!(locations[1].line, 10, "success not checked");
        assert_eq!(locations[2].line, 14, "loop success not checked");
    }

    #[test]
    fn test_skips_checked_calls() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(address payable addr) external {
                    // Checked with require
                    (bool success1, ) = addr.call{value: 1 ether}("");
                    require(success1, "Transfer failed");

                    // Checked with if
                    (bool success2, ) = addr.call{value: 1 ether}("");
                    if (!success2) {
                        revert("Failed");
                    }

                    // Checked with assert
                    (bool success3, ) = addr.delegatecall("");
                    assert(success3);
                }
            }
        "#;

        let detector = Arc::new(UncheckedLowLevelCallDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
