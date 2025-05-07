use crate::{
    core::visitor::ASTVisitor,
    detectors::Detector,
    models::{finding::Location, severity::Severity, SolidityFile},
    utils::ast_utils,
};
use solang_parser::pt::{Expression, Loc, Statement};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct DelegatecallInLoopDetector {
    locations: Arc<Mutex<Vec<Location>>>,
}

impl Detector for DelegatecallInLoopDetector {
    fn id(&self) -> &str {
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

    fn gas_savings(&self) -> Option<usize> {
        None
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

    fn get_locations_arc(&self) -> &Arc<Mutex<Vec<Location>>> {
        &self.locations
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_arc = self.clone();
        visitor.on_statement(move |stmt, file| {
            let mut predicate =
                |expr_to_check: &Expression, _file_context: &SolidityFile| -> Option<Loc> {
                    if let Expression::FunctionCall(loc, func_expr, _) = expr_to_check {
                        if let Expression::MemberAccess(_, _, member_ident) = func_expr.as_ref() {
                            if member_ident.name == "delegatecall" {
                                return Some(loc.clone());
                            }
                        }
                    }
                    None
                };

            let mut loop_body_to_search: Option<&Statement> = None;

            match stmt {
                Statement::For(_, _, _, _, Some(body_statement_box)) => {
                    loop_body_to_search = Some(body_statement_box.as_ref());
                }
                Statement::While(_, _, body_statement_box) => {
                    loop_body_to_search = Some(body_statement_box.as_ref());
                }
                Statement::DoWhile(_, body_statement_box, _) => {
                    loop_body_to_search = Some(body_statement_box.as_ref());
                }
                _ => {}
            }

            if let Some(body) = loop_body_to_search {
                let mut found_locations_in_loop_body = Vec::new();
                ast_utils::find_locations_in_statement(
                    body,
                    file,
                    &mut predicate,
                    &mut found_locations_in_loop_body,
                );

                for loc_data in found_locations_in_loop_body {
                    detector_arc.add_location(loc_data);
                }
            }
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
