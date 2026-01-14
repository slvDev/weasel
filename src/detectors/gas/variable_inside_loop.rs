use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::ast_utils::find_statement_types;
use solang_parser::pt::Statement;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct VariableInsideLoopDetector;

impl Detector for VariableInsideLoopDetector {
    fn id(&self) -> &'static str {
        "variable-inside-loop"
    }

    fn name(&self) -> &str {
        "Create variable outside the loop"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Creating variables inside a loop consumes more gas compared to declaring them outside \
        and reassigning values inside the loop. Saves ~20 gas per iteration."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - variable created inside loop (2012 gas)
for (uint256 i = 0; i < 10; i++) {
    uint256 insideVar = value;
}

// Good - variable created outside loop (1984 gas)
uint256 outsideVar;
for (uint256 i = 0; i < 10; i++) {
    outsideVar = value;
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file, _context| {
            let body = match stmt {
                Statement::For(_, _, _, _, Some(body)) => body.as_ref(),
                Statement::While(_, _, body) => body.as_ref(),
                Statement::DoWhile(_, body, _) => body.as_ref(),
                _ => return Vec::new(),
            };

            // Find variable declarations inside the loop body
            find_statement_types(body, file, self.id(), |inner_stmt| {
                matches!(inner_stmt, Statement::VariableDefinition(_, _, _))
            })
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_variable_inside_loop() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test() public {
                    for (uint i = 0; i < 10; i++) {
                        uint insideVar = 0;
                    }

                    while (true) {
                        uint anotherVar = 1;
                        break;
                    }
                }
            }
        "#;

        let detector = Arc::new(VariableInsideLoopDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 7, "uint insideVar in for loop");
        assert_eq!(locations[1].line, 11, "uint anotherVar in while loop");
    }

    #[test]
    fn test_skips_variable_outside_loop() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test() public {
                    uint outsideVar;
                    for (uint i = 0; i < 10; i++) {
                        outsideVar = i;
                    }
                }
            }
        "#;

        let detector = Arc::new(VariableInsideLoopDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
