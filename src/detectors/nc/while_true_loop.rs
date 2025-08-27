use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::{
    helpers::CodeLocation,
    pt::{Expression, Loc, Statement},
};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct WhileTrueLoopDetector;

impl Detector for WhileTrueLoopDetector {
    fn id(&self) -> &'static str {
        "while-true-loop"
    }

    fn name(&self) -> &str {
        "Dangerous `while(true)` loop"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Direct `while(true)` loops can be risky if the break condition isn't guaranteed to be met, potentially leading to infinite loops and gas exhaustion. Consider refactoring to a `for` loop or ensuring break conditions are robust."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"
```solidity
// Dangerous:
function processQueue() external {
    while (true) {
        // ... process item ...
    }
}

// No explicit break needed if logic processes exactly queue length
function processQueueWithFor() external {
    for (uint i = 0; i < queue.length(); ++i) {
         // ... process item ...
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file, _context| {
            if let Statement::While(loc, condition, body) = stmt {
                if let Expression::BoolLiteral(_, true) = condition {
                    let issue_loc = Loc::default()
                        .with_start(loc.start())
                        .with_end(body.loc().start());
                    return FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(&issue_loc, file),
                    }
                    .into();
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
    use std::sync::Arc;

    #[test]
    fn test_while_true_loop_detector() {
        let code_positive = r#"
            pragma solidity ^0.8.0;
            contract Test {
                function loopForever() public {
                    while (true) { // Positive
                        // ...
                    }
                }
                function anotherLoop() public {
                     bool condition = true;
                     while (condition) { // Negative
                         // ...
                     }
                }
                function loopWithSpaces() public {
                    while ( true ) { // Positive
                         // ...
                    }
                }
            }
        "#;
        let detector = Arc::new(WhileTrueLoopDetector::default());
        let locations = run_detector_on_code(detector, code_positive, "positive.sol");
        assert_eq!(locations.len(), 2, "Should detect 2 while(true) loops");
        assert_eq!(locations[0].line, 5);
        assert_eq!(locations[1].line, 16);

        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("while (true)"),
            "Snippet for first assert is incorrect"
        );

        let code_negative = r#"
            pragma solidity ^0.8.10;
            contract Test {
                bool flag;
                function loopWithVar() public {
                    while(flag) {
                        // ...
                    }
                }
                 function loopWithFor() public {
                     for (;;) {
                         // ...
                     }
                 }
            }
        "#;
        let detector = Arc::new(WhileTrueLoopDetector::default());
        let locations = run_detector_on_code(detector, code_negative, "negative.sol");
        assert_eq!(
            locations.len(),
            0,
            "Should detect 0 violations for safe patterns"
        );
    }
}
