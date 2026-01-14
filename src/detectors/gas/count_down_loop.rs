use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct CountDownLoopDetector;

impl Detector for CountDownLoopDetector {
    fn id(&self) -> &'static str {
        "count-down-loop"
    }

    fn name(&self) -> &str {
        "Counting down when iterating saves gas"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Counting down saves ~6 gas per loop iteration, since checks for zero are more \
        efficient than checks against any other value."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - counting up
for (uint256 i = 0; i < length; i++) {
    // ...
}

// Good - counting down
for (uint256 i = length; i != 0; --i) {
    // ...
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file, _context| {
            if let Statement::For(loc, _, _, Some(update), _) = stmt {
                if matches!(
                    update.as_ref(),
                    Expression::PostIncrement(_, _) | Expression::PreIncrement(_, _)
                ) {
                    return FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(loc, file),
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

    #[test]
    fn test_detects_increment_loops() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256[] array;

                function test() public {
                    for (uint i = 0; i < array.length; i++) {
                        array[i] = i;
                    }
                    for (uint i = 0; i < 10; ++i) {
                        array[i] = i;
                    }
                }
            }
        "#;

        let detector = Arc::new(CountDownLoopDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 8, "for loop with i++");
        assert_eq!(locations[1].line, 11, "for loop with ++i");
    }

    #[test]
    fn test_skips_decrement_loops() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test() public {
                    for (uint i = 10; i != 0; --i) {
                        // already counting down
                    }
                }
            }
        "#;

        let detector = Arc::new(CountDownLoopDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
