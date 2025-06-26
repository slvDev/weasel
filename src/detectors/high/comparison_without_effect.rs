use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ComparisonWithoutEffectDetector;

impl Detector for ComparisonWithoutEffectDetector {
    fn id(&self) -> &'static str {
        "comparison-without-effect"
    }

    fn name(&self) -> &str {
        "Comparison Without Effect"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &str {
        "A comparison operation (e.g., `a > b`) is used as a standalone statement. \
        This has no effect and likely indicates a missing `require`, `if`, or `assert` statement, \
        or an incomplete boolean assignment."
    }

    fn gas_savings(&self) -> Option<usize> {
        None
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad:
function checkValue(uint x, uint y) public view {
    x > y; // This comparison does nothing
    if (x == 0) return;
}

modifier onlyIfPositive(uint val) {
    val > 0; // This comparison does nothing
    _;
}

// Good:
function checkValueFixed(uint x, uint y) public view {
    require(x > y, "x must be greater than y");
    if (x == 0) return;
}

modifier onlyIfPositiveFixed(uint val) {
    require(val > 0, "val must be positive");
    _;
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file| {
            if let Statement::Expression(stmt_loc, expr) = stmt {
                match expr {
                    Expression::Equal(_, _, _)
                    | Expression::NotEqual(_, _, _)
                    | Expression::Less(_, _, _)
                    | Expression::More(_, _, _)
                    | Expression::LessEqual(_, _, _)
                    | Expression::MoreEqual(_, _, _) => {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(stmt_loc, file),
                        }
                        .into();
                    }
                    _ => {}
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
    fn test_comparison_without_effect_detector() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract TestNoEffect {
                uint public value = 10;

                function checkValue(uint x, uint y) public view {
                    x > y; // Positive
                    require(x == 0, "x is zero");
                    if (y < 5) {
                        assert(x != y);
                    }
                    bool isEq = (x == 5);
                    value == 10; // Positive
                }

                modifier onlyIfPositive(uint val) {
                    val > 0; // Positive
                    _;
                }

                function anotherTest(uint a) public onlyIfPositive(a) {
                     a < 100; // Positive
                     {
                        a >= 50; // Positive
                     }
                     return a == 1; // Negative: in return
                }

                function assignments() public {
                    bool b;
                    b = value > 0; // Negative
                }

                function loops() public {
                    for (uint i = 0; i < 10; i++) { // Negative
                        // ...
                    }
                    uint j = 0;
                    while (j < 5) { // Negative
                        j++;
                    }
                }
            }
        "#;

        let detector = Arc::new(ComparisonWithoutEffectDetector::default());
        let locations = run_detector_on_code(detector, code, "comparison_without_effect_test.sol");

        assert_eq!(locations.len(), 5, "Should detect 5 issues");

        assert_eq!(
            locations[0].line, 8,
            "Line number for location[0] should be 8"
        );
        assert_eq!(
            locations[1].line, 14,
            "Line number for location[1] should be 14"
        );
        assert_eq!(
            locations[2].line, 18,
            "Line number for location[2] should be 18"
        );
        assert_eq!(
            locations[3].line, 23,
            "Line number for location[3] should be 23"
        );
        assert_eq!(
            locations[4].line, 25,
            "Line number for location[4] should be 25"
        );

        assert!(
            locations[0].snippet.as_deref().unwrap_or("").eq("x > y"),
            "Snippet for x > y is incorrect"
        );
    }
}
