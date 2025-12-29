use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use crate::core::visitor::ASTVisitor;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UintGtZeroDetector;

impl Detector for UintGtZeroDetector {
    fn id(&self) -> &'static str {
        "uint-gt-zero"
    }

    fn name(&self) -> &str {
        "Use != 0 Instead of > 0 for Unsigned Integer"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "For unsigned integers, using != 0 is more gas efficient than > 0 in comparisons. \
         The != 0 operation is cheaper because it's a simple bitwise check, while > 0 \
         requires additional comparison logic."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - uses more gas
if (balance > 0) {
    transfer(balance);
}

// Good - more efficient
if (balance != 0) {
    transfer(balance);
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func, file, _context| {
            let Some(body) = &func.body else {
                return Vec::new();
            };

            find_in_statement(body, file, self.id(), |expr| {
                match expr {
                    // Pattern: x > 0
                    Expression::More(_, _left, right) => Self::is_zero_literal(right),
                    // Pattern: 0 < x
                    Expression::Less(_, left, _right) => Self::is_zero_literal(left),
                    _ => false,
                }
            })
        });
    }
}

impl UintGtZeroDetector {
    fn is_zero_literal(expr: &Expression) -> bool {
        matches!(expr, Expression::NumberLiteral(_, value, _, _) if value == "0")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_gt_zero_comparison() {
        let code = r#"
            contract Test {
                function check(uint x, uint y) public {
                    if (x > 0) {
                        // do something
                    }
                    require(y > 0, "must be positive");
                    bool valid = 0 < x;
                }
            }
        "#;
        let detector = Arc::new(UintGtZeroDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 4, "x > 0");
        assert_eq!(locations[1].line, 7, "y > 0");
        assert_eq!(locations[2].line, 8, "0 < x");
    }

    #[test]
    fn test_skips_valid_comparisons() {
        let code = r#"
            contract Test {
                function check(uint x, uint y) public {
                    if (x != 0) {
                        // already optimized
                    }
                    require(y > 1, "must be greater than 1");
                    bool valid = x >= 0;
                }
            }
        "#;
        let detector = Arc::new(UintGtZeroDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
