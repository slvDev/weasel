use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct LongCalculationsDetector;

impl Detector for LongCalculationsDetector {
    fn id(&self) -> &'static str {
        "long-calculations"
    }

    fn name(&self) -> &str {
        "Consider splitting long calculations"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "For improved readability and maintainability, it's suggested to limit arithmetic operations \
        to 3 per expression. Excessive operations can convolute the code, making it more prone to \
        errors and more difficult to debug or review. Splitting operations across multiple lines \
        or intermediate variables is often a good approach."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - too many operations in one expression
uint256 result = (a * b) / (c + d) % e + f;

// Good - split into intermediate steps
uint256 numerator = a * b;
uint256 denominator = c + d;
uint256 result = (numerator / denominator) % e + f;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            let Some(body) = &func_def.body else {
                return Vec::new();
            };

            find_in_statement(body, file, self.id(), |expr| {
                // Only check top-level arithmetic expressions to avoid duplicate reports
                if !is_arithmetic_op(expr) {
                    return false;
                }

                // Count operations in this expression tree
                let op_count = count_arithmetic_ops(expr);
                op_count > 3
            })
        });
    }
}

/// Check if expression is an arithmetic operation
fn is_arithmetic_op(expr: &Expression) -> bool {
    matches!(
        expr,
        Expression::Add(_, _, _)
            | Expression::Subtract(_, _, _)
            | Expression::Multiply(_, _, _)
            | Expression::Divide(_, _, _)
            | Expression::Modulo(_, _, _)
            | Expression::Power(_, _, _)
            | Expression::ShiftLeft(_, _, _)
            | Expression::ShiftRight(_, _, _)
    )
}

/// Count arithmetic operations in expression tree
fn count_arithmetic_ops(expr: &Expression) -> usize {
    match expr {
        Expression::Add(_, left, right)
        | Expression::Subtract(_, left, right)
        | Expression::Multiply(_, left, right)
        | Expression::Divide(_, left, right)
        | Expression::Modulo(_, left, right)
        | Expression::Power(_, left, right)
        | Expression::ShiftLeft(_, left, right)
        | Expression::ShiftRight(_, left, right) => {
            1 + count_arithmetic_ops(left) + count_arithmetic_ops(right)
        }
        Expression::Parenthesis(_, inner) | Expression::Negate(_, inner) => {
            count_arithmetic_ops(inner)
        }
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_long_calculations() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(uint256 x) public pure {
                    uint256 a;
                    a = (10 * 4) / (2 + 3) % 2;
                    a = x ** 2 + x * 3 - x / 4;
                }
            }
        "#;

        let detector = Arc::new(LongCalculationsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 7, "(10 * 4) / (2 + 3) % 2");
        assert_eq!(locations[1].line, 8, "x ** 2 + x * 3 - x / 4");
    }

    #[test]
    fn test_skips_short_calculations() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
                    uint256 x = a + b;
                    uint256 y = a * b / c;
                    uint256 z = a + b - c;
                    return x * y + z;
                }
            }
        "#;

        let detector = Arc::new(LongCalculationsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
