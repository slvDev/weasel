use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use crate::core::visitor::ASTVisitor;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DivisionBeforeMultiplicationDetector;

impl Detector for DivisionBeforeMultiplicationDetector {
    fn id(&self) -> &'static str {
        "division-before-multiplication"
    }

    fn name(&self) -> &str {
        "Precision loss due to division before multiplication"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Division operations can lead to a loss of precision as the fractional part is discarded. \
         When the result of such a division is then multiplied, this loss of precision can be magnified, \
         potentially leading to significant inaccuracies in calculations. Consider reordering operations \
         to multiply before dividing: `(a * c) / b` instead of `(a / b) * c`."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - division before multiplication loses precision
uint256 result = (a / b) * c;

// Good - multiply first to preserve precision
uint256 result = (a * c) / b;
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
                if let Expression::Multiply(_, left, right) = expr {
                    Self::is_division(left.as_ref()) || Self::is_division(right.as_ref())
                } else {
                    false
                }
            })
        });
    }
}

impl DivisionBeforeMultiplicationDetector {
    fn is_division(expr: &Expression) -> bool {
        match expr {
            Expression::Divide(_, _, _) => true,
            Expression::Parenthesis(_, inner) => Self::is_division(inner.as_ref()),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_division_before_multiplication() {
        let code = r#"
            contract Test {
                function divLeft(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
                    return (a / b) * c;
                }

                function divRight(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
                    return a * (b / c);
                }

                function divBoth(uint256 a, uint256 b, uint256 c, uint256 d) public pure returns (uint256) {
                    return (a / b) * (c / d);
                }

                function chainedDivMul(uint256 a, uint256 b, uint256 c, uint256 d) public pure returns (uint256) {
                    return (a / b) * c * d;
                }

                function inlineComplex(uint256 a, uint256 b, uint256 c, uint256 d) public pure returns (uint256) {
                    return ((a + b) / c) * d;
                }
            }
        "#;
        let detector = Arc::new(DivisionBeforeMultiplicationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 5);
        assert_eq!(locations[0].line, 4, "(a / b) * c");
        assert_eq!(locations[1].line, 8, "a * (b / c)");
        assert_eq!(locations[2].line, 12, "(a / b) * (c / d)");
        assert_eq!(locations[3].line, 16, "(a / b) * c * d");
        assert_eq!(locations[4].line, 20, "((a + b) / c) * d");
    }

    #[test]
    fn test_skips_safe_patterns() {
        let code = r#"
            contract Test {
                function mulBeforeDiv(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
                    return (a * b) / c;
                }

                function separateOperations(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
                    uint256 x = a / b;
                    uint256 y = c * 2;
                    return x + y;
                }

                function justDivision(uint256 a, uint256 b) public pure returns (uint256) {
                    return a / b;
                }

                function justMultiplication(uint256 a, uint256 b) public pure returns (uint256) {
                    return a * b;
                }

                function addBeforeMul(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
                    return (a + b) * c;
                }

                function divAfterMul(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
                    return a * b / c;
                }
            }
        "#;
        let detector = Arc::new(DivisionBeforeMultiplicationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
