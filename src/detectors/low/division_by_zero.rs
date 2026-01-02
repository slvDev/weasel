use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use crate::core::visitor::ASTVisitor;
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DivisionByZeroDetector;

impl Detector for DivisionByZeroDetector {
    fn id(&self) -> &'static str {
        "division-by-zero"
    }

    fn name(&self) -> &str {
        "Division by zero not prevented"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Division or modulo operations without zero-value checks on the divisor can cause runtime reverts. \
         The detector identifies divisions where the divisor is a variable that lacks validation (e.g., `require(b != 0)`, \
         `require(b > 0)`, `if (b == 0) revert()`, etc.). Always validate divisors before arithmetic operations."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no zero check on parameter
function divide(uint256 a, uint256 b) public pure returns (uint256) {
    return a / b;
}

// Good - require with != 0
function divide(uint256 a, uint256 b) public pure returns (uint256) {
    require(b != 0, "Division by zero");
    return a / b;
}
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
                match expr {
                    Expression::Divide(_, _, right) | Expression::Modulo(_, _, right) => {
                        if let Some(var_name) = Self::get_variable_name(right.as_ref()) {
                            !Self::find_zero_validation(body, var_name)
                        } else {
                            Self::is_potentially_zero(right.as_ref())
                        }
                    }
                    _ => false,
                }
            })
        });
    }
}

impl DivisionByZeroDetector {
    fn is_potentially_zero(expr: &Expression) -> bool {
        match expr {
            Expression::NumberLiteral(_, value, _, _) => {
                value == "0"
            }
            Expression::Variable(_) => true,
            Expression::MemberAccess(_, _, _) => true,
            Expression::FunctionCall(_, _, _) => true,
            Expression::ArraySubscript(_, _, _) => true,
            Expression::Add(_, left, right)
            | Expression::Subtract(_, left, right)
            | Expression::Multiply(_, left, right)
            | Expression::Divide(_, left, right)
            | Expression::Modulo(_, left, right)
            | Expression::Power(_, left, right) => {
                Self::is_potentially_zero(left.as_ref()) || Self::is_potentially_zero(right.as_ref())
            }
            _ => false,
        }
    }

    fn get_variable_name(expr: &Expression) -> Option<&str> {
        match expr {
            Expression::Variable(id) => Some(&id.name),
            _ => None,
        }
    }

    fn find_zero_validation(stmt: &Statement, var_name: &str) -> bool {
        match stmt {
            Statement::Block { statements, .. } => {
                statements.iter().any(|s| Self::find_zero_validation(s, var_name))
            }
            Statement::Expression(_, expr) => Self::expr_has_zero_validation(expr, var_name),
            Statement::If(_, cond, then_stmt, else_stmt) => {
                Self::expr_has_zero_validation(cond, var_name)
                    || Self::find_zero_validation(then_stmt, var_name)
                    || else_stmt.as_ref().map_or(false, |s| Self::find_zero_validation(s, var_name))
            }
            Statement::While(_, cond, body) => {
                Self::expr_has_zero_validation(cond, var_name) || Self::find_zero_validation(body, var_name)
            }
            Statement::DoWhile(_, body, cond) => {
                Self::find_zero_validation(body, var_name) || Self::expr_has_zero_validation(cond, var_name)
            }
            Statement::For(_, _, cond, _, body) => {
                cond.as_ref().map_or(false, |c| Self::expr_has_zero_validation(c, var_name))
                    || body.as_ref().map_or(false, |b| Self::find_zero_validation(b, var_name))
            }
            Statement::Return(_, Some(expr)) => Self::expr_has_zero_validation(expr, var_name),
            _ => false,
        }
    }

    fn expr_has_zero_validation(expr: &Expression, var_name: &str) -> bool {
        match expr {
            // != 0, == 0, > 0, >= 1
            Expression::NotEqual(_, left, right) => {
                (Self::is_variable_named(left, var_name) && Self::is_zero(right))
                    || (Self::is_zero(left) && Self::is_variable_named(right, var_name))
            }
            Expression::Equal(_, left, right) => {
                (Self::is_variable_named(left, var_name) && Self::is_zero(right))
                    || (Self::is_zero(left) && Self::is_variable_named(right, var_name))
            }
            Expression::More(_, left, right) => {
                Self::is_variable_named(left, var_name) && Self::is_zero(right)
            }
            Expression::MoreEqual(_, left, right) => {
                Self::is_variable_named(left, var_name) && Self::is_literal_one(right)
            }
            // require/assert/if
            Expression::FunctionCall(_, _, args) => {
                args.iter().any(|arg| Self::expr_has_zero_validation(arg, var_name))
            }
            // logical operators
            Expression::And(_, left, right) | Expression::Or(_, left, right) => {
                Self::expr_has_zero_validation(left, var_name) || Self::expr_has_zero_validation(right, var_name)
            }
            Expression::Not(_, inner) => Self::expr_has_zero_validation(inner, var_name),
            _ => false,
        }
    }

    fn is_variable_named(expr: &Expression, name: &str) -> bool {
        matches!(expr, Expression::Variable(id) if id.name == name)
    }

    fn is_zero(expr: &Expression) -> bool {
        matches!(expr, Expression::NumberLiteral(_, val, _, _) if val == "0")
    }

    fn is_literal_one(expr: &Expression) -> bool {
        matches!(expr, Expression::NumberLiteral(_, val, _, _) if val == "1")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_division_by_zero() {
        let code = r#"
            contract Test {
                uint256 divisor;
                mapping(address => uint256) balances;

                function divideParams(uint256 a, uint256 b) public pure returns (uint256) {
                    return a / b;
                }

                function divideState(uint256 value) public view returns (uint256) {
                    return value / divisor;
                }

                function divideCall(uint256 value) public view returns (uint256) {
                    return value / getDivisor();
                }

                function moduloParam(uint256 a, uint256 b) public pure returns (uint256) {
                    return a % b;
                }

                function divideMemberAccess(address user) public view returns (uint256) {
                    return 1000 / balances[user];
                }

                function divideArrayAccess(uint256[] memory arr, uint256 idx) public pure returns (uint256) {
                    return 100 / arr[idx];
                }

                function multipleDivisions(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
                    uint256 x = a / b;
                    uint256 y = x / c;
                    return y;
                }

                function moduloNoCheck(uint256 a, uint256 b) public pure returns (uint256) {
                    return a % b;
                }

                function getDivisor() public view returns (uint256) {
                    return divisor;
                }
            }
        "#;
        let detector = Arc::new(DivisionByZeroDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 9);
        assert_eq!(locations[0].line, 7, "a / b in divideParams");
        assert_eq!(locations[1].line, 11, "value / divisor in divideState");
        assert_eq!(locations[2].line, 15, "value / getDivisor() in divideCall");
        assert_eq!(locations[3].line, 19, "a % b in moduloParam");
        assert_eq!(locations[4].line, 23, "1000 / balances[user] in divideMemberAccess");
        assert_eq!(locations[5].line, 27, "100 / arr[idx] in divideArrayAccess");
        assert_eq!(locations[6].line, 31, "a / b in multipleDivisions");
        assert_eq!(locations[7].line, 32, "x / c in multipleDivisions");
        assert_eq!(locations[8].line, 37, "a % b in moduloNoCheck");
    }

    #[test]
    fn test_skips_safe_divisions() {
        let code = r#"
            contract Test {
                function divideLiteral(uint256 value) public pure returns (uint256) {
                    return value / 100;
                }

                function dividePower(uint256 value) public pure returns (uint256) {
                    return value / 10**18;
                }

                function divideLiteralArithmetic(uint256 value) public pure returns (uint256) {
                    return value / (2 * 5);
                }

                function divideWithRequire(uint256 a, uint256 b) public pure returns (uint256) {
                    require(b != 0, "Division by zero");
                    return a / b;
                }

                function divideWithIf(uint256 a, uint256 b) public pure returns (uint256) {
                    if (b == 0) revert();
                    return a / b;
                }

                function divideWithCheck(uint256 a, uint256 b) public pure returns (uint256) {
                    require(b > 0, "Must be positive");
                    return a / b;
                }

                function divideWithAssert(uint256 a, uint256 b) public pure returns (uint256) {
                    assert(b >= 1);
                    return a / b;
                }

                function divideWithLogic(uint256 a, uint256 b, bool flag) public pure returns (uint256) {
                    require(flag && b != 0, "Invalid");
                    return a / b;
                }

                function divideWithReversedCheck(uint256 a, uint256 b) public pure returns (uint256) {
                    require(0 != b, "Zero divisor");
                    return a / b;
                }

                function divideWithEqualityRevert(uint256 a, uint256 b) public pure returns (uint256) {
                    if (0 == b) revert("Zero");
                    return a / b;
                }

                function divideInWhile(uint256 a, uint256 b) public pure returns (uint256) {
                    while (b != 0) {
                        return a / b;
                    }
                    return 0;
                }

                function divideInFor(uint256 a, uint256 b) public pure returns (uint256) {
                    for (uint i = 0; b > 0 && i < 10; i++) {
                        return a / b;
                    }
                    return 0;
                }

                function divideWithOrCheck(uint256 a, uint256 b) public pure returns (uint256) {
                    require(b != 0 || a == 0, "Invalid");
                    return a / b;
                }

                function divideMultipleChecks(uint256 a, uint256 b, uint256 c) public pure returns (uint256) {
                    require(b != 0, "b is zero");
                    require(c > 0, "c is zero");
                    return (a / b) / c;
                }
            }
        "#;
        let detector = Arc::new(DivisionByZeroDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
