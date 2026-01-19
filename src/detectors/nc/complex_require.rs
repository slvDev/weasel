use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ComplexRequireDetector;

impl Detector for ComplexRequireDetector {
    fn id(&self) -> &'static str {
        "complex-require"
    }

    fn name(&self) -> &str {
        "Simplify complex require statements"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Complex require statements with multiple logical operators (&&, ||) can be hard to read \
         and debug. Consider simplifying by using local variables, splitting into multiple require \
         statements, or using if/revert patterns for better readability and modularity."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - complex condition
require(a == b && c == d || e == f);

// Good - split for clarity
require(a == b, "a != b");
require(c == d || e == f, "invalid c/e");
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
                if let Expression::FunctionCall(_, func_expr, args) = expr {
                    if let Expression::Variable(id) = func_expr.as_ref() {
                        if id.name == "require" && !args.is_empty() {
                            return Self::has_multiple_logic_ops(&args[0]);
                        }
                    }
                }
                false
            })
        });
    }
}

impl ComplexRequireDetector {
    /// Check if expression has more than one logical operator (&&, ||)
    fn has_multiple_logic_ops(expr: &Expression) -> bool {
        Self::count_logic_ops(expr) > 1
    }

    fn count_logic_ops(expr: &Expression) -> usize {
        match expr {
            Expression::And(_, left, right) | Expression::Or(_, left, right) => {
                1 + Self::count_logic_ops(left) + Self::count_logic_ops(right)
            }
            Expression::Parenthesis(_, inner) | Expression::Not(_, inner) => {
                Self::count_logic_ops(inner)
            }
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_issue() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(uint256 a, uint256 b, uint256 c) public {
                    require(a == b && c == d || e == f);    // Line 6 - complex
                    require(a > 0 && b > 0 && c > 0);       // Line 7 - complex
                }
            }
        "#;
        let detector = Arc::new(ComplexRequireDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 complex requires");
        assert_eq!(locations[0].line, 6, "first complex require");
        assert_eq!(locations[1].line, 7, "second complex require");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(uint256 a, uint256 b) public {
                    require(a > 0);                 // single condition - OK
                    require(a > 0 && b > 0);        // single && - OK
                    require(a > 0 || b > 0);        // single || - OK
                }
            }
        "#;
        let detector = Arc::new(ComplexRequireDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Simple requires should not be flagged");
    }
}
