use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_statement_types;
use solang_parser::pt::Statement;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct RedundantReturnDetector;

impl Detector for RedundantReturnDetector {
    fn id(&self) -> &'static str {
        "redundant-return"
    }

    fn name(&self) -> &str {
        "Adding a `return` statement when the function defines a named return variable is redundant"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "When a function uses named return variables, the value is automatically returned at the \
         end of the function. Adding an explicit `return` statement is redundant and reduces \
         code clarity."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - redundant return with named return variable
function calculate(uint256 x) public pure returns (uint256 result) {
    result = x * 2;
    return result;  // Redundant
}

// Good - let named return work automatically
function calculate(uint256 x) public pure returns (uint256 result) {
    result = x * 2;
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func, file, _context| {
            let has_named_return = func
                .returns
                .iter()
                .any(|(_, param_opt)| param_opt.as_ref().is_some_and(|param| param.name.is_some()));

            if !has_named_return {
                return Vec::new();
            }

            let Some(body) = &func.body else {
                return Vec::new();
            };

            find_statement_types(body, file, self.id(), |stmt| {
                matches!(stmt, Statement::Return(_, _))
            })
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_redundant_return() {
        let code = r#"
            contract Test {
                function calculate(uint256 x) public pure returns (uint256 result) {
                    result = x * 2;
                    return result;
                }

                function multiReturn(uint256 x) public pure returns (uint256 a, uint256 b) {
                    a = x;
                    b = x * 2;
                    return (a, b);
                }

                function withCondition(uint256 x) public pure returns (uint256 result) {
                    if (x > 10) {
                        result = x;
                        return result;
                    }
                    result = 0;
                }
            }
        "#;
        let detector = Arc::new(RedundantReturnDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 5, "return result");
        assert_eq!(locations[1].line, 11, "return (a, b)");
        assert_eq!(locations[2].line, 17, "return in if");
    }

    #[test]
    fn test_skips_unnamed_returns() {
        let code = r#"
            contract Test {
                function calculate(uint256 x) public pure returns (uint256) {
                    return x * 2;
                }

                function noReturn(uint256 x) public pure returns (uint256 result) {
                    result = x * 2;
                }
            }
        "#;
        let detector = Arc::new(RedundantReturnDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
