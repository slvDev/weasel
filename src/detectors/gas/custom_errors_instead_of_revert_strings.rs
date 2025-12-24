use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct CustomErrorsInsteadOfRevertStringsDetector;

impl Detector for CustomErrorsInsteadOfRevertStringsDetector {
    fn id(&self) -> &'static str {
        "custom-errors-instead-of-revert-strings"
    }

    fn name(&self) -> &str {
        "Use custom errors instead of revert strings to save gas"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Custom errors are available from Solidity version 0.8.4. Custom errors save ~50 gas \
        each time they're hit by avoiding having to allocate and store the revert string. \
        Not defining the strings also saves deployment gas. Consider replacing all revert \
        strings with custom errors."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - using revert strings (extra gas)
require(balance >= amount, "Insufficient balance");
revert("Not authorized");

// Good - using custom errors
error InsufficientBalance();
error NotAuthorized();

if (balance < amount) revert InsufficientBalance();
if (!authorized) revert NotAuthorized();
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let self_clone = self.clone();
        // Check require() calls with string messages
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func_expr, args) = expr {
                if let Expression::Variable(ident) = func_expr.as_ref() {
                    if ident.name == "require" && Self::has_string_argument(args) {
                        return FindingData {
                            detector_id: self_clone.id(),
                            location: loc_to_location(loc, file),
                        }
                        .into();
                    }
                }
            }
            Vec::new()
        });

        // Check revert("string") statements
        visitor.on_statement(move |stmt, file, _context| {
            if let Statement::Revert(loc, _, args) = stmt {
                if Self::has_string_argument(args) {
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

impl CustomErrorsInsteadOfRevertStringsDetector {
    fn has_string_argument(args: &[Expression]) -> bool {
        args.iter().any(|arg| Self::is_string_literal(arg))
    }

    fn is_string_literal(expr: &Expression) -> bool {
        matches!(expr, Expression::StringLiteral(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_revert_strings() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function requireWithString(uint256 value) external pure {
                    require(value > 0, "Value must be positive");
                }

                function revertWithString() external pure {
                    revert("Not implemented");
                }

                function multipleRequires(uint256 a, uint256 b) external pure {
                    require(a > 0, "A must be positive");
                    require(b > 0, "B must be positive");
                }
            }
        "#;

        let detector = Arc::new(CustomErrorsInsteadOfRevertStringsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].line, 6, "require with string");
        assert_eq!(locations[1].line, 10, "revert with string");
        assert_eq!(locations[2].line, 14, "first require");
        assert_eq!(locations[3].line, 15, "second require");
    }

    #[test]
    fn test_skips_valid_patterns() {
        let code = r#"
            pragma solidity ^0.8.4;

            error InsufficientBalance();
            error NotAuthorized();
            error InvalidAmount(uint256 amount);

            contract Test {
                function requireWithoutString(uint256 value) external pure {
                    require(value > 0);
                }

                function customErrorRevert() external pure {
                    revert InsufficientBalance();
                }

                function customErrorWithParam(uint256 amount) external pure {
                    revert InvalidAmount(amount);
                }

                function ifRevertCustom(bool authorized) external pure {
                    if (!authorized) {
                        revert NotAuthorized();
                    }
                }
            }
        "#;

        let detector = Arc::new(CustomErrorsInsteadOfRevertStringsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
