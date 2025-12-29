use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct SplitRequireDetector;

impl Detector for SplitRequireDetector {
    fn id(&self) -> &'static str {
        "split-require"
    }

    fn name(&self) -> &str {
        "Splitting require() statements that use && saves gas"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "When using `&&` in a `require()` statement, the entire condition is evaluated even if \
        the first condition is false. Splitting the conditions into separate `require()` statements \
        can save gas by short-circuiting when the first condition fails. Additionally, separate \
        require statements provide more specific revert messages.\n\n\
        Instead of:\n\
        ```solidity\n\
        require(condition1 && condition2, \"Error\");\n\
        ```\n\
        Use:\n\
        ```solidity\n\
        require(condition1, \"Error: condition1 failed\");\n\
        require(condition2, \"Error: condition2 failed\");\n\
        ```"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - evaluates both conditions even if first fails
function bad(uint256 x, uint256 y) external pure {
    require(x > 0 && y < 100, "Invalid values");
}

// Good - short-circuits and provides better error messages
function good(uint256 x, uint256 y) external pure {
    require(x > 0, "x must be positive");
    require(y < 100, "y must be less than 100");
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            let mut findings = Vec::new();

            if let Expression::FunctionCall(loc, func, args) = expr {
                if matches!(func.as_ref(), Expression::Variable(ident) if ident.name == "require")
                    && !args.is_empty()
                    && Self::contains_and_operator(&args[0])
                {
                    findings.push(FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(loc, file),
                    });
                }
            }

            findings
        });
    }
}

impl SplitRequireDetector {

    /// Recursively check if expression contains && operator
    fn contains_and_operator(expr: &Expression) -> bool {
        match expr {
            Expression::And(_, _, _) => true,
            Expression::Parenthesis(_, inner) => Self::contains_and_operator(inner),
            Expression::Not(_, inner) => Self::contains_and_operator(inner),
            Expression::Less(_, left, right)
            | Expression::More(_, left, right)
            | Expression::LessEqual(_, left, right)
            | Expression::MoreEqual(_, left, right)
            | Expression::Equal(_, left, right)
            | Expression::NotEqual(_, left, right)
            | Expression::Or(_, left, right)
            | Expression::BitwiseAnd(_, left, right)
            | Expression::BitwiseOr(_, left, right)
            | Expression::BitwiseXor(_, left, right) => {
                Self::contains_and_operator(left) || Self::contains_and_operator(right)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_issues() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function validate(uint256 x, uint256 y, address addr) external pure {
                    require(x > 0 && y < 100, "Invalid values");
                    require(x != y && addr != address(0), "Invalid params");
                    require(x > 10 && x < 1000 && y > 5, "Out of range");
                }

                function complex(uint256 x, uint256 y, uint256 z) external pure {
                    // Parenthesized && - should still detect
                    require((x > 0) && (y < 100), "Invalid");

                    // Nested in other operators
                    require(x > 0 && y < 100 || z == 5, "Complex condition");
                }
            }
        "#;

        let detector = Arc::new(SplitRequireDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 5);
        assert_eq!(locations[0].line, 6, "x > 0 && y < 100");
        assert_eq!(locations[1].line, 7, "x != y && addr != address(0)");
        assert_eq!(locations[2].line, 8, "multiple &&");
        assert_eq!(locations[3].line, 13, "parenthesized &&");
        assert_eq!(locations[4].line, 16, "nested with ||");
    }

    #[test]
    fn test_skips_valid_cases() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function validate(uint256 x, uint256 y) external pure {
                    // Single condition - no issue
                    require(x > 0, "x must be positive");
                    require(y < 100, "y too large");

                    // Using || instead of && - no issue (different logic)
                    require(x > 100 || y > 100, "At least one must be large");

                    // Bitwise AND (&) not logical AND (&&) - no issue
                    require((x & 0xFF) == y, "Bitwise check");
                }
            }
        "#;

        let detector = Arc::new(SplitRequireDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
