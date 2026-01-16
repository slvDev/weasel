use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, VariableAttribute};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ConstantExpressionDetector;

impl Detector for ConstantExpressionDetector {
    fn id(&self) -> &'static str {
        "constant-expression"
    }

    fn name(&self) -> &str {
        "Expressions for constant values should use `immutable` rather than `constant`"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "There is a difference between `constant` and `immutable` variables, and they should \
         each be used in their appropriate contexts. For `constant` variables, the expression \
         assigned to it is copied to all places where it is accessed and re-evaluated each time. \
         For `immutable` variables, the expression is evaluated once at construction time and \
         the value is copied to all places where it is accessed. `constant`s should be used for \
         literal values written into the code (e.g., `uint256 constant X = 42`), and `immutable` \
         variables should be used for expressions or values calculated in or passed into the \
         constructor (e.g., `keccak256()`, arithmetic operations, function calls)."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - expression used with constant
bytes32 constant MINTER_ROLE = keccak256("MINTER_ROLE");
uint256 constant MAX_UINT = 2**256 - 1;

// Good - use immutable for expressions
bytes32 immutable MINTER_ROLE = keccak256("MINTER_ROLE");
uint256 immutable MAX_UINT = 2**256 - 1;

// Good - constant for literal values
uint256 constant MAX_SUPPLY = 1000000;
address constant DEAD_ADDRESS = 0x000000000000000000000000000000000000dEaD;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_variable(move |var_def, file, _context| {
            // Check if variable is constant
            let is_constant = var_def
                .attrs
                .iter()
                .any(|attr| matches!(attr, VariableAttribute::Constant(_)));

            if !is_constant {
                return Vec::new();
            }

            // Check if initializer is an expression (not a literal)
            if let Some(init) = &var_def.initializer {
                if Self::is_expression(init) {
                    return FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(&var_def.loc, file),
                    }
                    .into();
                }
            }

            Vec::new()
        });
    }
}

impl ConstantExpressionDetector {
    fn is_expression(expr: &Expression) -> bool {
        matches!(
            expr,
            Expression::Add(_, _, _)
                | Expression::Subtract(_, _, _)
                | Expression::Multiply(_, _, _)
                | Expression::Divide(_, _, _)
                | Expression::Modulo(_, _, _)
                | Expression::Power(_, _, _)
                | Expression::FunctionCall(_, _, _)
                | Expression::ArrayLiteral(_, _)
                | Expression::MemberAccess(_, _, _)
        )
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
                bytes32 constant MINTER_ROLE = keccak256("MINTER_ROLE");  // Line 5 - function call
                uint256 constant MAX_UINT = 2**256 - 1;                   // Line 6 - arithmetic
                uint256 constant COMPUTED = 100 * 10;                     // Line 7 - multiplication
                bytes32 constant ADMIN = keccak256(abi.encodePacked("ADMIN"));  // Line 8 - nested call
            }
        "#;
        let detector = Arc::new(ConstantExpressionDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4, "Should detect 4 issues");
        assert_eq!(locations[0].line, 5, "MINTER_ROLE with keccak256");
        assert_eq!(locations[1].line, 6, "MAX_UINT with power/subtract");
        assert_eq!(locations[2].line, 7, "COMPUTED with multiplication");
        assert_eq!(locations[3].line, 8, "ADMIN with nested keccak256");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                // Literal values - OK
                uint256 constant MAX_SUPPLY = 1000000;
                address constant DEAD_ADDRESS = 0x000000000000000000000000000000000000dEaD;
                string constant NAME = "MyToken";
                bool constant IS_ACTIVE = true;

                // Immutable with expressions - OK
                bytes32 immutable MINTER_ROLE = keccak256("MINTER_ROLE");

                // Non-constant variables - OK
                uint256 public computed = 100 * 10;
            }
        "#;
        let detector = Arc::new(ConstantExpressionDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
