use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use crate::core::visitor::ASTVisitor;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ConstantDecimalsDetector;

impl Detector for ConstantDecimalsDetector {
    fn id(&self) -> &'static str {
        "constant-decimals"
    }

    fn name(&self) -> &str {
        "Avoid using constant decimals in expressions"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "The use of fixed decimal values such as `1e18` or `10 ** 18` in Solidity contracts can \
         lead to bugs and vulnerabilities when interacting with tokens having different decimal \
         configurations. Not all ERC20 tokens follow the standard 18 decimal places, and \
         assumptions about decimal places can lead to miscalculations. Always retrieve and use \
         the `decimals()` function from the token contract itself when performing calculations \
         involving token amounts."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - hardcoded decimals
uint256 amount = fee / 10 ** 18;
uint256 amount = fee / 1e18;

// Good - use token's decimals
uint256 amount = fee / (10 ** token.decimals());
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
                Self::is_constant_decimal(expr)
            })
        });
    }
}

impl ConstantDecimalsDetector {
    fn is_constant_decimal(expr: &Expression) -> bool {
        // Check for 10 ** 18 pattern
        if let Expression::Power(_, base, exponent) = expr {
            if Self::is_number_literal(base, "10") && Self::is_number_literal(exponent, "18") {
                return true;
            }
        }

        // Check for 1e18 pattern (NumberLiteral with exponent)
        if let Expression::NumberLiteral(_, value, exp, _) = expr {
            if value == "1" && exp == "18" {
                return true;
            }
        }

        false
    }

    fn is_number_literal(expr: &Expression, expected: &str) -> bool {
        if let Expression::NumberLiteral(_, value, exp, _) = expr {
            value == expected && exp.is_empty()
        } else {
            false
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
                function test(uint256 fee) public {
                    uint256 a = fee / 10 ** 18;   // Line 6 - power notation
                    uint256 b = fee / 1e18;       // Line 7 - scientific notation
                    uint256 c = fee * 10 ** 18;   // Line 8 - multiplication
                    uint256 d = 1e18 + fee;       // Line 9 - addition
                }
            }
        "#;
        let detector = Arc::new(ConstantDecimalsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4, "Should detect 4 issues");
        assert_eq!(locations[0].line, 6, "10 ** 18 division");
        assert_eq!(locations[1].line, 7, "1e18 division");
        assert_eq!(locations[2].line, 8, "10 ** 18 multiplication");
        assert_eq!(locations[3].line, 9, "1e18 addition");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(uint256 fee, uint8 decimals) public {
                    // Dynamic decimals - OK
                    uint256 a = fee / (10 ** decimals);

                    // Other powers - OK
                    uint256 b = fee / 10 ** 6;
                    uint256 c = fee * 10 ** 8;

                    // Other scientific notation - OK
                    uint256 d = 1e6;
                    uint256 e = 1e8;

                    // Regular numbers - OK
                    uint256 f = 18;
                    uint256 g = 10;
                }
            }
        "#;
        let detector = Arc::new(ConstantDecimalsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
