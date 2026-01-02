use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct TypeMaxLiteralDetector;

impl Detector for TypeMaxLiteralDetector {
    fn id(&self) -> &'static str {
        "type-max-literal"
    }

    fn name(&self) -> &str {
        "Use `type(uint256).max` instead of `2 ** 256 - 1`"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Using `type(uint256).max` is more readable and maintainable than the literal \
         expression `2 ** 256 - 1`."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
uint256 max = 2 ** 256 - 1;

// Good
uint256 max = type(uint256).max;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::Subtract(loc, left, right) = expr {
                if !Self::is_number(right, "1") {
                    return Vec::new();
                }

                if let Expression::Power(_, base, exp) = left.as_ref() {
                    if Self::is_number(base, "2") && Self::is_uint_bit_size(exp) {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(loc, file),
                        }
                        .into();
                    }
                }
            }
            Vec::new()
        });
    }
}

impl TypeMaxLiteralDetector {
    const UINT_BIT_SIZES: &'static [&'static str] = &["8", "16", "32", "64", "128", "256"];

    fn is_number(expr: &Expression, expected: &str) -> bool {
        matches!(expr, Expression::NumberLiteral(_, val, _, _) if val == expected)
    }

    fn is_uint_bit_size(expr: &Expression) -> bool {
        if let Expression::NumberLiteral(_, val, _, _) = expr {
            return Self::UINT_BIT_SIZES.contains(&val.as_str());
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_power_minus_one() {
        let code = r#"
            contract Test {
                uint256 public max256 = 2 ** 256 - 1;
                uint128 public max128 = 2 ** 128 - 1;
                uint64 public max64 = 2 ** 64 - 1;
                uint32 public max32 = 2 ** 32 - 1;
                uint8 public max8 = 2 ** 8 - 1;

                function getMax() external pure returns (uint256) {
                    return 2**256-1;
                }
            }
        "#;
        let detector = Arc::new(TypeMaxLiteralDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 6);
        assert_eq!(locations[0].line, 3, "2 ** 256 - 1");
        assert_eq!(locations[1].line, 4, "2 ** 128 - 1");
        assert_eq!(locations[2].line, 5, "2 ** 64 - 1");
        assert_eq!(locations[3].line, 6, "2 ** 32 - 1");
        assert_eq!(locations[4].line, 7, "2 ** 8 - 1");
        assert_eq!(locations[5].line, 10, "return 2**256-1");
    }

    #[test]
    fn test_skips_other_patterns() {
        let code = r#"
            contract Test {
                uint256 public max = type(uint256).max;
                uint256 public val = 2 ** 100 - 1;
                uint256 public other = 2 ** 256;
            }
        "#;
        let detector = Arc::new(TypeMaxLiteralDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
