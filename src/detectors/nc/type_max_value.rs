use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Type};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct TypeMaxValueDetector;

impl Detector for TypeMaxValueDetector {
    fn id(&self) -> &'static str {
        "type-max-value"
    }

    fn name(&self) -> &str {
        "Use `type(uint<n>).max` instead of `uint<n>(-1)`"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Using `type(uint256).max` is more readable and explicit than casting -1 to get \
         the maximum value of an unsigned integer type."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
uint256 max = uint256(-1);
uint128 max128 = uint128(-1);

// Good
uint256 max = type(uint256).max;
uint128 max128 = type(uint128).max;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            // Looking for: uint256(-1) which is FunctionCall with Type as function
            if let Expression::FunctionCall(loc, func, args) = expr {
                // Check if it's a type cast (type as function)
                if let Expression::Type(_, ty) = func.as_ref() {
                    // Only flag uint types
                    if !matches!(ty, Type::Uint(_)) {
                        return Vec::new();
                    }

                    // Check if single argument is -1
                    if args.len() == 1 {
                        if let Expression::Negate(_, inner) = &args[0] {
                            if let Expression::NumberLiteral(_, val, _, _) = inner.as_ref() {
                                if val == "1" {
                                    return FindingData {
                                        detector_id: self.id(),
                                        location: loc_to_location(loc, file),
                                    }
                                    .into();
                                }
                            }
                        }
                    }
                }
            }
            Vec::new()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_uint_minus_one() {
        let code = r#"
            contract Test {
                uint256 public max256 = uint256(-1);
                uint128 public max128 = uint128(-1);
                uint public maxUint = uint(-1);

                function getMax() external pure returns (uint256) {
                    return uint256(-1);
                }
            }
        "#;
        let detector = Arc::new(TypeMaxValueDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].line, 3, "uint256(-1)");
        assert_eq!(locations[1].line, 4, "uint128(-1)");
        assert_eq!(locations[2].line, 5, "uint(-1)");
        assert_eq!(locations[3].line, 8, "return uint256(-1)");
    }

    #[test]
    fn test_skips_proper_patterns() {
        let code = r#"
            contract Test {
                uint256 public max = type(uint256).max;
                uint256 public val = uint256(100);
                int256 public intVal = int256(-1);
            }
        "#;
        let detector = Arc::new(TypeMaxValueDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
