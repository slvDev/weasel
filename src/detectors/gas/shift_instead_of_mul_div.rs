use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ShiftInsteadOfMulDivDetector;

impl Detector for ShiftInsteadOfMulDivDetector {
    fn id(&self) -> &'static str {
        "shift-instead-of-mul-div"
    }

    fn name(&self) -> &str {
        "Use shift right/left instead of division/multiplication if possible"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "While the `DIV` / `MUL` opcode uses 5 gas, the `SHR` / `SHL` opcode only uses 3 gas. \
        Furthermore, beware that Solidity's division operation also includes a division-by-0 \
        prevention which is bypassed using shifting. Eventually, overflow checks are never \
        performed for shift operations as they are done for arithmetic operations. Instead, the \
        result is always truncated, so the calculation can be unchecked in Solidity version `0.8+`\n\
        - Use `>> 1` instead of `/ 2`\n\
        - Use `>> 2` instead of `/ 4`\n\
        - Use `<< 3` instead of `* 8`\n\
        - Use `>> 5` instead of `/ 2^5 == / 32`\n\
        - Use `<< 6` instead of `* 2^6 == * 64`\n\n\
        TL;DR:\n\
        - Shifting left by N is like multiplying by 2^N\n\
        - Shifting right by N is like dividing by 2^N\n\n\
        *Saves around 2 gas + 20 for unchecked per instance*"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - uses expensive MUL/DIV opcodes
function bad(uint256 x) external pure returns (uint256) {
    uint256 a = x / 2;
    uint256 b = x * 8;
    return a + b;
}

// Good - uses cheap SHR/SHL opcodes
function good(uint256 x) external pure returns (uint256) {
    uint256 a = x >> 1;  // equivalent to x / 2
    uint256 b = x << 3;  // equivalent to x * 8
    return a + b;
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            let mut findings = Vec::new();

            match expr {
                Expression::Divide(loc, _, right) => {
                    if Self::is_power_of_two_literal(right) {
                        findings.push(FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(loc, file),
                        });
                    }
                }
                Expression::Multiply(loc, left, right) => {
                    // Check both sides for power of 2 (multiplication is commutative)
                    if Self::is_power_of_two_literal(left) || Self::is_power_of_two_literal(right)
                    {
                        findings.push(FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(loc, file),
                        });
                    }
                }
                _ => {}
            }

            findings
        });
    }
}

impl ShiftInsteadOfMulDivDetector {
    /// Check if expression is a power of 2 number literal (2, 4, 8, 16, 32, ...)
    fn is_power_of_two_literal(expr: &Expression) -> bool {
        if let Expression::NumberLiteral(_, value, _, _) = expr {
            if let Ok(n) = value.parse::<u64>() {
                return n > 0 && (n & (n - 1)) == 0;
            }
        }
        false
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
                function calculate(uint256 x) external pure returns (uint256) {
                    uint256 a = x / 2;
                    uint256 b = x * 4;
                    uint256 c = 8 * x;
                    uint256 d = x / 16;
                    return a + b + c + d;
                }
            }
        "#;

        let detector = Arc::new(ShiftInsteadOfMulDivDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].line, 6, "x / 2");
        assert_eq!(locations[1].line, 7, "x * 4");
        assert_eq!(locations[2].line, 8, "8 * x");
        assert_eq!(locations[3].line, 9, "x / 16");
    }

    #[test]
    fn test_skips_valid_cases() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function calculate(uint256 x) external pure returns (uint256) {
                    // Non-power-of-2 - no issue
                    uint256 a = x / 3;
                    uint256 b = x * 5;
                    uint256 c = x / 7;

                    // Already using shifts - no issue
                    uint256 d = x >> 1;
                    uint256 e = x << 3;

                    return a + b + c + d + e;
                }
            }
        "#;

        let detector = Arc::new(ShiftInsteadOfMulDivDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }

    #[test]
    fn test_various_powers_of_two() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(uint256 x) external pure returns (uint256) {
                    return x / 2 + x / 4 + x / 8 + x / 32 + x / 64 +
                           x / 128 + x / 256 + x / 512 + x / 1024 + x / 2048;
                }
            }
        "#;

        let detector = Arc::new(ShiftInsteadOfMulDivDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        // Should detect all 10 divisions by powers of 2
        assert_eq!(locations.len(), 10);
    }
}
