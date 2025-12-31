use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnsafeAbiEncodePackedDetector;

impl Detector for UnsafeAbiEncodePackedDetector {
    fn id(&self) -> &'static str {
        "unsafe-abi-encode-packed"
    }

    fn name(&self) -> &str {
        "`abi.encodePacked()` should not be used with dynamic types when passing the result to a hash function such as `keccak256()`"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Use `abi.encode()` instead which will pad items to 32 bytes, which will prevent hash collisions \
         (e.g. `abi.encodePacked(0x123,0x456)` => `0x123456` => `abi.encodePacked(0x1,0x23456)`, but \
         `abi.encode(0x123,0x456)` => `0x0...1230...456`). Unless there is a compelling reason, `abi.encode` \
         should be preferred. If there is only one argument to `abi.encodePacked()` it can often be cast to \
         `bytes()` or `bytes32()` instead. If all arguments are strings and or bytes, `bytes.concat()` should \
         be used instead. References: https://docs.soliditylang.org/en/v0.8.13/abi-spec.html#non-standard-packed-mode, \
         https://ethereum.stackexchange.com/questions/30912/how-to-compare-strings-in-solidity#answer-82739"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - hash collision risk with multiple arguments
function computeHash(uint256 a, uint256 b) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(a, b));
}

// Bad - dynamic types can cause collisions
function computeHash(string memory a, string memory b) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(a, b));
}

// Good - use abi.encode() for hash functions
function computeHash(uint256 a, uint256 b) public pure returns (bytes32) {
    return keccak256(abi.encode(a, b));
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func_expr, args) = expr {
                // Check for abi.encodePacked()
                let is_encode_packed = match func_expr.as_ref() {
                    Expression::MemberAccess(_, _, member) => member.name == "encodePacked",
                    _ => false,
                };

                if is_encode_packed {
                    let has_dynamic_arg = args.iter().any(|arg| Self::is_potentially_dynamic(arg));

                    if has_dynamic_arg {
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

impl UnsafeAbiEncodePackedDetector {
    fn is_potentially_dynamic(expr: &Expression) -> bool {
        match expr {
            // Only numeric literals are safe
            Expression::NumberLiteral(_, _, _, _) |
            Expression::RationalNumberLiteral(_, _, _, _, _) |
            Expression::HexNumberLiteral(_, _, _) |
            Expression::BoolLiteral(_, _) |
            Expression::AddressLiteral(_, _) => false,

            // Everything else is potentially dynamic
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_unsafe_encode_packed() {
        let code = r#"
            contract Test {
                function computeHash(uint256 a, uint256 b) public pure returns (bytes32) {
                    return keccak256(abi.encodePacked(a, b));
                }

                function computeHash2(string memory s1, string memory s2) public pure returns (bytes32) {
                    return keccak256(abi.encodePacked(s1, s2));
                }
            }
        "#;
        let detector = Arc::new(UnsafeAbiEncodePackedDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 4, "abi.encodePacked(a, b)");
        assert_eq!(locations[1].line, 8, "abi.encodePacked(s1, s2)");
    }

    #[test]
    fn test_skips_safe_patterns() {
        let code = r#"
            contract Test {
                function computeHash() public pure returns (bytes32) {
                    return keccak256(abi.encode(1, 2));
                }

                function useEncodePacked() public pure returns (bytes) {
                    return abi.encodePacked(42);
                }

                function useLiterals() public pure returns (bytes32) {
                    return keccak256(abi.encodePacked(123, 456));
                }
            }
        "#;
        let detector = Arc::new(UnsafeAbiEncodePackedDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
