use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Type};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct AddressZeroCheckDetector;

impl Detector for AddressZeroCheckDetector {
    fn id(&self) -> &'static str {
        "address-zero-check"
    }

    fn name(&self) -> &str {
        "Use assembly to check for address(0)"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Using assembly to check for address(0) saves 6 gas per instance."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Less efficient - 6 more gas
require(owner != address(0), "Invalid address");
if (recipient == address(0)) { revert(); }

// More efficient - using assembly
assembly {
    if iszero(owner) { revert(0, 0) }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            // Check for == or != comparisons with address(0)
            match expr {
                Expression::Equal(loc, left, right) | Expression::NotEqual(loc, left, right) => {
                    if self.is_address_zero(left) || self.is_address_zero(right) {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(loc, file),
                        }
                        .into();
                    }
                }
                _ => {}
            }
            
            Vec::new()
        });
    }
}

impl AddressZeroCheckDetector {
    fn is_address_zero(&self, expr: &Expression) -> bool {
        if let Expression::FunctionCall(_, func, args) = expr {
            if args.len() == 1 {
                let is_address = match func.as_ref() {
                    Expression::Type(_, ty) => {
                        matches!(ty, Type::Address | Type::AddressPayable)
                    }
                    Expression::Variable(var) => var.name == "address",
                    _ => false,
                };
                
                if is_address {
                    match &args[0] {
                        // Check if argument is literal 0 (number or hex)
                        Expression::NumberLiteral(_, num, _, _) => {
                            return num == "0";
                        }
                        // Check if hex literal is zero (0x0, 0x00, etc.)
                        Expression::HexLiteral(hex_vec) => {
                            return hex_vec.iter().all(|h| h.hex.starts_with("0x0"));
                        }
                        _ => {}
                    }
                }
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
    fn test_address_zero_check() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract AddressCheck {
                address public owner;
                
                function setOwner(address newOwner) public {
                    // Bad - comparison with address(0)
                    require(newOwner != address(0), "Invalid address");
                    owner = newOwner;
                }
                
                function checkRecipient(address recipient) public pure {
                    // Bad - comparison with address(0)
                    if (recipient == address(0)) {
                        revert("Zero address");
                    }
                }
                
                function isZeroAddress(address addr) public pure returns (bool) {
                    // Bad - comparison with address(0)
                    return addr == address(0);
                }
                
                function normalComparison(address a, address b) public pure returns (bool) {
                    // OK - comparing two addresses, not with address(0)
                    return a == b;
                }
                
                function numberComparison(uint256 value) public pure returns (bool) {
                    // OK - not address comparison
                    return value == 0;
                }
            }
        "#;

        let detector = Arc::new(AddressZeroCheckDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3, "Should detect 3 address(0) comparisons");
        assert_eq!(locations[0].line, 9, "First address(0) check in require");
        assert_eq!(locations[1].line, 15, "Second address(0) check in if");
        assert_eq!(locations[2].line, 22, "Third address(0) check in return");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract NoAddressZero {
                function compare(address a, address b) public pure returns (bool) {
                    // OK - not comparing with address(0)
                    return a == b;
                }
                
                function checkValue(uint256 value) public pure returns (bool) {
                    // OK - not an address comparison
                    return value != 0;
                }
                
                function checkAddress(address addr) public pure returns (bool) {
                    // OK - not comparing with address(0), just checking existence
                    return addr != msg.sender;
                }
            }
        "#;

        let detector = Arc::new(AddressZeroCheckDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0, "Should not detect any address(0) comparisons");
    }
}