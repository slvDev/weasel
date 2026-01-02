use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct HardcodedAddressDetector;

impl Detector for HardcodedAddressDetector {
    fn id(&self) -> &'static str {
        "hardcoded-address"
    }

    fn name(&self) -> &str {
        "Addresses shouldn't be hard-coded"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Hard-coded addresses reduce code portability across networks. Consider using \
         immutable variables assigned via constructor arguments instead."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
address constant ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;

// Good
address immutable ROUTER;
constructor(address _router) {
    ROUTER = _router;
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            match expr {
                Expression::AddressLiteral(loc, addr) => {
                    if Self::is_real_address(addr) {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(loc, file),
                        }
                        .into();
                    }
                }
                Expression::HexNumberLiteral(loc, val, _) => {
                    let hex_part = val.strip_prefix("0x").unwrap_or(val);
                    if hex_part.len() == 40 && Self::is_real_address(hex_part) {
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

impl HardcodedAddressDetector {
    fn is_real_address(addr: &str) -> bool {
        let addr = addr.strip_prefix("0x").unwrap_or(addr).to_lowercase();

        // Skip zero address
        if addr.chars().all(|c| c == '0') {
            return false;
        }

        // Skip max address (all f's)
        if addr.chars().all(|c| c == 'f') {
            return false;
        }

        // Skip dead address
        // 0x000000000000000000000000000000000000dEaD
        // 0xdead000000000000000000000000000000000000
        if addr.ends_with("dead") || addr.starts_with("dead") {
            let non_dead = addr.replace("dead", "");
            if non_dead.chars().all(|c| c == '0') {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_hardcoded_addresses() {
        let code = r#"
            contract Test {
                address constant ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
                address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

                function getRouter() external pure returns (address) {
                    return 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
                }
            }
        "#;
        let detector = Arc::new(HardcodedAddressDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 3, "ROUTER constant");
        assert_eq!(locations[1].line, 4, "WETH constant");
        assert_eq!(locations[2].line, 7, "return address");
    }

    #[test]
    fn test_skips_special_addresses() {
        let code = r#"
            contract Test {
                address constant ZERO = address(0);
                address constant DEAD = 0x000000000000000000000000000000000000dEaD;
                address constant MAX = 0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF;

                function check(address a) external pure {
                    require(a != address(0), "Zero");
                }
            }
        "#;
        let detector = Arc::new(HardcodedAddressDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
