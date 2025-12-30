use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct Erc20DecimalsDetector;

impl Detector for Erc20DecimalsDetector {
    fn id(&self) -> &'static str {
        "erc20-decimals-not-standard"
    }

    fn name(&self) -> &str {
        "`decimals()` is not a part of the ERC-20 standard"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "The `decimals()` function is not a part of the ERC-20 standard (https://eips.ethereum.org/EIPS/eip-20), \
         and was added later as an optional extension \
         (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/extensions/IERC20Metadata.sol). \
         As such, some valid ERC20 tokens do not support this interface, so it is unsafe to blindly cast all tokens \
         to this interface, and then call this function."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - assumes all ERC20 tokens have decimals()
function getTokenDecimals(address token) public view returns (uint8) {
    return IERC20(token).decimals(); // May revert for some valid ERC20 tokens
}

// Good - use try/catch or check if token supports IERC20Metadata
function getTokenDecimals(address token) public view returns (uint8) {
    try IERC20Metadata(token).decimals() returns (uint8 decimals) {
        return decimals;
    } catch {
        return 18; // Default fallback
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func_expr, args) = expr {
                if let Expression::MemberAccess(_, _, member) = func_expr.as_ref() {
                    // Check for .decimals() with no arguments
                    if member.name == "decimals" && args.is_empty() {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_decimals_call() {
        let code = r#"
            interface IERC20 {
                function decimals() external view returns (uint8);
            }

            contract Test {
                function getDecimals(address token) public view returns (uint8) {
                    return IERC20(token).decimals();
                }
            }
        "#;
        let detector = Arc::new(Erc20DecimalsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 8, "decimals() call");
    }

    #[test]
    fn test_skips_safe_patterns() {
        let code = r#"
            interface IERC20 {
                function transfer(address to, uint256 amount) external returns (bool);
                function balanceOf(address account) external view returns (uint256);
            }

            contract Test {
                function transfer(address token, address to, uint256 amount) public {
                    IERC20(token).transfer(to, amount);
                }

                function getBalance(address token, address account) public view returns (uint256) {
                    return IERC20(token).balanceOf(account);
                }
            }
        "#;
        let detector = Arc::new(Erc20DecimalsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
