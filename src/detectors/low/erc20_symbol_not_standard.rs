use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct Erc20SymbolNotStandardDetector;

impl Detector for Erc20SymbolNotStandardDetector {
    fn id(&self) -> &'static str {
        "erc20-symbol-not-standard"
    }

    fn name(&self) -> &str {
        "`symbol()` is not a part of the ERC-20 standard"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "The `symbol()` function is not a part of the ERC-20 standard, and was added later as an \
         optional extension. As such, some valid ERC20 tokens do not support this interface, so it \
         is unsafe to blindly cast all tokens to this interface, and then call this function. \
         Consider using IERC20Metadata interface or checking for support before calling. \
         References: https://eips.ethereum.org/EIPS/eip-20, \
         https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/extensions/IERC20Metadata.sol"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - symbol() may not exist on all ERC20 tokens
function getTokenSymbol(address tokenAddress) public view returns (string memory) {
    IERC20 token = IERC20(tokenAddress);
    return token.symbol();  // May revert on valid ERC20 tokens
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(_, func_expr, args) = expr {
                if let Expression::MemberAccess(_, _, member) = func_expr.as_ref() {
                    if member.name == "symbol" && args.is_empty() {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(&member.loc, file),
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
    fn test_detects_symbol_call() {
        let code = r#"
            contract Test {
                function getSymbol(address token) public view returns (string memory) {
                    return IERC20(token).symbol();
                }

                function processToken(IERC20 token) public {
                    string memory sym = token.symbol();
                }
            }
        "#;
        let detector = Arc::new(Erc20SymbolNotStandardDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 4, "symbol() call on cast");
        assert_eq!(locations[1].line, 8, "symbol() call on variable");
    }

    #[test]
    fn test_skips_non_symbol_calls() {
        let code = r#"
            contract Test {
                function getName(address token) public view returns (string memory) {
                    return IERC20Metadata(token).name();
                }

                function getDecimals(IERC20 token) public view returns (uint8) {
                    return token.decimals();
                }
            }
        "#;
        let detector = Arc::new(Erc20SymbolNotStandardDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
