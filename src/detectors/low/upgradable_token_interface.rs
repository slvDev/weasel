use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Identifier};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UpgradableTokenInterfaceDetector;

impl Detector for UpgradableTokenInterfaceDetector {
    fn id(&self) -> &'static str {
        "upgradable-token-interface"
    }

    fn name(&self) -> &str {
        "Upgradable contracts not taken into account when using token interfaces"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "When casting addresses to token interfaces like IERC20, IERC721, or IERC1155, consider that \
        these tokens may be upgradable contracts. Upgradable tokens can change their behavior or \
        interface over time, potentially leading to compatibility issues or security vulnerabilities. \
        Consider implementing checks for token behavior changes or using wrapper contracts that can \
        adapt to interface modifications."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Flagged - token could be upgradable and change behavior
IERC20(token).transfer(to, value);
IERC721(nft).transferFrom(from, to, tokenId);
IERC1155(token).safeTransferFrom(from, to, id, amount, data);

// Consider:
// - Checking if token is upgradable (proxy pattern)
// - Monitoring for token upgrades
// - Using try/catch for graceful failure handling
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            // Look for type casts: IERC20(addr), IERC721(addr), etc.
            if let Expression::FunctionCall(loc, func_expr, _) = expr {
                if let Expression::Variable(Identifier { name, .. }) = func_expr.as_ref() {
                    let name_lower = name.to_lowercase();
                    if name_lower.contains("ierc20")
                        || name_lower.contains("ierc721")
                        || name_lower.contains("ierc1155")
                    {
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
    fn test_detects_token_interface_casts() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(address token, address nft) public {
                    IERC20(token).transfer(to, value);
                    IERC721(nft).transferFrom(from, to, tokenId);
                    IERC1155(token).safeTransferFrom(from, to, id, amount, data);
                }
            }
        "#;

        let detector = Arc::new(UpgradableTokenInterfaceDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 6, "IERC20 cast");
        assert_eq!(locations[1].line, 7, "IERC721 cast");
        assert_eq!(locations[2].line, 8, "IERC1155 cast");
    }

    #[test]
    fn test_skips_non_token_interfaces() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(address vault, address router) public {
                    IVault(vault).deposit(amount);
                    IRouter(router).swap(tokenIn, tokenOut, amount);
                }
            }
        "#;

        let detector = Arc::new(UpgradableTokenInterfaceDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
