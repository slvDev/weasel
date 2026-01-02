use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::{find_in_statement, is_likely_erc20_token};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ZeroValueTransferDetector;

impl Detector for ZeroValueTransferDetector {
    fn id(&self) -> &'static str {
        "zero-value-transfer"
    }

    fn name(&self) -> &str {
        "ERC20 transfer may revert on zero value"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Some ERC20 tokens (like LEND) revert when zero-value transfers are made, which may \
         cause batch operations to fail. Consider skipping the transfer if the amount is zero, \
         which will also save gas."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - may revert on zero amount
token.transfer(to, amount);

// Good - skip zero transfers
if (amount > 0) {
    token.transfer(to, amount);
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            let Some(body) = &func_def.body else {
                return Vec::new();
            };

            find_in_statement(body, file, self.id(), |expr| Self::is_erc20_transfer(expr))
        });
    }
}

impl ZeroValueTransferDetector {
    /// Transfer method names that could revert on zero
    const TRANSFER_METHODS: &'static [&'static str] = &[
        "transfer",
        "transferFrom",
        "safeTransfer",
        "safeTransferFrom",
    ];

    /// Checks if expression is an ERC20 transfer call
    fn is_erc20_transfer(expr: &Expression) -> bool {
        if let Expression::FunctionCall(_, func, _) = expr {
            if let Expression::MemberAccess(_, base, member) = func.as_ref() {
                // Check if method is a transfer method
                if !Self::TRANSFER_METHODS.contains(&member.name.as_str()) {
                    return false;
                }

                // Check if base looks like an ERC20 token using helper
                return is_likely_erc20_token(base.as_ref());
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
    fn test_detects_zero_value_transfers() {
        let code = r#"
            interface IERC20 {
                function transfer(address to, uint256 amount) external;
                function transferFrom(address from, address to, uint256 amount) external;
            }

            contract Test {
                IERC20 public token;

                function bad1(address to, uint256 amount) public {
                    token.transfer(to, amount);
                }

                function bad2(address from, address to, uint256 amount) public {
                    token.transferFrom(from, to, amount);
                }

                function bad3(IERC20 _token, address to, uint256 amount) public {
                    _token.transfer(to, amount);
                }

                function bad4(address tokenAddr, address to, uint256 amount) public {
                    IERC20(tokenAddr).transfer(to, amount);
                }
            }
        "#;
        let detector = Arc::new(ZeroValueTransferDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].line, 11, "token.transfer");
        assert_eq!(locations[1].line, 15, "token.transferFrom");
        assert_eq!(locations[2].line, 19, "_token.transfer");
        assert_eq!(locations[3].line, 23, "IERC20(tokenAddr).transfer");
    }

    #[test]
    fn test_skips_non_erc20_transfers() {
        let code = r#"
            contract Test {
                mapping(address => uint256) public balances;

                function notToken(address to, uint256 amount) public {
                    // Not an ERC20 call - using non-token variable
                    payable(to).transfer(amount);
                }

                function notTransfer() public view returns (uint256) {
                    return balances[msg.sender];
                }
            }
        "#;
        let detector = Arc::new(ZeroValueTransferDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
