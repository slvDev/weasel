use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::is_likely_erc20_token;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UncheckedTransferDetector;

impl Detector for UncheckedTransferDetector {
    fn id(&self) -> &'static str {
        "unchecked-transfer"
    }

    fn name(&self) -> &str {
        "Return values of transfer()/transferFrom() not checked"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "Not all ERC20 implementations revert() when there's a failure in transfer()/transferFrom(). \
        The function signature has a boolean return value and they indicate errors that way instead. \
        By not checking the return value, operations that should have marked as failed, may potentially \
        go through without actually making a payment."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - return value not checked
token.transfer(recipient, amount);
token.transferFrom(sender, recipient, amount);

// Good - return value checked
bool success = token.transfer(recipient, amount);
require(success, "Transfer failed");

// Also good - using SafeERC20
token.safeTransfer(recipient, amount);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file, _context| {
            // Check for expression statements (direct calls without assignment)
            if let Statement::Expression(loc, expr) = stmt {
                if self.is_unchecked_transfer_call(expr) {
                    return FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(loc, file),
                    }
                    .into();
                }
            }
            
            Vec::new()
        });
    }
}

impl UncheckedTransferDetector {
    fn is_unchecked_transfer_call(&self, expr: &Expression) -> bool {
        // Check if this is a direct function call (not assigned to anything)
        match expr {
            Expression::FunctionCall(_, func, _) => {
                if let Expression::MemberAccess(_, base, member) = func.as_ref() {
                    if member.name == "transfer" || member.name == "transferFrom" {
                        return is_likely_erc20_token(base);
                    }
                }
            }
            _ => {}
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_unchecked_transfer() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            interface IERC20 {
                function transfer(address to, uint256 amount) external returns (bool);
                function transferFrom(address from, address to, uint256 amount) external returns (bool);
            }
            
            contract TokenHandler {
                IERC20 public token;
                
                function badTransfer(address recipient, uint256 amount) public {
                    // Bad - return value not checked
                    token.transfer(recipient, amount);
                }
                
                function badTransferFrom(address sender, address recipient, uint256 amount) public {
                    // Bad - return value not checked
                    token.transferFrom(sender, recipient, amount);
                }
                
                function goodTransfer(address recipient, uint256 amount) public {
                    // Good - return value checked
                    bool success = token.transfer(recipient, amount);
                    require(success, "Transfer failed");
                }
                
                function goodTransferFrom(address sender, address recipient, uint256 amount) public {
                    // Good - return value checked in require
                    require(token.transferFrom(sender, recipient, amount), "Transfer failed");
                }
                
                function ethTransfer(address payable recipient) public {
                    // Should not be flagged - this is ETH transfer
                    recipient.transfer(100);
                }
            }
        "#;

        let detector = Arc::new(UncheckedTransferDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 unchecked transfers");
        assert_eq!(locations[0].line, 14, "First unchecked transfer");
        assert_eq!(locations[1].line, 19, "Second unchecked transferFrom");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract NoTokenTransfers {
                function someFunction() public pure returns (uint256) {
                    uint256 value = 100;
                    return value;
                }
                
                function ethTransfer(address payable recipient) public {
                    // ETH transfer - should not be flagged
                    recipient.transfer(1 ether);
                }
            }
        "#;

        let detector = Arc::new(UncheckedTransferDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}