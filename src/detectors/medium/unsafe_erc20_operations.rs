use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnsafeErc20OperationsDetector;

impl Detector for UnsafeErc20OperationsDetector {
    fn id(&self) -> &'static str {
        "unsafe-erc20-operations"
    }

    fn name(&self) -> &str {
        "Unsafe use of transfer()/transferFrom() with IERC20"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "Some tokens do not implement the ERC20 standard properly but are still accepted by most code \
        that accepts ERC20 tokens. For example Tether (USDT)'s transfer() and transferFrom() functions \
        on L1 do not return booleans as the specification requires, and instead have no return value. \
        When these sorts of tokens are cast to IERC20, their function signatures do not match and \
        therefore the calls made, revert. Use OpenZeppelin's SafeERC20's safeTransfer()/safeTransferFrom() instead."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - direct call on IERC20 interface
IERC20(token).transfer(recipient, amount);
bool success = IERC20(token).transferFrom(sender, recipient, amount);

// Good - using SafeERC20
using SafeERC20 for IERC20;
IERC20(token).safeTransfer(recipient, amount);
IERC20(token).safeTransferFrom(sender, recipient, amount);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file, _context| {
            match stmt {
                Statement::Expression(loc, expr) | Statement::VariableDefinition(loc, _, Some(expr)) => {
                    if self.check_expression_for_unsafe_call(expr) {
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

impl UnsafeErc20OperationsDetector {
    fn check_expression_for_unsafe_call(&self, expr: &Expression) -> bool {
        match expr {
            // Check assignments like: bool success = IERC20(token).transfer(...)
            Expression::Assign(_, _, right) => self.check_expression_for_unsafe_call(right),
            
            // Check function calls
            Expression::FunctionCall(_, func, args) => {
                // First check if this call itself is an unsafe transfer/transferFrom
                if let Expression::MemberAccess(_, base, member) = func.as_ref() {
                    // Check if it's transfer or transferFrom
                    if member.name == "transfer" || member.name == "transferFrom" {
                        // Check if base is an IERC20 cast
                        return self.is_ierc20_cast(base);
                    }
                }
                
                // check arguments for nested unsafe calls (eg require(IERC20(token).transfer(...)))
                args.iter().any(|arg| self.check_expression_for_unsafe_call(arg))
            }
            
            _ => false
        }
    }
    
    fn is_ierc20_cast(&self, expr: &Expression) -> bool {
        match expr {
            Expression::FunctionCall(_, func, _) => {
                if let Expression::Variable(var) = func.as_ref() {
                    let name = &var.name;
                    return name == "IERC20" || name == "ERC20";
                }
                false
            }
            _ => false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_unsafe_erc20_operations() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            interface IERC20 {
                function transfer(address to, uint256 amount) external returns (bool);
                function transferFrom(address from, address to, uint256 amount) external returns (bool);
            }
            
            contract UnsafeTokenHandler {
                function badTransfer1(address token, address recipient, uint256 amount) public {
                    // Bad - direct cast and call
                    IERC20(token).transfer(recipient, amount);
                }
                
                function badTransfer2(address token, address recipient, uint256 amount) public {
                    // Bad - even with return value check
                    bool success = IERC20(token).transfer(recipient, amount);
                    require(success, "Transfer failed");
                }
                
                function badTransferFrom(address token, address sender, address recipient, uint256 amount) public {
                    // Bad - direct cast and call
                    require(IERC20(token).transferFrom(sender, recipient, amount), "Transfer failed");
                }
                
                function normalTokenTransfer(address token, address recipient, uint256 amount) public {
                    // This won't be flagged - not an explicit cast
                    // Only explicit IERC20(token) casts are flagged
                    bool success = token.call(abi.encodeWithSignature("transfer(address,uint256)", recipient, amount));
                }
            }
        "#;

        let detector = Arc::new(UnsafeErc20OperationsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3, "Should detect 3 unsafe ERC20 cast operations");
        assert_eq!(locations[0].line, 12, "First unsafe transfer");
        assert_eq!(locations[1].line, 17, "Second unsafe transfer with check");
        assert_eq!(locations[2].line, 23, "Unsafe transferFrom in require");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            library SafeERC20 {
                function safeTransfer(address token, address to, uint256 value) internal {
                    // Implementation
                }
            }
            
            contract SafeTokenHandler {
                using SafeERC20 for address;
                
                function safeTransfer(address token, address recipient, uint256 amount) public {
                    // Good - using SafeERC20 (would be safeTransfer in real code)
                    // This is just a mock, won't be flagged
                    token.safeTransfer(recipient, amount);
                }
                
                function ethTransfer(address payable recipient) public {
                    // ETH transfer - should not be flagged
                    recipient.transfer(1 ether);
                }
            }
        "#;

        let detector = Arc::new(UnsafeErc20OperationsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}