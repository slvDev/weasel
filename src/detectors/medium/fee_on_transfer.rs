use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::{ast_utils, location::loc_to_location};
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct FeeOnTransferDetector;

impl Detector for FeeOnTransferDetector {
    fn id(&self) -> &'static str {
        "fee-on-transfer"
    }

    fn name(&self) -> &str {
        "Contracts are vulnerable to fee-on-transfer accounting-related issues"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "Consistently check account balance before and after transfers for Fee-On-Transfer discrepancies. \
        As arbitrary ERC20 tokens can be used, the amount here should be calculated every time to take into \
        consideration a possible fee-on-transfer or deflation. Use the balance before and after the transfer \
        to calculate the received amount instead of assuming that it would be equal to the amount passed as a parameter."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - assumes received amount equals sent amount:
IERC20(token).transferFrom(msg.sender, address(this), amount);
totalDeposits += amount; // Wrong! May have received less

// Good - checks actual received amount:
uint256 balanceBefore = IERC20(token).balanceOf(address(this));
IERC20(token).transferFrom(msg.sender, address(this), amount);
uint256 balanceAfter = IERC20(token).balanceOf(address(this));
uint256 actualReceived = balanceAfter - balanceBefore;
totalDeposits += actualReceived;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func_expr, args) = expr {
                // Check for transferFrom or safeTransferFrom
                if let Expression::MemberAccess(_, base_expr, member) = func_expr.as_ref() {
                    if member.name != "transferFrom" && member.name != "safeTransferFrom" {
                        return Vec::new();
                    }
                    
                    // Check if recipient is address(this) - look in the second argument
                    if args.len() < 2 {
                        return Vec::new();
                    }
                    
                    // Check if second argument contains address(this)
                    if ast_utils::contains_address_this(&args[1]) {
                        // Check if this looks like an ERC20 token transfer
                        if ast_utils::is_likely_erc20_token(base_expr) {
                            return FindingData {
                                detector_id: self.id(),
                                location: loc_to_location(&loc, file),
                            }
                            .into();
                        }
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
    fn test_fee_on_transfer() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            interface IERC20 {
                function transferFrom(address from, address to, uint256 amount) external returns (bool);
                function safeTransferFrom(address from, address to, uint256 amount) external;
                function balanceOf(address account) external view returns (uint256);
            }
            
            contract Vault {
                IERC20 public token;
                mapping(address => uint256) public deposits;
                
                function deposit(uint256 amount) external {
                    // Should detect - transferring to address(this) without checking balance
                    token.transferFrom(msg.sender, address(this), amount);
                    deposits[msg.sender] += amount; // Wrong! Assumes full amount received
                }
                
                function depositWithCast(address tokenAddr, uint256 amount) external {
                    // Should detect - cast to IERC20
                    IERC20(tokenAddr).transferFrom(msg.sender, address(this), amount);
                    deposits[msg.sender] += amount;
                }
                
                function safeDeposit(uint256 amount) external {
                    // Should detect - safeTransferFrom also affected
                    token.safeTransferFrom(msg.sender, address(this), amount);
                    deposits[msg.sender] += amount;
                }
                
                function goodDeposit(uint256 amount) external {
                    uint256 balanceBefore = token.balanceOf(address(this));
                    token.transferFrom(msg.sender, address(this), amount);
                    uint256 balanceAfter = token.balanceOf(address(this));
                    uint256 actualReceived = balanceAfter - balanceBefore;
                    deposits[msg.sender] += actualReceived; // Correct!
                }
                
                function transferToOther(address recipient, uint256 amount) external {
                    // Should NOT detect - not transferring to address(this)
                    token.transferFrom(msg.sender, recipient, amount);
                }
                
                function notToken(address someContract) external {
                    // Should NOT detect - not likely a token
                    ISomething(someContract).transferFrom(msg.sender, address(this), 100);
                }
            }
        "#;

        let detector = Arc::new(FeeOnTransferDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4, "Should detect 4 transfers to address(this)");
        assert_eq!(locations[0].line, 16, "deposit function");
        assert_eq!(locations[1].line, 22, "depositWithCast function");
        assert_eq!(locations[2].line, 28, "safeDeposit function");
        assert_eq!(locations[3].line, 34, "goodDeposit also needs checking");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract Test {
                function transferFrom(address from, address to, uint256 amount) public {
                    // Function definition, not a call - should NOT detect
                }
                
                function test() public {
                    // Should NOT detect - no address(this)
                    token.transferFrom(sender, recipient, amount);
                    
                    // Should NOT detect - not a transfer function
                    something.doSomething(address(this));
                }
            }
        "#;

        let detector = Arc::new(FeeOnTransferDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0, "Should not detect any false positives");
    }
}