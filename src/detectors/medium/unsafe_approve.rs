use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnsafeApproveDetector;

impl Detector for UnsafeApproveDetector {
    fn id(&self) -> &'static str {
        "unsafe-approve"
    }

    fn name(&self) -> &str {
        "`approve()`/`safeApprove()` may revert if current approval is not zero"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "Some tokens (like USDT) revert when changing allowance from non-zero to non-zero value. \
        This is a protection against front-running attacks. These tokens require first setting approval to 0, \
        then to the desired value. Additionally, OpenZeppelin's `safeApprove` will revert with \
        'SafeERC20: approve from non-zero to non-zero allowance'. Always reset approval to zero before setting a new value."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - may revert for tokens like USDT
token.approve(spender, newAmount);
token.safeApprove(spender, newAmount);

// Good - reset to 0 first
token.approve(spender, 0);
token.approve(spender, newAmount);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func_expr, _) = expr {
                if let Expression::MemberAccess(_, _, member) = func_expr.as_ref() {
                    let func_name = &member.name;
                    // Check for approve() or safeApprove() calls
                    if func_name == "approve" || func_name == "safeApprove" {
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
    fn test_unsafe_approve_detection() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            interface IERC20 {
                function approve(address spender, uint256 amount) external returns (bool);
            }
            
            library SafeERC20 {
                function safeApprove(IERC20 token, address spender, uint256 value) internal {}
            }
            
            contract TestContract {
                using SafeERC20 for IERC20;
                IERC20 public token;
                
                function unsafeApproval(address spender, uint256 amount) public {
                    token.approve(spender, amount);  // Should detect
                }
                
                function unsafeSafeApproval(address spender, uint256 amount) public {
                    token.safeApprove(spender, amount);  // Should detect
                }
                
                function nestedApprove() public {
                    if (true) {
                        token.approve(address(this), 100);  // Should detect
                    }
                }
                
                function goodPattern(address spender, uint256 amount) public {
                    token.approve(spender, 0);  // Should detect (but this is the reset)
                    token.approve(spender, amount);  // Should detect (but follows good pattern)
                }
                
                function notApprove() public {
                    token.transfer(msg.sender, 100);  // Should NOT detect
                    token.allowance(address(this), msg.sender);  // Should NOT detect
                }
            }
        "#;

        let detector = Arc::new(UnsafeApproveDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 5, "Should detect 5 approve/safeApprove calls");
        
        // Check detection lines
        assert_eq!(locations[0].line, 17, "First approve() call");
        assert_eq!(locations[1].line, 21, "safeApprove() call");
        assert_eq!(locations[2].line, 26, "Nested approve() call");
        assert_eq!(locations[3].line, 31, "approve(0) call");
        assert_eq!(locations[4].line, 32, "approve(amount) call");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract TestContract {
                // These should NOT trigger the detector
                function approved() public {}  // Function named approved
                function isApprove() public {}  // Function with approve in name
                function safeApproved() public {}  // Function with safeApprove substring
                
                function test() public {
                    approved();  // Not an approve call
                    isApprove();  // Not an approve call
                    
                    // Other function calls that aren't approve
                    token.transfer(address(this), 100);
                    token.allowance(address(this), msg.sender);
                    token.balanceOf(address(this));
                    
                    // Variable names with approve
                    bool approveResult = true;
                    uint256 approveAmount = 100;
                }
            }
        "#;

        let detector = Arc::new(UnsafeApproveDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            0,
            "Should not detect any false positives"
        );
    }
}