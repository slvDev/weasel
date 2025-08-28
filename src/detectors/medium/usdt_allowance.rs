use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UsdtAllowanceDetector;

impl Detector for UsdtAllowanceDetector {
    fn id(&self) -> &'static str {
        "usdt-allowance"
    }

    fn name(&self) -> &str {
        "increaseAllowance/decreaseAllowance won't work on mainnet for USDT"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "On mainnet, USDT doesn't support increaseAllowance/decreaseAllowance. \
        USDT reverts on setting a non-zero & non-max allowance unless the allowance is already zero. \
        Use a pattern that sets allowance to 0 first, then to the desired value."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - will revert for USDT:
IERC20(usdt).increaseAllowance(spender, amount);
IERC20(usdt).decreaseAllowance(spender, amount);

// Good - set to 0 first, then desired amount:
IERC20(usdt).approve(spender, 0);
IERC20(usdt).approve(spender, amount);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func_expr, _args) = expr {
                if let Expression::MemberAccess(_, _, member) = func_expr.as_ref() {
                    let name = &member.name;
                    if name == "increaseAllowance" || name == "decreaseAllowance" {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(&loc, file),
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
    fn test_usdt_allowance() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            interface IERC20 {
                function approve(address spender, uint256 amount) external returns (bool);
                function increaseAllowance(address spender, uint256 addedValue) external returns (bool);
                function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool);
            }
            
            contract TokenInteraction {
                IERC20 public usdt;
                
                function increaseUSDTAllowance(address spender, uint256 amount) public {
                    // Should detect - won't work with USDT
                    usdt.increaseAllowance(spender, amount);
                }
                
                function decreaseUSDTAllowance(address spender, uint256 amount) public {
                    // Should detect - won't work with USDT
                    usdt.decreaseAllowance(spender, amount);
                }
                
                function approveUSDT(address spender, uint256 amount) public {
                    // Should NOT detect - standard approve
                    usdt.approve(spender, amount);
                }
                
                function someOtherFunction() public {
                    // Should NOT detect - different function
                    usdt.transfer(address(0), 100);
                }
            }
        "#;

        let detector = Arc::new(UsdtAllowanceDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 problematic calls");
        assert_eq!(locations[0].line, 15, "increaseAllowance detection");
        assert_eq!(locations[1].line, 20, "decreaseAllowance detection");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract Test {
                function increaseAllowance(address spender, uint256 amount) public {
                    // Function definition, not a call - should NOT detect
                }
                
                function decreaseAllowance(address spender, uint256 amount) public {
                    // Function definition, not a call - should NOT detect
                }
                
                function test() public {
                    // Should NOT detect - standard functions
                    token.approve(spender, amount);
                    token.transfer(to, amount);
                    token.transferFrom(from, to, amount);
                }
            }
        "#;

        let detector = Arc::new(UsdtAllowanceDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            0,
            "Should not detect any false positives"
        );
    }
}