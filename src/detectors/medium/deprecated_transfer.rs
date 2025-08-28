use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DeprecatedTransferDetector;

impl Detector for DeprecatedTransferDetector {
    fn id(&self) -> &'static str {
        "deprecated-transfer"
    }

    fn name(&self) -> &str {
        "call() should be used instead of transfer() on address payable"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "The use of the deprecated transfer() function for an address may make the transaction fail \
        due to the 2300 gas stipend. Use call() instead which allows specifying gas and handles return values properly."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - limited to 2300 gas:
payable(recipient).transfer(amount);

// Good - flexible gas usage:
(bool success, ) = payable(recipient).call{value: amount}("");
require(success, "Transfer failed");
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func_expr, args) = expr {
                if args.len() != 1 {
                    return Vec::new();
                }
                
                if let Expression::MemberAccess(_, _, member) = func_expr.as_ref() {
                    if member.name == "transfer" {
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
    fn test_deprecated_transfer() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract Test {
                address payable public recipient;
                
                function badTransfer(uint256 amount) public {
                    // Should detect - using transfer
                    recipient.transfer(amount);
                }
                
                function anotherBadTransfer() public {
                    // Should detect - transfer with inline address
                    payable(msg.sender).transfer(100);
                }
                
                function complexBadTransfer(address payable to) public {
                    // Should detect
                    to.transfer(address(this).balance);
                }
                
                function goodTransfer(uint256 amount) public {
                    // Should NOT detect - using call
                    (bool success, ) = recipient.call{value: amount}("");
                    require(success, "Transfer failed");
                }
                
                function notTransfer() public {
                    // Should NOT detect - different function name
                    recipient.send(100);
                    someOtherTransfer();
                }
                
                function transferWithTwoArgs() public {
                    // Should NOT detect - transfer with wrong number of args
                    something.transfer(100, 200);
                }
            }
        "#;

        let detector = Arc::new(DeprecatedTransferDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3, "Should detect 3 uses of transfer()");
        
        // Verify detection at correct lines
        assert_eq!(locations[0].line, 9, "First detection in badTransfer()");
        assert_eq!(locations[1].line, 14, "Second detection in anotherBadTransfer()");
        assert_eq!(locations[2].line, 19, "Third detection in complexBadTransfer()");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract Test {
                function transfer(address to, uint256 amount) public {
                    // Function definition, not a call - should NOT detect
                }
                
                function test() public {
                    // Should NOT detect - transfer with wrong args count
                    token.transfer(recipient, amount);
                    
                    // Should NOT detect - using call
                    (bool success, ) = payable(recipient).call{value: 1 ether}("");
                    
                    // Should NOT detect - using send
                    payable(recipient).send(100);
                }
            }
        "#;

        let detector = Arc::new(DeprecatedTransferDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            0,
            "Should not detect any false positives"
        );
    }
}