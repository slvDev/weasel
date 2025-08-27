use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Loc, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct MsgValueInLoopDetector;

impl Detector for MsgValueInLoopDetector {
    fn id(&self) -> &'static str {
        "msg-value-in-loop"
    }

    fn name(&self) -> &str {
        "Use of `msg.value` inside a loop"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &str {
        "Reading `msg.value` inside a loop is dangerous. If the loop executes multiple times, \
        the full `msg.value` might be credited or used in calculations repeatedly, \
        leading to incorrect accounting or potential exploits. \
        Read `msg.value` once into a local variable *before* the loop."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
function distributePayment(address[] calldata addresses) external payable {
    uint amountPerRecipient = msg.value / addresses.length; // Calculated once, good.
    for (uint i = 0; i < addresses.length; i++) {
        // If a recipient calls back, msg.value is read again.
        require(msg.value > 0, "Payment required"); // Reads msg.value in loop
        payable(addresses[i]).transfer(amountPerRecipient);
    }
}

// Good
function distributePaymentFixed(address[] calldata addresses) external payable {
    uint totalPayment = msg.value; // Read once before loop
    require(totalPayment > 0, "Payment required");
    require(addresses.length > 0, "No recipients");
    uint amountPerRecipient = totalPayment / addresses.length;

    for (uint i = 0; i < addresses.length; i++) {
         payable(addresses[i]).transfer(amountPerRecipient);
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file, _context| {
            // Extract loop body if this is a loop statement
            let loop_body = match stmt {
                Statement::For(_, _, _, _, Some(body)) => Some(body.as_ref()),
                Statement::While(_, _, body) | Statement::DoWhile(_, body, _) => {
                    Some(body.as_ref())
                }
                _ => None,
            };

            // If not a loop, nothing to check
            let Some(body) = loop_body else {
                return Vec::new();
            };

            // Define predicate to find msg.value expressions
            let mut is_msg_value = |expr: &Expression, _: &_| -> Option<Loc> {
                if let Expression::MemberAccess(loc, base_expr, member) = expr {
                    if member.name == "value" {
                        if let Expression::Variable(base_var) = base_expr.as_ref() {
                            if base_var.name == "msg" {
                                return Some(loc.clone());
                            }
                        }
                    }
                }
                None
            };

            // Search for msg.value in the loop body
            let mut msg_value_locations = Vec::new();
            ast_utils::find_locations_in_statement(
                body,
                file,
                &mut is_msg_value,
                &mut msg_value_locations,
            );

            // Convert found locations to findings
            msg_value_locations
                .into_iter()
                .map(|location| FindingData {
                    detector_id: self.id(),
                    location,
                })
                .collect()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_msg_value_in_loop_detector() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract TestMsgValueInLoop {

                function badForLoop(uint count) external payable {
                    for (uint i = 0; i < count; i++) {
                        require(msg.value > 1 ether, "Must send > 1"); // Positive
                        payable(msg.sender).transfer(1 wei); 
                    }
                }

                function badWhileLoop(uint count) external payable {
                    while (i < count) {
                        bool check = msg.value > 0; // Positive
                        require(check, "Pay up");
                        i++;
                    }
                }

                function badDoWhileLoop(uint count) external payable {
                    do {
                        uint payment = msg.value; // Positive
                        require(payment > 0);
                        i++;
                    } while (i < count);
                }

                function okLoop() external payable {
                    uint paid = msg.value; // Negative
                    for (uint i = 0; i < 3; i++) {
                        require(paid > 0);
                    }
                }
                
                function okOutsideLoop() external payable {
                     require(msg.value > 0); // Negative
                }
                
                function otherMsgMembers(uint count) external payable {
                    for (uint i = 0; i < count; i++) {
                        address sender = msg.sender; // Negative
                        bytes calldata data = msg.data; // Negative
                    }
                }
            }
        "#;

        let detector = Arc::new(MsgValueInLoopDetector::default());
        let locations = run_detector_on_code(detector.clone(), code, "msg_value_loop_test.sol");

        assert_eq!(locations.len(), 3, "Should detect 3 issues");

        assert_eq!(locations[0].line, 8, "Finding in badForLoop expected");
        assert_eq!(locations[1].line, 15, "Finding in badWhileLoop expected");
        assert_eq!(locations[2].line, 23, "Finding in badDoWhileLoop expected");

        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("msg.value"),
            "Snippet for badForLoop is incorrect"
        );
    }
}
