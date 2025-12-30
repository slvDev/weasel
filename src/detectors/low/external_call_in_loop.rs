use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use crate::core::visitor::ASTVisitor;
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ExternalCallInLoopDetector;

impl Detector for ExternalCallInLoopDetector {
    fn id(&self) -> &'static str {
        "external-call-in-loop"
    }

    fn name(&self) -> &str {
        "External calls in an un-bounded `for-`loop may result in a DOS"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Consider limiting the number of iterations in for-loops that make external calls. \
         External calls on array elements within unbounded loops can lead to denial-of-service \
         if the array grows too large, as each iteration consumes gas and may fail or become \
         prohibitively expensive."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - unbounded loop with external calls
function distributeRewards(address[] memory recipients) public {
    for (uint i = 0; i < recipients.length; i++) {
        recipients[i].transfer(reward);  // External call in loop
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file, _context| {
            let Statement::For(_, _, cond, _, Some(body)) = stmt else {
                return Vec::new();
            };

            // Check if loop condition uses .length (unbounded loop)
            let has_length_check = cond.as_ref().map_or(false, |c| Self::uses_length(c));

            if !has_length_check {
                return Vec::new();
            }

            // Find external function calls in for-loop body
            find_in_statement(body, file, self.id(), |expr| {
                // Check for member access function calls (external calls)
                if let Expression::FunctionCall(_, func_expr, _) = expr {
                    return matches!(func_expr.as_ref(), Expression::MemberAccess(_, _, _));
                }
                false
            })
        });
    }
}

impl ExternalCallInLoopDetector {
    fn uses_length(expr: &Expression) -> bool {
        match expr {
            Expression::MemberAccess(_, _, member) => member.name == "length",
            Expression::Less(_, left, right)
            | Expression::LessEqual(_, left, right)
            | Expression::More(_, left, right)
            | Expression::MoreEqual(_, left, right) => {
                Self::uses_length(left) || Self::uses_length(right)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_external_call_in_loop() {
        let code = r#"
            contract Test {
                IERC20[] public tokens;
                ISomeContract public someContract;

                function distribute(address[] memory recipients) public {
                    for (uint i = 0; i < recipients.length; i++) {
                        recipients[i].transfer(1 ether);
                        someContract.callExternal();
                    }

                    for (uint j = 0; j < tokens.length; j++) {
                        tokens[j].balanceOf(msg.sender);
                    }
                }
            }
        "#;
        let detector = Arc::new(ExternalCallInLoopDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 8, "transfer on array element");
        assert_eq!(locations[1].line, 9, "external call in loop");
        assert_eq!(locations[2].line, 13, "balanceOf on array element");
    }

    #[test]
    fn test_skips_bounded_loops() {
        let code = r#"
            contract Test {
                address wallet;
                address[] recipients;

                function loopWithNonArrayCall() public {
                    for (uint i = 0; i < 10; i++) {
                        wallet.transfer(1 ether);
                    }
                }

                function callOutsideLoop(address[] memory addrs) public {
                    addrs[0].transfer(1 ether);
                }

                function stateArrayAccess() public {
                    recipients[0].transfer(1 ether);
                }
            }
        "#;
        let detector = Arc::new(ExternalCallInLoopDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
