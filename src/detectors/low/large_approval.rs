use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use solang_parser::pt::{Expression, Identifier, Type};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct LargeApprovalDetector;

impl Detector for LargeApprovalDetector {
    fn id(&self) -> &'static str {
        "large-approval"
    }

    fn name(&self) -> &str {
        "Large approvals may not work with some ERC20 tokens"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Not all IERC20 implementations are fully compliant. Some tokens (e.g. UNI, COMP) may \
        fail if the value passed to `approve` is larger than `uint96`. Using `type(uint256).max` \
        may cause issues with systems that expect the value to be reflected in allowances mapping."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Potentially problematic with UNI, COMP tokens
token.approve(spender, type(uint256).max);

// Consider using specific amounts or checking token compatibility
token.approve(spender, amount);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func, file, _context| {
            let Some(body) = &func.body else {
                return Vec::new();
            };

            find_in_statement(body, file, self.id(), |expr| {
                if let Expression::FunctionCall(_, func_expr, params) = expr {
                    if let Expression::MemberAccess(_, obj, Identifier { name, .. }) =
                        func_expr.as_ref()
                    {
                        // Skip WETH
                        if let Expression::Variable(Identifier { name: obj_name, .. }) =
                            obj.as_ref()
                        {
                            if obj_name.to_lowercase().contains("weth") {
                                return false;
                            }
                        }

                        // Check for approve or safeApprove with type(uint256).max
                        if (name == "approve" || name == "safeApprove") && !params.is_empty() {
                            if let Some(last) = params.last() {
                                if is_type_max(last) {
                                    return true;
                                }
                            }
                        }
                    }
                }
                false
            })
        });
    }
}

/// Check if expression is `type(uintN).max` where N > 96
fn is_type_max(expr: &Expression) -> bool {
    if let Expression::MemberAccess(_, base, Identifier { name, .. }) = expr {
        if name == "max" {
            if let Expression::FunctionCall(_, func, args) = base.as_ref() {
                if let Expression::Variable(Identifier {
                    name: func_name, ..
                }) = func.as_ref()
                {
                    if func_name == "type" && args.len() == 1 {
                        // Check if arg is uint type larger than 96 bits
                        if let Some(Expression::Type(_, Type::Uint(bits))) = args.first() {
                            return *bits > 96;
                        }
                    }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_large_approval() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(address token) public {
                    IERC20(token).approve(spender, type(uint256).max);
                }
            }
        "#;

        let detector = Arc::new(LargeApprovalDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 6, "approve with type(uint256).max");
    }

    #[test]
    fn test_skips_weth() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test() public {
                    WETH.approve(spender, type(uint256).max);
                    weth.approve(spender, type(uint256).max);
                    token.approve(spender, type(uint96).max);
                }
            }
        "#;

        let detector = Arc::new(LargeApprovalDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
