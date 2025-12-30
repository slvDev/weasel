use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use crate::core::visitor::ASTVisitor;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DeprecatedSafeApproveDetector;

impl Detector for DeprecatedSafeApproveDetector {
    fn id(&self) -> &'static str {
        "deprecated-safe-approve"
    }

    fn name(&self) -> &str {
        "Do not use deprecated `safeApprove` function"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "OpenZeppelin's `safeApprove()` function has been deprecated in favor of `safeIncreaseAllowance()` \
         and `safeDecreaseAllowance()`. The `safeApprove()` function requires that the allowance is either \
         zero or being set to zero, which reverts when changing from non-zero to non-zero. This restriction \
         causes issues in legitimate use cases and doesn't actually solve the front-running problem it was \
         designed for. Use `safeIncreaseAllowance()` and `safeDecreaseAllowance()` for atomic allowance changes."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - uses deprecated safeApprove
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

function setAllowance(IERC20 token, address spender, uint256 amount) external {
    SafeERC20.safeApprove(token, spender, amount);
}

// Good - use safeIncreaseAllowance/safeDecreaseAllowance
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

function increaseAllowance(IERC20 token, address spender, uint256 amount) external {
    SafeERC20.safeIncreaseAllowance(token, spender, amount);
}

function decreaseAllowance(IERC20 token, address spender, uint256 amount) external {
    SafeERC20.safeDecreaseAllowance(token, spender, amount);
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

            find_in_statement(body, file, self.id(), |expr| {
                if let Expression::FunctionCall(_, func_expr, _) = expr {
                    if let Expression::MemberAccess(_, _, member) = func_expr.as_ref() {
                        return member.name == "safeApprove";
                    }
                }
                false
            })
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_safe_approve() {
        let code = r#"
            import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

            contract Test {
                using SafeERC20 for IERC20;

                function setAllowance(IERC20 token, address spender, uint256 amount) external {
                    token.safeApprove(spender, amount);
                }
            }
        "#;
        let detector = Arc::new(DeprecatedSafeApproveDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 8, "safeApprove call");
    }

    #[test]
    fn test_skips_safe_increase_allowance() {
        let code = r#"
            import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

            contract Test {
                using SafeERC20 for IERC20;

                function increaseAllowance(IERC20 token, address spender, uint256 amount) external {
                    token.safeIncreaseAllowance(spender, amount);
                }
            }
        "#;
        let detector = Arc::new(DeprecatedSafeApproveDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
