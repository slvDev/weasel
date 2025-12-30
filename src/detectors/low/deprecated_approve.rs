use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use crate::core::visitor::ASTVisitor;
use solang_parser::pt::{Expression, FunctionTy};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DeprecatedApproveDetector;

impl Detector for DeprecatedApproveDetector {
    fn id(&self) -> &'static str {
        "deprecated-approve"
    }

    fn name(&self) -> &str {
        "Deprecated approve() function"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Due to the inheritance of ERC20's approve function, there's a vulnerability to the ERC20 \
         approve and double spend front running attack. Briefly, an authorized spender could spend \
         both allowances by front running an allowance-changing transaction. Consider using \
         OpenZeppelin's SafeERC20 library with `.safeIncreaseAllowance()` and `.safeDecreaseAllowance()` \
         instead of raw `.approve()` calls."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - vulnerable to front-running
function setAllowance(address token, address spender, uint256 amount) external {
    IERC20(token).approve(spender, amount);
}

// Good - use SafeERC20.safeIncreaseAllowance
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

function increaseAllowance(address token, address spender, uint256 amount) external {
    SafeERC20.safeIncreaseAllowance(IERC20(token), spender, amount);
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            // Skip constructors
            if matches!(func_def.ty, FunctionTy::Constructor) {
                return Vec::new();
            }

            let Some(body) = &func_def.body else {
                return Vec::new();
            };

            find_in_statement(body, file, self.id(), |expr| {
                if let Expression::FunctionCall(_, func_expr, _) = expr {
                    if let Expression::MemberAccess(_, _, member) = func_expr.as_ref() {
                        return member.name == "approve";
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
    fn test_detects_approve_call() {
        let code = r#"
            contract Test {
                IERC20 public token;

                function setAllowance(address spender, uint256 amount) external {
                    token.approve(spender, amount);
                }
            }
        "#;
        let detector = Arc::new(DeprecatedApproveDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 6, "approve call");
    }

    #[test]
    fn test_skips_safe_approve() {
        let code = r#"
            import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

            contract Test {
                using SafeERC20 for IERC20;

                function setAllowance(IERC20 token, address spender, uint256 amount) external {
                    token.safeApprove(spender, amount);
                }
            }
        "#;
        let detector = Arc::new(DeprecatedApproveDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
