use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct SweepTokenAccountingDetector;

impl Detector for SweepTokenAccountingDetector {
    fn id(&self) -> &'static str {
        "sweep-token-accounting"
    }

    fn name(&self) -> &str {
        "Sweeping may break accounting if tokens with multiple addresses are used"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "There have been cases where tokens mistakenly had two addresses that could control their \
         balance, and transfers using one address impacted the balance of the other. Sweep/recover/rescue \
         functions should ensure the balance of non-sweepable tokens does not change after transfer."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no balance check before/after sweep
function sweep(IERC20 token) external {
    token.transfer(owner, token.balanceOf(address(this)));
}

// Good - verify critical token balances unchanged
function sweep(IERC20 token) external {
    uint256 protectedBefore = protectedToken.balanceOf(address(this));
    token.transfer(owner, token.balanceOf(address(this)));
    require(protectedToken.balanceOf(address(this)) == protectedBefore);
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            let Some(name) = &func_def.name else {
                return Vec::new();
            };

            if Self::is_sweep_function(&name.name) {
                return vec![FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&func_def.loc, file),
                }];
            }

            Vec::new()
        });
    }
}

impl SweepTokenAccountingDetector {
    /// Checks if function name matches sweep/recover/rescue patterns
    /// Regex: /sweep|recover(ERC|Token)|rescue(ERC|Token)/gi
    fn is_sweep_function(name: &str) -> bool {
        let name_lower = name.to_lowercase();

        // Check for "sweep"
        if name_lower.contains("sweep") {
            return true;
        }

        // Check for "recovererc" or "recovertoken"
        if name_lower.contains("recovererc") || name_lower.contains("recovertoken") {
            return true;
        }

        // Check for "rescueerc" or "rescuetoken"
        if name_lower.contains("rescueerc") || name_lower.contains("rescuetoken") {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_sweep_functions() {
        let code = r#"
            contract Test {
                function sweep(address token) external {}
                function sweepTokens(address token) external {}
                function recoverERC20(address token) external {}
                function recoverToken(address token) external {}
                function rescueERC20(address token) external {}
                function rescueTokens(address token) external {}
            }
        "#;
        let detector = Arc::new(SweepTokenAccountingDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 6);
        assert_eq!(locations[0].line, 3, "sweep");
        assert_eq!(locations[1].line, 4, "sweepTokens");
        assert_eq!(locations[2].line, 5, "recoverERC20");
        assert_eq!(locations[3].line, 6, "recoverToken");
        assert_eq!(locations[4].line, 7, "rescueERC20");
        assert_eq!(locations[5].line, 8, "rescueTokens");
    }

    #[test]
    fn test_skips_non_sweep_functions() {
        let code = r#"
            contract Test {
                function transfer(address to, uint256 amount) external {}
                function recover(address account) external {}
                function rescue(address account) external {}
                function withdrawERC20(address token) external {}
            }
        "#;
        let detector = Arc::new(SweepTokenAccountingDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
