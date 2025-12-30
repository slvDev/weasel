use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct CurveCalcTokenAmountDetector;

impl Detector for CurveCalcTokenAmountDetector {
    fn id(&self) -> &'static str {
        "curve-calc-token-amount-slippage"
    }

    fn name(&self) -> &str {
        "`calc_token_amount()` has slippage added on top of Curve's calculated slippage"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "According to the Curve documentation (https://curve.readthedocs.io/_/downloads/en/latest/pdf/), \
         `StableSwap.calc_token_amount()` already includes slippage but not fees, so adding extra slippage \
         on top of the returned result, as is done by the caller of functions higher up the caller chain, \
         is an incorrect operation."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - adding slippage on top of calc_token_amount result
function addLiquidity(uint256[2] memory amounts) external {
    uint256 expectedLpTokens = curvePool.calc_token_amount(amounts, true);
    uint256 minLpTokens = expectedLpTokens * 95 / 100; // Extra slippage added - INCORRECT
    curvePool.add_liquidity(amounts, minLpTokens);
}

// Good - use calc_token_amount result directly (it already includes slippage)
function addLiquidity(uint256[2] memory amounts) external {
    uint256 minLpTokens = curvePool.calc_token_amount(amounts, true);
    curvePool.add_liquidity(amounts, minLpTokens);
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func_expr, _args) = expr {
                if let Expression::MemberAccess(_, _, member) = func_expr.as_ref() {
                    if member.name == "calc_token_amount" {
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
    fn test_detects_calc_token_amount() {
        let code = r#"
            contract Test {
                ICurvePool public pool;

                function addLiquidity(uint256[2] memory amounts) external {
                    uint256 expectedLp = pool.calc_token_amount(amounts, true);
                    uint256 minLp = expectedLp * 95 / 100;
                }
            }
        "#;
        let detector = Arc::new(CurveCalcTokenAmountDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 6, "calc_token_amount call");
    }

    #[test]
    fn test_skips_other_functions() {
        let code = r#"
            contract Test {
                ICurvePool public pool;

                function addLiquidity(uint256[2] memory amounts) external {
                    // Using other Curve functions that don't include slippage
                    pool.add_liquidity(amounts, 0);
                    uint256 balance = pool.balances(0);
                }
            }
        "#;
        let detector = Arc::new(CurveCalcTokenAmountDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
