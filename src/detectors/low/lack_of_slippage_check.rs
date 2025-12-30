use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct LackOfSlippageCheckDetector;

impl Detector for LackOfSlippageCheckDetector {
    fn id(&self) -> &'static str {
        "lack-of-slippage-check"
    }

    fn name(&self) -> &str {
        "Lack of Slippage check"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Setting `amountOutMin` to 0 in swap operations removes slippage protection, allowing \
         the transaction to complete with any output amount. This can lead to significant loss \
         of funds through front-running or sandwich attacks. Always set a reasonable minimum \
         output amount based on acceptable slippage tolerance (e.g., 1-5%)."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no slippage protection (accepts any output amount)
router.swapExactTokensForTokens({
    amountIn: 100,
    amountOutMin: 0,  // Vulnerable to MEV attacks
    path: path,
    to: recipient,
    deadline: block.timestamp
});

// Good - with slippage protection
router.swapExactTokensForTokens({
    amountIn: 100,
    amountOutMin: amountIn * 95 / 100,  // 5% max slippage
    path: path,
    to: recipient,
    deadline: block.timestamp
});
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::NamedFunctionCall(_, _func, args) = expr {
                for arg in args {
                    if arg.name.name.to_lowercase() == "amountoutmin"
                        && matches!(&arg.expr, Expression::NumberLiteral(_, val, _, _) if val == "0")
                    {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(&arg.loc, file),
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
    fn test_detects_zero_slippage() {
        let code = r#"
            contract Test {
                function swap() public {
                    router.swapExactTokensForTokens({
                        amountIn: 100,
                        amountOutMin: 0,
                        path: path,
                        to: msg.sender
                    });
                }
            }
        "#;
        let detector = Arc::new(LackOfSlippageCheckDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 6, "amountOutMin: 0");
    }

    #[test]
    fn test_skips_nonzero_slippage() {
        let code = r#"
            contract Test {
                function swap() public {
                    router.swapExactTokensForTokens({
                        amountIn: 100,
                        amountOutMin: 95,
                        path: path,
                        to: msg.sender
                    });

                    router.swap({
                        amountOutMin: minAmount,
                        amountIn: 100
                    });
                }
            }
        "#;
        let detector = Arc::new(LackOfSlippageCheckDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
