use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct CurveSpotPriceOracleDetector;

impl Detector for CurveSpotPriceOracleDetector {
    fn id(&self) -> &'static str {
        "curve-spot-price-oracle"
    }

    fn name(&self) -> &str {
        "Unsafe Curve Pool Price Oracle (`get_dy_underlying`)"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &str {
        "Using `get_dy_underlying` from Curve pools as a price oracle is vulnerable to flash loan manipulation. \
        Attackers can skew pool reserves within a single transaction to get a manipulated price, leading to potential loss of funds. \
        Use Chainlink Price Feeds or TWAP oracles instead for critical price data."
    }


    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
contract MyProtocol {
    ICurvePool curvePool = ICurvePool(0x...);

    function checkPriceAndAct(uint amountIn) external {
        // Unsafe: Price derived from get_dy_underlying can be manipulated
        uint amountOut = curvePool.get_dy_underlying(0, 1, amountIn);
        require(amountOut > minExpected, "Price too low"); // Decision based on manipulated price
        // ... perform action based on amountOut ...
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file| {
            if let Expression::FunctionCall(loc, func_expr, _) = expr {
                if let Expression::MemberAccess(_, _, member_ident) = func_expr.as_ref() {
                    if member_ident.name == "get_dy_underlying" {
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
    fn test_curve_spot_price_oracle_detector() {
        let code = r#"
            pragma solidity ^0.8.0;

            interface ICurvePool {
                function get_dy(int128 i, int128 j, uint256 dx) external view returns (uint256);
                function get_dy_underlying(int128 i, int128 j, uint256 dx) external view returns (uint256);
            }

            contract TestCurveOracle {
                ICurvePool pool = ICurvePool(address(0x1));
                address otherContract;

                function unsafeAction(uint amount) external {
                    uint price = pool.get_dy_underlying(0, 1, amount); // Positive
                    // ... use price ...
                }

                function safeAction(uint amount) external {
                     uint price = pool.get_dy(0, 1, amount); // Negative (different function)
                     // ... use price ...
                }
                
                function otherCall() external {
                     otherContract.call(abi.encodeWithSignature("get_dy_underlying()")); // Negative (not direct call)
                }
                
                function variableCall() external {
                    bytes4 selector = ICurvePool.get_dy_underlying.selector; // Negative (selector usage)
                    (bool s, bytes memory r) = address(pool).staticcall(abi.encodeWithSelector(selector, 0, 1, 100)); // Negative
                }

                function unrelatedCall() external {
                    uint x = get_dy_underlying(); // Negative (not member access)
                }
                function get_dy_underlying() internal pure returns (uint) { return 1; } // Negative (local func)
            }
        "#;

        let detector = Arc::new(CurveSpotPriceOracleDetector::default());
        let locations = run_detector_on_code(detector.clone(), code, "curve_oracle.sol");

        assert_eq!(locations.len(), 1, "Should detect 1 issue");

        assert_eq!(locations[0].line, 14, "Incorrect line number found");
        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("pool.get_dy_underlying(0, 1, amount)"),
            "Incorrect snippet found"
        );
    }
}
