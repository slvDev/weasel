use crate::{
    core::visitor::ASTVisitor,
    detectors::Detector,
    models::{finding::Location, severity::Severity},
    utils::location::loc_to_location,
};
use solang_parser::pt::Expression;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct WstethStethPerTokenUsageDetector {
    locations: Arc<Mutex<Vec<Location>>>,
}

impl Detector for WstethStethPerTokenUsageDetector {
    fn id(&self) -> &str {
        "wsteth-stethpertoken-usage"
    }

    fn name(&self) -> &str {
        "Potentially Unsafe Use of wstETH.stEthPerToken()"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn description(&self) -> &str {
        "The function `wstETH.stEthPerToken()` returns the amount of `stETH` per `wstETH`, not an ETH-equivalent value or rate. \
        Using this value directly in financial calculations assuming it represents ETH, or combining it incorrectly with ETH/USD price feeds, \
        can lead to significant value calculation errors due to market fluctuations between stETH and ETH. \
        Ensure calculations correctly account for the stETH units returned and use appropriate price feeds (stETH/USD or ETH/USD combined with market stETH/ETH rate)."
    }

    fn gas_savings(&self) -> Option<usize> {
        None
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
contract VulnerableContract {
    function calculateValueInUsd(uint256 _wstethAmount) public view returns (uint256) {
        uint256 stEthRate = wsteth.stEthPerToken(); // This rate is stETH per wstETH (scaled)
        (,int ethPriceUsd,,,) = ethUsdPriceFeed.latestRoundData();
        
        // The calculation needs to convert wstETH to stETH units first, 
        // then use a stETH/USD price feed or ETH/USD + market stETH/ETH rate.
        uint256 value = (_wstethAmount * stEthRate * uint256(ethPriceUsd)) / (1e18 * 1e8); // Incorrect logic

        return value;
    }
    
    function justCallingFunction() public view {
        uint256 rate = wsteth.stEthPerToken(); // Calling the function flags potential issue
        // ... further logic might misuse 'rate' ...
    }
}
```"#
                .to_string(),
        )
    }

    fn get_locations_arc(&self) -> &Arc<Mutex<Vec<Location>>> {
        &self.locations
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_arc = self.clone();
        visitor.on_expression(move |expr, file| {
            if let Expression::FunctionCall(loc, func_expr, _) = expr {
                if let Expression::MemberAccess(_, _, member_ident) = func_expr.as_ref() {
                    if member_ident.name == "stEthPerToken" {
                        detector_arc.add_location(loc_to_location(loc, file));
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_wsteth_stethpertoken_usage_detector() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract TestWstETH {
                function unsafeUsage() public view {
                    uint rate = wsteth.stEthPerToken(); // Positive
                    // ... use rate ...
                }

                function safeUsage() public view {
                     uint amountStETH = wsteth.getStETHByWstETH(1 ether); // Negative (different function)
                }
                
                function otherCall() public view {
                     otherContract.call(abi.encodeWithSignature("stEthPerToken()")); // Negative (not direct call)
                }

                function variableCall() public view {
                    bytes4 selector = IWstETH.stEthPerToken.selector; // Negative (selector usage)
                    (bool s, bytes memory r) = address(wsteth).staticcall(abi.encodeWithSelector(selector)); // Negative
                }

                function unrelatedCall() public view {
                    uint x = stEthPerToken(); // Negative (not member access)
                }
                function stEthPerToken() internal pure returns (uint) { return 1e18; } // Negative (local func)
            }
        "#;

        let detector = Arc::new(WstethStethPerTokenUsageDetector::default());
        let locations = run_detector_on_code(detector.clone(), code, "wsteth_usage.sol");

        assert_eq!(locations.len(), 1, "Should detect 1 issue");

        assert_eq!(locations[0].line, 6, "Incorrect line number found");
        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("wsteth.stEthPerToken()"),
            "Incorrect snippet found"
        );
    }
}
