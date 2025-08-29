use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ChainlinkStalePriceDetector;

impl Detector for ChainlinkStalePriceDetector {
    fn id(&self) -> &'static str {
        "chainlink-stale-price"
    }

    fn name(&self) -> &str {
        "Chainlink's latestRoundData might return stale or incorrect results"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "latestRoundData() is used to fetch the asset price from a Chainlink aggregator, but it's missing additional validations \
        to ensure that the round is complete. If there is a problem with Chainlink starting a new round and finding consensus on \
        the new value for the oracle (e.g. Chainlink nodes abandon the oracle, chain congestion, vulnerability/attacks on the \
        Chainlink system) consumers of this contract may continue using outdated stale data / stale prices. \
        The function returns 5 values, but if some are ignored, critical validation data is lost."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - ignoring return values that could indicate stale data
(, int256 price, , , ) = priceFeed.latestRoundData();

// Good - capture all return values and validate
(
    uint80 roundId,
    int256 price,
    uint256 startedAt,
    uint256 updatedAt,
    uint80 answeredInRound
) = priceFeed.latestRoundData();

require(updatedAt > 0, "Round not complete");
require(price > 0, "Invalid price");
require(answeredInRound >= roundId, "Stale price");
require(block.timestamp - updatedAt < 3600, "Price too old");
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file, _context| {
            // Check for expression statements with tuple destructuring
            if let Statement::Expression(loc, expr) = stmt {
                // Check for tuple destructuring assignment: (a, b, c, d, e) = latestRoundData()
                if let Expression::Assign(_, left, right) = expr {
                    if self.is_latest_round_data_call(right) {
                        if self.has_missing_validation_values(left) {
                            return FindingData {
                                detector_id: self.id(),
                                location: loc_to_location(loc, file),
                            }
                            .into();
                        }
                    }
                }
            }
            
            Vec::new()
        });
    }
}

impl ChainlinkStalePriceDetector {
    fn is_latest_round_data_call(&self, expr: &Expression) -> bool {
        match expr {
            Expression::FunctionCall(_, func, _) => {
                if let Expression::MemberAccess(_, _, member) = func.as_ref() {
                    return member.name == "latestRoundData";
                }
            }
            _ => {}
        }
        false
    }
    
    fn has_missing_validation_values(&self, expr: &Expression) -> bool {
        // Check for tuple expressions and verify critical positions are captured
        if let Expression::List(_, params) = expr {
            // latestRoundData returns 5 values:
            // 0: roundId (needed)
            // 1: price (obviously needed)
            // 2: startedAt (not critical)
            // 3: updatedAt (needed)
            // 4: answeredInRound (needed)
            
            if params.len() != 5 {
                return true; // Wrong number of values
            }
            
            // Check if critical positions are ignored (None)
            // Position 0 (roundId) - needed for answeredInRound >= roundId check
            if let Some((_, param)) = params.get(0) {
                if param.is_none() {
                    return true;
                }
            }
            
            // Position 3 (updatedAt) - needed for updatedAt > 0 check
            if let Some((_, param)) = params.get(3) {
                if param.is_none() {
                    return true;
                }
            }
            
            // Position 4 (answeredInRound) - needed for stale price check
            if let Some((_, param)) = params.get(4) {
                if param.is_none() {
                    return true;
                }
            }
            
            false
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_chainlink_stale_price() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            interface AggregatorV3Interface {
                function latestRoundData() external view returns (
                    uint80 roundId,
                    int256 answer,
                    uint256 startedAt,
                    uint256 updatedAt,
                    uint80 answeredInRound
                );
            }
            
            contract PriceConsumer {
                AggregatorV3Interface public priceFeed;
                
                function getBadPrice1() public view returns (int256) {
                    // Bad - ignoring roundId (position 0)
                    (, int256 price, , uint256 updatedAt, uint80 answeredInRound) = priceFeed.latestRoundData();
                    return price;
                }
                
                function getBadPrice2() public view returns (int256) {
                    // Bad - ignoring updatedAt (position 3)
                    (uint80 roundId, int256 price, , , uint80 answeredInRound) = priceFeed.latestRoundData();
                    return price;
                }
                
                function getBadPrice3() public view returns (int256) {
                    // Bad - ignoring answeredInRound (position 4)
                    (uint80 roundId, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
                    return price;
                }
                
                function getBadPrice4() public view returns (int256) {
                    // Bad - ignoring all validation values
                    (, int256 price, , , ) = priceFeed.latestRoundData();
                    return price;
                }
                
                function getGoodPrice() public view returns (int256) {
                    // Good - using all values for validation
                    (
                        uint80 roundId,
                        int256 price,
                        uint256 startedAt,
                        uint256 updatedAt,
                        uint80 answeredInRound
                    ) = priceFeed.latestRoundData();
                    
                    require(updatedAt > 0, "Round not complete");
                    require(answeredInRound >= roundId, "Stale price");
                    
                    return price;
                }
            }
        "#;

        let detector = Arc::new(ChainlinkStalePriceDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4, "Should detect 4 bad latestRoundData calls");
        assert_eq!(locations[0].line, 19, "Bad call 1 - missing roundId");
        assert_eq!(locations[1].line, 25, "Bad call 2 - missing updatedAt");
        assert_eq!(locations[2].line, 31, "Bad call 3 - missing answeredInRound");
        assert_eq!(locations[3].line, 37, "Bad call 4 - missing all validation");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract NoChainlink {
                function someFunction() public pure returns (uint256) {
                    // Not a Chainlink call
                    uint256 value = 100;
                    return value;
                }
                
                function callOtherFunction() public pure returns (uint256, uint256) {
                    // Some other function that returns tuple
                    (uint256 a, uint256 b) = getTwoValues();
                    return (a, b);
                }
                
                function getTwoValues() private pure returns (uint256, uint256) {
                    return (1, 2);
                }
            }
        "#;

        let detector = Arc::new(ChainlinkStalePriceDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}