use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Loc};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DeprecatedChainlinkFunctionDetector;

impl Detector for DeprecatedChainlinkFunctionDetector {
    fn id(&self) -> &'static str {
        "deprecated-chainlink-function"
    }

    fn name(&self) -> &str {
        "Use of deprecated Chainlink function: latestAnswer()"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "According to Chainlink's documentation, the latestAnswer() function is deprecated. \
        This function does not throw an error if no answer has been reached, but instead returns 0, \
        possibly causing an incorrect price to be fed to different price feeds or even a Denial of Service. \
        Use latestRoundData() instead which includes additional validation checks."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Deprecated - returns 0 on error:
int256 price = priceFeed.latestAnswer();

// Recommended - use latestRoundData with validation:
(
    uint80 roundID,
    int256 price,
    uint256 startedAt,
    uint256 timeStamp,
    uint80 answeredInRound
) = priceFeed.latestRoundData();
require(timeStamp > 0, "Round not complete");
require(price > 0, "Invalid price");
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func_expr, args) = expr {
                if !args.is_empty() {
                    return Vec::new();
                }
                
                if let Expression::MemberAccess(_, _, member) = func_expr.as_ref() {
                    if member.name == "latestAnswer" {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(&loc, file),
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
    fn test_deprecated_chainlink_function() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            interface AggregatorV3Interface {
                function latestAnswer() external view returns (int256);
                function latestRoundData() external view returns (
                    uint80 roundId,
                    int256 answer,
                    uint256 startedAt,
                    uint256 updatedAt,
                    uint80 answeredInRound
                );
            }
            
            contract PriceConsumer {
                AggregatorV3Interface internal priceFeed;
                
                function getBadPrice() public view returns (int256) {
                    // Should detect - deprecated function
                    return priceFeed.latestAnswer();
                }
                
                function getAnotherBadPrice() external view returns (int256) {
                    int256 price = priceFeed.latestAnswer();  // Should detect
                    return price;
                }
                
                function getGoodPrice() public view returns (int256) {
                    // Should NOT detect - using recommended function
                    (
                        ,
                        int256 price,
                        ,
                        uint256 timeStamp,
                        
                    ) = priceFeed.latestRoundData();
                    require(timeStamp > 0, "Round not complete");
                    return price;
                }
                
                function notChainlinkCall() public pure returns (int256) {
                    // Should NOT detect - different function name
                    return someOtherFunction();
                }
            }
        "#;

        let detector = Arc::new(DeprecatedChainlinkFunctionDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 uses of latestAnswer()");
        
        // Verify detection at correct lines
        assert_eq!(locations[0].line, 20, "First detection in getBadPrice()");
        assert_eq!(locations[1].line, 24, "Second detection in getAnotherBadPrice()");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract Test {
                function latestAnswer() public pure returns (int256) {
                    // Function definition, not a call - should NOT detect
                    return 100;
                }
                
                function test() public view {
                    // Should NOT detect - latestAnswer with arguments
                    something.latestAnswer(123);
                    
                    // Should NOT detect - different function names
                    oracle.latestRoundData();
                    oracle.getLatestAnswer();
                    oracle.latest();
                    oracle.answer();
                }
            }
        "#;

        let detector = Arc::new(DeprecatedChainlinkFunctionDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            0,
            "Should not detect any false positives"
        );
    }
}