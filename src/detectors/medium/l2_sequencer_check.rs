use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct L2SequencerCheckDetector;

impl Detector for L2SequencerCheckDetector {
    fn id(&self) -> &'static str {
        "l2-sequencer-check"
    }

    fn name(&self) -> &str {
        "Missing checks for whether the L2 Sequencer is active"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "Chainlink recommends that users using price oracles, check whether the Arbitrum/L2 Sequencer is active. \
        If the sequencer goes down, the Chainlink oracles will have stale prices from before the downtime, \
        until a new L2 OCR transaction goes through. Users who submit their transactions via the L1 Delayed Inbox \
        will be able to take advantage of these stale prices. Use a Chainlink oracle to determine whether the \
        sequencer is offline or not, and don't allow operations to take place while the sequencer is offline."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no sequencer check on L2
function getPrice() public view returns (int256) {
    (, int256 price, , , ) = priceFeed.latestRoundData();
    return price;
}

// Good - check sequencer status first
function getPrice() public view returns (int256) {
    // Check sequencer status
    (, int256 answer, uint256 startedAt, , ) = sequencerUptimeFeed.latestRoundData();
    
    // Answer == 0: Sequencer is up
    // Answer == 1: Sequencer is down
    bool isSequencerUp = answer == 0;
    
    if (!isSequencerUp) {
        revert SequencerDown();
    }
    
    // Check the sequencer grace period has passed
    uint256 timeSinceUp = block.timestamp - startedAt;
    if (timeSinceUp <= GRACE_PERIOD_TIME) {
        revert GracePeriodNotOver();
    }
    
    // Get price
    (, int256 price, , , ) = priceFeed.latestRoundData();
    return price;
}
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
                    if self.is_latest_round_data_call(right) && self.is_missing_answer_check(left) {
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

impl L2SequencerCheckDetector {
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
    
    fn is_missing_answer_check(&self, left: &Expression) -> bool {
        // Check if this is a tuple destructuring that ignores the answer field
        if let Expression::List(_, params) = left {
            // latestRoundData returns 5 values, answer is at position 1
            if params.len() == 5 {
                // Check if position 1 (answer) is ignored
                if let Some((_, param)) = params.get(1) {
                    return param.is_none();
                }
            }
        }
        true // Not a proper tuple destructuring
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_l2_sequencer_check() {
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
            
            contract L2PriceConsumer {
                AggregatorV3Interface public priceFeed;
                AggregatorV3Interface public sequencerFeed;
                
                function getBadPrice() public view returns (int256) {
                    // Bad - ignoring answer field (position 1) which could be sequencer status
                    (uint80 roundId, , , uint256 updatedAt, ) = priceFeed.latestRoundData();
                    return 0;
                }
                
                function getGoodPrice() public view returns (int256) {
                    // Good - capturing answer, likely for sequencer check
                    (uint80 roundId, int256 answer, , uint256 updatedAt, ) = sequencerFeed.latestRoundData();
                    require(answer == 0, "Sequencer is down");
                }
            }
        "#;

        let detector = Arc::new(L2SequencerCheckDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 1, "Should detect 1 bad latestRoundData call");
        assert_eq!(locations[0].line, 20, "Bad call - no answer captured");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract NoOracleContract {
                function someFunction() public pure returns (uint256) {
                    // No oracle calls
                    uint256 value = 100;
                    return value;
                }
                
                function otherFunction() public pure returns (uint256, uint256) {
                    // Some other function that returns tuple
                    (uint256 a, uint256 b) = getTwoValues();
                    return (a, b);
                }
                
                function getTwoValues() private pure returns (uint256, uint256) {
                    return (1, 2);
                }
            }
        "#;

        let detector = Arc::new(L2SequencerCheckDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}