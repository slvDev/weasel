use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct BlockNumberL2Detector;

impl Detector for BlockNumberL2Detector {
    fn id(&self) -> &'static str {
        "block-number-l2"
    }

    fn name(&self) -> &str {
        "`block.number` means different things on different L2s"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "Using `block.number` for timing or logic can cause inconsistencies across L2 chains. \
        On Optimism it returns the L2 block number, but on Arbitrum it returns the L1 block number. \
        L2 blocks may occur per-transaction, making timing unreliable. Consider using block.timestamp \
        or implement a clock mechanism (EIP-6372) for cross-chain compatibility."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - inconsistent across L2s
if (block.number > deadline) { 
    revert("Too late");
}

// Better - use timestamp
if (block.timestamp > deadline) {
    revert("Too late");
}

// For Arbitrum specifically
uint256 l2BlockNumber = ArbSys(address(100)).arbBlockNumber();
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::MemberAccess(loc, base_expr, member) = expr {
                if let Expression::Variable(var) = base_expr.as_ref() {
                    if var.name == "block" && member.name == "number" {
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
    fn test_block_number_l2_detection() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract TestContract {
                uint256 public lastBlock;
                
                function checkTiming() public {
                    require(block.number > 1000);  // Should detect
                    lastBlock = block.number;  // Should detect
                }
                
                function useInCalculation() public view returns (uint256) {
                    return block.number * 2;  // Should detect
                }
                
                function compareBlocks(uint256 targetBlock) public view {
                    if (block.number >= targetBlock) {  // Should detect
                        // do something
                    }
                }
                
                function goodPractice() public view {
                    uint256 time = block.timestamp;  // Should NOT detect
                    uint256 difficulty = block.difficulty;  // Should NOT detect
                    address coinbase = block.coinbase;  // Should NOT detect
                }
                
                function localVariable() public pure {
                    uint256 number = 42;  // Should NOT detect - local var
                    Block memory block;  // Should NOT detect - local var
                }
                
                struct Block {
                    uint256 number;  // Should NOT detect - struct field
                }
            }
        "#;

        let detector = Arc::new(BlockNumberL2Detector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4, "Should detect 4 uses of block.number");
        
        // Check detection lines
        assert_eq!(locations[0].line, 8, "First block.number in require");
        assert_eq!(locations[1].line, 9, "Second block.number assignment");
        assert_eq!(locations[2].line, 13, "Third block.number in return");
        assert_eq!(locations[3].line, 17, "Fourth block.number in if");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract TestContract {
                // Should not detect these
                uint256 public number;
                mapping(uint256 => uint256) public blockData;
                
                function test() public view {
                    uint256 time = block.timestamp;
                    uint256 gasLimit = block.gaslimit;
                    address coinbase = block.coinbase;
                    uint256 chainId = block.chainid;
                    uint256 baseFee = block.basefee;
                    
                    // Local variables with "number" in name
                    uint256 blockNumber = 123;
                    uint256 myNumber = 456;
                    
                    // Not the global block variable
                    MyBlock memory myBlock;
                    uint256 val = myBlock.number;
                }
                
                struct MyBlock {
                    uint256 number;
                    uint256 timestamp;
                }
                
                function getNumber() public pure returns (uint256) {
                    return 42;  // Not block.number
                }
            }
        "#;

        let detector = Arc::new(BlockNumberL2Detector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            0,
            "Should not detect any false positives"
        );
    }
}