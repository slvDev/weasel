use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct BlockTimestampDeadlineDetector;

impl Detector for BlockTimestampDeadlineDetector {
    fn id(&self) -> &'static str {
        "block-timestamp-deadline"
    }

    fn name(&self) -> &str {
        "Signature use at deadlines should be allowed"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "According to EIP-2612, signatures used on exactly the deadline timestamp are supposed to be allowed. \
         While the signature may or may not be used for the exact EIP-2612 use case (transfer approvals), \
         for consistency's sake, all deadlines should follow this semantic. If the timestamp is an expiration \
         rather than a deadline, consider whether it makes more sense to include the expiration timestamp as \
         a valid timestamp, as is done for deadlines."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - excludes exact deadline timestamp (violates EIP-2612)
function permit(address owner, address spender, uint256 value, uint256 deadline) external {
    require(deadline > block.timestamp, "Expired");  // Should use >=
    // ...
}

// Good - allows exact deadline timestamp (follows EIP-2612)
function permit(address owner, address spender, uint256 value, uint256 deadline) external {
    require(deadline >= block.timestamp, "Expired");
    // ...
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            match expr {
                Expression::Less(loc, left, right) | Expression::More(loc, left, right) => {
                    if Self::is_block_timestamp(left) || Self::is_block_timestamp(right) {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(loc, file),
                        }
                        .into();
                    }
                }
                _ => {}
            }
            Vec::new()
        });
    }
}

impl BlockTimestampDeadlineDetector {
    fn is_block_timestamp(expr: &Expression) -> bool {
        if let Expression::MemberAccess(_, obj, member) = expr {
            if let Expression::Variable(id) = obj.as_ref() {
                return id.name == "block" && member.name == "timestamp";
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_strict_inequality_with_timestamp() {
        let code = r#"
            contract Test {
                function check(uint256 deadline, uint256 unlockTime) public view {
                    require(deadline > block.timestamp, "Expired");
                    require(block.timestamp < unlockTime, "Too early");
                }
            }
        "#;
        let detector = Arc::new(BlockTimestampDeadlineDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 4, "deadline > block.timestamp (should use >=)");
        assert_eq!(locations[1].line, 5, "block.timestamp < unlockTime (should use <=)");
    }

    #[test]
    fn test_skips_correct_operators() {
        let code = r#"
            contract Test {
                function permit(uint256 deadline) public view {
                    require(deadline >= block.timestamp, "Expired");
                    require(block.timestamp <= deadline, "Expired");
                }

                function compare(uint256 a, uint256 b) public pure {
                    require(a > b);
                }
            }
        "#;
        let detector = Arc::new(BlockTimestampDeadlineDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
