use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UncheckedLoopIncrementDetector;

impl Detector for UncheckedLoopIncrementDetector {
    fn id(&self) -> &'static str {
        "unchecked-loop-increment"
    }

    fn name(&self) -> &str {
        "Increments/decrements can be unchecked in for-loops"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "In Solidity 0.8+, there's a default overflow check on unsigned integers. It's possible \
        to uncheck this in for-loops and save some gas at each iteration. The risk of overflow \
        is non-existent for uint256 when bounded by a loop condition. Saves ~25 gas per iteration."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - checked increment (extra gas per iteration)
for (uint256 i = 0; i < length; i++) {
    // ...
}

// Good - unchecked increment
for (uint256 i = 0; i < length; ) {
    // ...
    unchecked { ++i; }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file, _context| {
            if let Statement::For(loc, _, _, update_opt, _) = stmt {
                if let Some(update_expr) = update_opt {
                    if Self::is_increment_or_decrement(update_expr) {
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

impl UncheckedLoopIncrementDetector {
    fn is_increment_or_decrement(expr: &Expression) -> bool {
        match expr {
            // i++, ++i, i--, --i
            Expression::PostIncrement(_, _)
            | Expression::PreIncrement(_, _)
            | Expression::PostDecrement(_, _)
            | Expression::PreDecrement(_, _) => true,
            // i += N, i -= N
            Expression::AssignAdd(_, _, _) | Expression::AssignSubtract(_, _, _) => true,
            // i = i + N, i = i - N
            Expression::Assign(_, _, right) => matches!(
                right.as_ref(),
                Expression::Add(_, _, _) | Expression::Subtract(_, _, _)
            ),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_increments_and_decrements() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function postIncrement(uint256[] memory arr) external pure returns (uint256) {
                    uint256 sum = 0;
                    for (uint256 i = 0; i < arr.length; i++) {
                        sum += arr[i];
                    }
                    return sum;
                }

                function preIncrement(uint256[] memory arr) external pure returns (uint256) {
                    uint256 sum = 0;
                    for (uint256 i = 0; i < arr.length; ++i) {
                        sum += arr[i];
                    }
                    return sum;
                }

                function postDecrement(uint256 n) external pure returns (uint256) {
                    uint256 sum = 0;
                    for (uint256 i = n; i > 0; i--) {
                        sum += i;
                    }
                    return sum;
                }

                function assignAdd(uint256[] memory arr) external pure returns (uint256) {
                    uint256 sum = 0;
                    for (uint256 i = 0; i < arr.length; i += 1) {
                        sum += arr[i];
                    }
                    return sum;
                }

                function assignSubtract(uint256 n) external pure returns (uint256) {
                    uint256 sum = 0;
                    for (uint256 i = n; i > 0; i -= 1) {
                        sum += i;
                    }
                    return sum;
                }
            }
        "#;

        let detector = Arc::new(UncheckedLoopIncrementDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 5);
        assert_eq!(locations[0].line, 7, "i++");
        assert_eq!(locations[1].line, 15, "++i");
        assert_eq!(locations[2].line, 23, "i--");
        assert_eq!(locations[3].line, 31, "i += 1");
        assert_eq!(locations[4].line, 39, "i -= 1");
    }

    #[test]
    fn test_skips_already_optimized() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function whileLoop(uint256 n) external pure returns (uint256) {
                    uint256 i = 0;
                    while (i < n) {
                        i++;
                    }
                    return i;
                }

                function alreadyUnchecked() external pure returns (uint256) {
                    uint256 sum = 0;
                    for (uint256 i = 0; i < 10; ) {
                        sum += i;
                        unchecked { ++i; }
                    }
                    return sum;
                }
            }
        "#;

        let detector = Arc::new(UncheckedLoopIncrementDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
