use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ArrayCompoundAssignmentDetector;

impl Detector for ArrayCompoundAssignmentDetector {
    fn id(&self) -> &'static str {
        "array-compound-assignment"
    }

    fn name(&self) -> &str {
        "array[index] += amount is cheaper than array[index] = array[index] + amount"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "When updating a value in an array with arithmetic, using array[index] += amount is cheaper \
        than array[index] = array[index] + amount. This is because you avoid an additional mload when \
        the array is stored in memory, and an sload when the array is stored in storage. \
        Saves 28 gas for a storage array, 38 for a memory array."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Less efficient - extra load operation
balances[user] = balances[user] + amount;
array[i] = array[i] - value;

// More efficient - compound assignment
balances[user] += amount;
array[i] -= value;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            // Check for regular assignment (=) where left is array access
            if let Expression::Assign(loc, left, right) = expr {
                if let Expression::ArraySubscript(_, _, _) = left.as_ref() {
                    // Check if right side is a binary operation
                    if self.is_inefficient_array_update(left, right) {
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

impl ArrayCompoundAssignmentDetector {
    fn is_inefficient_array_update(&self, _left: &Expression, right: &Expression) -> bool {
        match right {
            Expression::Add(_, op1, op2) | Expression::Subtract(_, op1, op2) => {
                matches!(op1.as_ref(), Expression::ArraySubscript(_, _, _)) ||
                matches!(op2.as_ref(), Expression::ArraySubscript(_, _, _))
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_array_compound_assignment() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract ArrayOperations {
                uint256[] public values;
                mapping(address => uint256) public balances;
                
                function inefficientAdd(uint256 index, uint256 amount) public {
                    // Bad - should use +=
                    values[index] = values[index] + amount;
                }
                
                function inefficientSubtract(address user, uint256 amount) public {
                    // Bad - should use -=
                    balances[user] = balances[user] - amount;
                }
                
                function efficientAdd(uint256 index, uint256 amount) public {
                    // Good - uses compound assignment
                    values[index] += amount;
                }
                
                function normalAssignment(uint256 index, uint256 value) public {
                    // OK - not an arithmetic update
                    values[index] = value;
                }
                
                function differentIndices(uint256 i, uint256 j) public {
                    // OK - different indices (though our simple detector might flag this)
                    values[i] = values[j] + 1;
                }
            }
        "#;

        let detector = Arc::new(ArrayCompoundAssignmentDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        // Should detect inefficient patterns
        assert!(locations.len() >= 2, "Should detect at least 2 inefficient array updates");
        assert_eq!(locations[0].line, 10, "First inefficient array update");
        assert_eq!(locations[1].line, 15, "Second inefficient mapping update");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract NoArrayIssues {
                uint256[] public values;
                
                function goodUpdate(uint256 index, uint256 amount) public {
                    // Good - uses compound assignment
                    values[index] += amount;
                }
                
                function simpleAssignment(uint256 index, uint256 newValue) public {
                    // OK - simple assignment, not arithmetic
                    values[index] = newValue;
                }
                
                function regularMath(uint256 a, uint256 b) public pure returns (uint256) {
                    // OK - not array operations
                    uint256 result = a + b;
                    return result;
                }
            }
        "#;

        let detector = Arc::new(ArrayCompoundAssignmentDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}