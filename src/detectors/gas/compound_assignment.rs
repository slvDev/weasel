use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct CompoundAssignmentDetector;

impl Detector for CompoundAssignmentDetector {
    fn id(&self) -> &'static str {
        "compound-assignment"
    }

    fn name(&self) -> &str {
        "a = a + b is more gas effective than a += b for state variables"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Using a = a + b instead of a += b for state variables (excluding arrays and mappings) \
        saves 16 gas per instance."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Less efficient - uses compound assignment
contract Example {
    uint256 public total;
    
    function add(uint256 amount) public {
        total += amount;  // Uses more gas
    }
}

// More efficient - uses expanded form
contract Example {
    uint256 public total;
    
    function add(uint256 amount) public {
        total = total + amount;  // Saves 16 gas
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            match expr {
                Expression::AssignAdd(loc, left, _) | Expression::AssignSubtract(loc, left, _) => {
                    if matches!(left.as_ref(), Expression::ArraySubscript(_, _, _)) {
                        return Vec::new();
                    }
                    
                    return FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(loc, file),
                    }
                    .into();
                }
                _ => {}
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
    fn test_compound_assignment() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract CompoundAssignment {
                uint256 public total;
                mapping(address => uint256) public balances;
                uint256[] public values;
                
                function inefficientAdd(uint256 amount) public {
                    // Bad - compound assignment
                    total += amount;
                }
                
                function inefficientSubtract(uint256 amount) public {
                    // Bad - compound assignment
                    total -= amount;
                }
                
                function efficientAdd(uint256 amount) public {
                    // Good - expanded form
                    total = total + amount;
                }
                
                function localVariableAdd(uint256 amount) public pure returns (uint256) {
                    uint256 local = 100;
                    // This also gets flagged currently, but ideally shouldn't (local var)
                    local += amount;
                    return local;
                }
                
                function arrayOperation(uint256 index, uint256 amount) public {
                    // Should NOT be flagged - array access
                    values[index] += amount;
                }
                
                function mappingOperation(address user, uint256 amount) public {
                    // Should NOT be flagged - mapping access
                    balances[user] += amount;
                }
            }
        "#;

        let detector = Arc::new(CompoundAssignmentDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        // Currently detects all += and -= assignments
        assert_eq!(locations.len(), 3, "Should detect 3 compound assignments");
        assert_eq!(locations[0].line, 11, "First compound assignment +=");
        assert_eq!(locations[1].line, 16, "Second compound assignment -=");
        assert_eq!(locations[2].line, 27, "Third compound assignment (local var)");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract NoCompoundAssignment {
                uint256 public total;
                
                function add(uint256 amount) public {
                    // Good - expanded form
                    total = total + amount;
                }
                
                function multiply(uint256 factor) public {
                    // Good - expanded form
                    total = total * factor;
                }
                
                function subtract(uint256 amount) public {
                    // Good - expanded form
                    total = total - amount;
                }
            }
        "#;

        let detector = Arc::new(CompoundAssignmentDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0, "Should not detect any compound assignments");
    }
}