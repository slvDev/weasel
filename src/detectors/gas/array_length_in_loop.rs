use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_expression;
use crate::core::visitor::ASTVisitor;
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ArrayLengthInLoopDetector;

impl Detector for ArrayLengthInLoopDetector {
    fn id(&self) -> &'static str {
        "array-length-in-loop"
    }

    fn name(&self) -> &str {
        "Array Length Lookup in Loop Condition"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Looking up the length of a memory array in every iteration of a for-loop is inefficient. \
        Cache the array length outside the loop to save gas."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"
```solidity
// Inefficient:
for (uint i = 0; i < array.length; i++) {
    // ...
}

// More efficient:
uint length = array.length;
for (uint i = 0; i < length; i++) {
    // ...
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file| {
            if let Statement::For(_, _, condition_opt, _, _) = stmt {
                if let Some(condition) = condition_opt {
                    return find_in_expression(condition, file, self.id(), |expr| {
                        matches!(expr, Expression::MemberAccess(_, _, identifier) if identifier.name == "length")
                    });
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
    use std::sync::Arc;

    #[test]
    fn test_array_length_in_loop_detection() {
        let code = r#"
            pragma solidity ^0.8.0;
            contract Test {
                uint[] array;
                uint[][] matrix;
                
                function inefficientLoop1() public {
                    for (uint i = 0; i < array.length; i++) {  // Should detect
                        array[i] = i;
                    }
                }
                
                function inefficientLoop2() public {
                    for (uint i = 0; i < matrix[0].length; i++) {  // Should detect
                        matrix[0][i] = i;
                    }
                }
                
                function efficientLoop() public {
                    uint length = array.length;
                    for (uint i = 0; i < length; i++) {  // Should NOT detect
                        array[i] = i;
                    }
                }
                
                function complexCondition() public {
                    for (uint i = 0; i < array.length - 1; i++) {  // Should detect
                        array[i] = i;
                    }
                }
            }
        "#;

        let detector = Arc::new(ArrayLengthInLoopDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            3,
            "Should detect 3 array.length accesses in loops"
        );

        // Check specific line numbers for array.length accesses
        assert_eq!(locations[0].line, 8, "First detection should be on line 8");
        assert_eq!(
            locations[1].line, 14,
            "Second detection should be on line 14"
        );
        assert_eq!(
            locations[2].line, 27,
            "Third detection should be on line 27"
        );
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            contract Test {
                uint[] array;
                uint length;
                
                function efficientLoop1() public {
                    uint len = array.length;
                    for (uint i = 0; i < len; i++) {  // Should NOT detect
                        array[i] = i;
                    }
                }
                
                function efficientLoop2() public {
                    for (uint i = 0; i < length; i++) {  // Should NOT detect
                        array[i] = i;
                    }
                }
            }
        "#;

        let detector = Arc::new(ArrayLengthInLoopDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            0,
            "Should not detect any issues in efficient code"
        );
    }
}
