use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnsafeArrayAccessDetector;

impl Detector for UnsafeArrayAccessDetector {
    fn id(&self) -> &'static str {
        "unsafe-array-access"
    }

    fn name(&self) -> &str {
        "Use unsafe array access to avoid bounds checking"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "When accessing arrays inside loops where the bounds are already verified by the loop condition, \
        you can save gas by using unsafe array access to skip redundant bounds checking. \
        This optimization can save ~2100 gas per array access."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"
```solidity
// Instead of:
for (uint i = 0; i < array.length; i++) {
    array[i] = newValue;  // Costly bounds check (~2100 gas per access)
}

// Consider using:
import "@openzeppelin/contracts/utils/Arrays.sol";
for (uint i = 0; i < array.length; i++) {
    Arrays.unsafeAccess(array, i).value = newValue;  // Skip bounds check
}

// WARNING: Only use if you are certain pos is lower than the array length.
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file, _context| {
            // Detect array access in any for-loop - developer can decide if bounds are safe
            if let Statement::For(_, _, _, _, body_opt) = stmt {
                if let Some(body) = body_opt {
                    return find_in_statement(body, file, self.id(), |expr| {
                        matches!(expr, Expression::ArraySubscript(_, _, _))
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
    fn test_unsafe_array_access_detection() {
        let code = r#"
            pragma solidity ^0.8.0;
            contract Test {
                uint[] public numbers;
                uint[][] public matrix;
                
                function arrayAccessInLoop() public {
                    for (uint i = 0; i < numbers.length; i++) {
                        numbers[i] = i * 2;  // Should detect - can use unsafe access
                    }
                }
                
                function multipleArrayAccess() public {
                    for (uint i = 0; i < numbers.length; i++) {
                        numbers[i] = numbers[i] + 1;  // Should detect both accesses
                    }
                }
                
                function matrixAccess() public {
                    for (uint i = 0; i < matrix.length; i++) {
                        matrix[i][0] = i;  // Should detect
                    }
                }
                
                function genericLoop() public {
                    for (uint i = 0; i < 10; i++) {
                        numbers[i] = i;  // Should detect - any array access in loop
                    }
                }
                
                function noArrayAccess() public {
                    for (uint i = 0; i < numbers.length; i++) {
                        uint temp = i * 2;  // Should NOT detect - no array access
                    }
                }
            }
        "#;

        let detector = Arc::new(UnsafeArrayAccessDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            5,
            "Should detect 5 array access opportunities"
        );

        // Check specific line numbers for array access that could be optimized
        assert_eq!(locations[0].line, 9, "First detection should be on line 9");
        assert_eq!(
            locations[1].line, 15,
            "Second detection should be on line 15"
        );
        assert_eq!(
            locations[2].line, 15,
            "Third detection should be on line 15"
        );
        assert_eq!(
            locations[3].line, 21,
            "Fourth detection should be on line 21"
        );
        assert_eq!(
            locations[4].line, 27,
            "Fifth detection should be on line 27"
        );
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            contract Test {
                uint[] public numbers;
                
                function noArrayAccess() public {
                    for (uint i = 0; i < numbers.length; i++) {
                        // No array access in body
                        uint temp = i * 2;
                    }
                }
                
                function onlyVariables() public {
                    for (uint i = 0; i < 10; i++) {
                        uint temp = i * 2;  // No array/mapping access
                    }
                }
                
                function noLoop() public {
                    numbers[0] = 42;  // Array access but not in a loop
                }
            }
        "#;

        let detector = Arc::new(UnsafeArrayAccessDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            0,
            "Should not detect any issues when no array access in loops"
        );
    }
}
