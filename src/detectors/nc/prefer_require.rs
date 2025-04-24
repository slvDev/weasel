use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Loc};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct PreferRequireDetector {
    locations: Arc<Mutex<Vec<Location>>>,
}

impl Detector for PreferRequireDetector {
    fn id(&self) -> &str {
        "prefer-require"
    }

    fn name(&self) -> &str {
        "Prefer `require` over `assert`"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Prior to Solidity v0.8.0, `assert()` consumes the remainder of the transaction's available gas, \
        unlike `require()`/`revert()`. Even in v0.8.0+, `assert()` should usually be avoided. \
        As per the [Solidity documentation](https://docs.soliditylang.org/en/v0.8.14/control-structures.html#panic-via-assert-and-error-via-require), \
        `assert` creates a `Panic(uint256)` error and is intended for checking internal invariants. \
        Properly functioning code should never cause a Panic. For validating external inputs, return values \
        from external calls, or ensuring state conditions, `require` (which creates an `Error(string)`) \
        or custom errors are more appropriate and informative."
    }

    fn gas_savings(&self) -> Option<usize> {
        None // Gas difference is pre-0.8.0 behavior, not direct savings from replacement
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Instead of asserting internal invariants or conditions:
// assert(x > 5);

// Consider using require for input/state validation:
require(input > 0, "Input must be positive");
require(balance >= amount, "Insufficient balance");

// If asserting an invariant that should never fail (indicating a bug):
// assert(array.length < MAX_SIZE); // This might still be okay, but understand the implications
```"#
                .to_string(),
        )
    }

    fn get_locations_arc(&self) -> &Arc<Mutex<Vec<Location>>> {
        &self.locations
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_arc = self.clone();

        visitor.on_expression(move |expr, file| {
            if let Expression::FunctionCall(loc, func_expr, _args) = expr {
                // Check if the function expression is the identifier 'assert'
                if let Expression::Variable(ident) = func_expr.as_ref() {
                    if ident.name == "assert" {
                        // Found a call to assert()
                        detector_arc.add_location(loc_to_location(loc, file));
                    }
                }
            }
        });
    }
}

// --- Unit Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;
    use std::sync::Arc;

    #[test]
    fn test_prefer_require_detector() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint public value = 10;

                function checkValue(uint _input) public view {
                    require(_input > 0, "Input must be positive"); // Negative case
                    assert(value > 5);                             // Positive case
                    if (_input == 1) {
                        assert(true);                              // Positive case
                    }
                    externalContract.assert(_input);               // Negative case
                }

                 function checkWithCustomError(uint _input) public view {
                    if (_input == 0) revert("Input cannot be zero"); // Negative case
                 }
            }
        "#;

        let detector = Arc::new(PreferRequireDetector::default());
        let locations = run_detector_on_code(detector, code, "prefer_require_test.sol");

        assert_eq!(
            locations.len(),
            2,
            "Should detect exactly two assert() calls"
        );

        assert_eq!(
            locations[0].line, 9,
            "Line number for first assert should be 9"
        );
        assert_eq!(
            locations[1].line, 11,
            "Line number for second assert should be 11"
        );

        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .contains("assert(value > 5)"),
            "Snippet for first assert is incorrect"
        );
        assert!(
            locations[1]
                .snippet
                .as_deref()
                .unwrap_or("")
                .contains("assert(true)"),
            "Snippet for second assert is incorrect"
        );
    }
}
