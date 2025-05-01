use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Type};
use std::sync::{Arc, Mutex};

/// Detector to flag implicit `int` and `uint` types, suggesting explicit `int256`/`uint256`.
#[derive(Debug, Default)]
pub struct ExplicitNumTypesDetector {
    locations: Arc<Mutex<Vec<Location>>>,
}

impl Detector for ExplicitNumTypesDetector {
    fn id(&self) -> &str {
        "explicit-num-types"
    }

    fn name(&self) -> &str {
        "Use Explicit int256/uint256 Types"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Implicitly sized types `int` and `uint` are aliases for `int256` and `uint256`, respectively. Using the explicit `int256` and `uint256` types enhances code clarity and consistency."
    }

    fn gas_savings(&self) -> Option<usize> {
        None
    }

    fn example(&self) -> Option<String> {
        None
    }

    fn get_locations_arc(&self) -> &Arc<Mutex<Vec<Location>>> {
        &self.locations
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_arc = self.clone();

        visitor.on_expression(move |expr, file| {
            if let Expression::Type(loc, ty) = expr {
                let type_len = loc.end() - loc.start();
                match ty {
                    Type::Int(_) => {
                        if type_len == 3 {
                            detector_arc.add_location(loc_to_location(loc, file));
                        }
                    }
                    Type::Uint(_) => {
                        if type_len == 4 {
                            detector_arc.add_location(loc_to_location(loc, file));
                        }
                    }
                    _ => {}
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;
    use std::sync::Arc;

    #[test]
    fn test_explicit_int_types_detector() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract TestExplicitTypes {
                int public stateInt; // Positive
                uint public stateUint; // Positive
                int256 internal stateInt256; // Ignore
                uint8 public stateUint8; // Negative

                struct MyStruct {
                    int structInt; // Positive
                    uint structUint; // Positive
                    uint256 structUint256; // Negative
                }

                MyStruct myStruct;

                function checkTypes(
                    int paramInt, // Positive
                    uint paramUint, // Positive
                    int128 paramInt128 // Ignore
                ) public pure returns (int, uint, uint256) { // Positive (x2)
                    int localInt = -10; // Positive
                    uint localUint = 5; // Positive
                    uint256 localUint256 = 100; // Negative

                    // Check usage in type conversion (should not detect variable name)
                    uint256 converted = uint(localUint256); // Positive

                    int intermediate = 1; // Positive

                    return (localInt, localUint, localUint256);
                }

                // Ensure variable names aren't detected
                 function namingTest() public pure {
                     uint256 intermediate = 0;
                     int256 interval = 0;
                 }
            }
        "#;

        let detector = Arc::new(ExplicitNumTypesDetector::default());
        let locations = run_detector_on_code(detector, code, "explicit_types.sol");

        assert_eq!(locations.len(), 12, "Incorrect number of detections");

        assert!(
            locations[0].snippet.as_deref().unwrap_or("").eq("int"),
            "Snippet for first assert is incorrect"
        );
    }
}
