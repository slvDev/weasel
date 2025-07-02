use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct MagicNumberDetector;

impl Detector for MagicNumberDetector {
    fn id(&self) -> &'static str {
        "magic-numbers"
    }

    fn name(&self) -> &str {
        "`constant`s should be defined rather than using magic numbers"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Numeric literals used directly as arguments in function calls can obscure meaning. Define and use constants instead for clarity and maintainability."
    }


    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Magic numbers used directly in calls
require(userLevel > 5, "Level too low");
someContract.call{value: 1 ether}("");
emit StatusUpdate(0);

// Using named constants
uint constant MIN_USER_LEVEL = 5;
uint constant ONE_ETHER = 1 ether;
uint constant STATUS_SUCCESS = 0;

require(userLevel > MIN_USER_LEVEL, "Level too low");
someContract.call{value: ONE_ETHER}("");
emit StatusUpdate(STATUS_SUCCESS);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file| {
            let mut findings = Vec::new();
            match expr {
                Expression::FunctionCall(loc, _func, args) => {
                    for arg in args {
                        match arg {
                            Expression::NumberLiteral(_, _, _, _) => {
                                findings.push(FindingData {
                                    detector_id: self.id(),
                                    location: loc_to_location(loc, file),
                                });
                            }
                            Expression::HexNumberLiteral(_, _, _) => {
                                findings.push(FindingData {
                                    detector_id: self.id(),
                                    location: loc_to_location(loc, file),
                                });
                            }
                            _ => {}
                        }
                    }
                }
                Expression::NamedFunctionCall(loc, _func, args) => {
                    for arg in args {
                        match &arg.expr {
                            Expression::NumberLiteral(_, _, _, _) => {
                                findings.push(FindingData {
                                    detector_id: self.id(),
                                    location: loc_to_location(loc, file),
                                });
                            }
                            Expression::HexNumberLiteral(_, _, _) => {
                                findings.push(FindingData {
                                    detector_id: self.id(),
                                    location: loc_to_location(loc, file),
                                });
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
            findings
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;
    use std::sync::Arc;

    #[test]
    fn test_magic_number_in_calls_detector() {
        let code = r#"
            pragma solidity ^0.8.0;

            uint constant MY_CONSTANT = 100;
            uint constant TWO = 2;

            contract Test {
                uint stateVar = 5;

                function check(uint input) public pure returns (uint) {
                    require(input > TWO, "Input must be > 2"); // Negative
                    require(input > 2, "Input must be > 2");   // Negative (for now)
                    otherFunc(0x0A, 1);                        // Positive

                    assert(input != 0); // Negative (for now)
                    assert(input != 1); // Negative (for now)

                    uint local = 1000;
                    uint calculation = local * 2; // Negative (for now)

                    emit SomeEvent(42); // Positive
                    return 42; // Negative (for now)
                }

                function otherFunc(uint a, uint b) internal pure {}
                event SomeEvent(uint val);
            }
        "#;

        let detector = Arc::new(MagicNumberDetector::default());
        let locations = run_detector_on_code(detector, code, "magic_numbers.sol");

        assert_eq!(
            locations.len(),
            3,
            "Should detect 3 magic numbers in call arguments"
        );

        assert_eq!(locations[0].line, 13); // otherFunc(0x0A, ...)
        assert_eq!(locations[1].line, 13); // otherFunc(..., 1)
        assert_eq!(locations[2].line, 21); // emit SomeEvent(42)

        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("otherFunc(0x0A, 1)"),
            "Snippet for first assert is incorrect"
        );

        let code_no_violations = r#"
            pragma solidity ^0.8.10;

            uint constant MY_CONSTANT = 10;
            uint constant ZERO = 0;
            uint constant ONE = 1;

            contract Test {
                uint stateVar = 5;
                function check(uint input) public pure {
                     require(input > MY_CONSTANT, "Input too low"); 
                     require(input != ZERO && input != ONE, "Cannot be 0 or 1");
                     uint x = 1;
                     uint y = 0;
                     otherFunc(ZERO, ONE);
                     if (input == MY_CONSTANT) return;
                }
                 function otherFunc(uint a, uint b) internal pure {}
            }
        "#;
        let detector = Arc::new(MagicNumberDetector::default());
        let locations = run_detector_on_code(detector, code_no_violations, "no_violations.sol");
        assert_eq!(
            locations.len(),
            0,
            "Should detect 0 violations when only constants are used in calls"
        );
    }
}
