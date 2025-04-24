use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use solang_parser::pt::VariableAttribute;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct ConstantCaseDetector {
    locations: Arc<Mutex<Vec<Location>>>,
}

impl Detector for ConstantCaseDetector {
    fn id(&self) -> &str {
        "constant-case"
    }

    fn name(&self) -> &str {
        "Constants/Immutables should be CONSTANT_CASE"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Constant and immutable variable names should use all capital letters with underscores separating words (CONSTANT_CASE)."
    }

    fn gas_savings(&self) -> Option<usize> {
        None
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad:
uint constant myConstant = 10;
address immutable deployerAddress;

// Good:
uint constant MY_CONSTANT = 10;
address immutable DEPLOYER_ADDRESS;
```"#
                .to_string(),
        )
    }

    fn get_locations_arc(&self) -> &Arc<Mutex<Vec<Location>>> {
        &self.locations
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_arc = self.clone();

        visitor.on_variable(move |var_def, file| {
            let is_constant = var_def
                .attrs
                .iter()
                .any(|attr| matches!(attr, VariableAttribute::Constant(_)));
            let is_immutable = var_def
                .attrs
                .iter()
                .any(|attr| matches!(attr, VariableAttribute::Immutable(_)));
            let is_override = var_def
                .attrs
                .iter()
                .any(|attr| matches!(attr, VariableAttribute::Override(_, _)));

            // Only check constants/immutables that are not overrides
            if (is_constant || is_immutable) && !is_override {
                if let Some(name_ident) = &var_def.name {
                    let name = &name_ident.name;
                    if name.chars().any(|c| c.is_ascii_lowercase()) {
                        detector_arc.add_location(loc_to_location(&var_def.loc, file));
                    }
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
    fn test_constant_case_detector() {
        let code = r#"
            pragma solidity ^0.8.0;

            uint constant my_constant = 10; // Positive
            uint constant MY_CONSTANT = 10; // Negative
            address immutable deployerAddress; // Positive
            address immutable DEPLOYER_ADDRESS; // Negative
            string constant SomeString = "hello"; // Positive
            bytes32 constant GOOD_BYTES = 0x123; // Negative
            uint immutable overrideValue = 5; // Positive
            uint constant override OVERRIDE_ME = 100; // Negative

            function foo() public pure returns (uint) {
                return MY_CONSTANT;
            }
        "#;

        let detector = Arc::new(ConstantCaseDetector::default());
        let locations = run_detector_on_code(detector, code, "file_level.sol");
        assert_eq!(locations.len(), 4, "File-level: Should detect 4 violations");
        assert_eq!(locations[0].line, 4); // my_constant
        assert_eq!(locations[1].line, 6); // deployerAddress
        assert_eq!(locations[2].line, 8); // SomeString
        assert_eq!(locations[3].line, 10); // overrideValue

        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint constant myConstantInContract = 20; // Positive
                uint constant MY_CONSTANT_IN_CONTRACT = 20; // Negative
                address immutable deployerInContract; // Positive
                address immutable DEPLOYER_IN_CONTRACT; // Negative
                string constant SomeStringInContract = "world"; // Positive
                uint immutable public override overrideMe = 1; // Negative
                uint normalVariable = 5; // Negative
            }
        "#;
        let detector = Arc::new(ConstantCaseDetector::default());
        let locations = run_detector_on_code(detector, code, "contract_level.sol");
        assert_eq!(
            locations.len(),
            3,
            "Contract-level: Should detect 3 violations"
        );
        assert_eq!(locations[0].line, 5); // myConstantInContract
        assert_eq!(locations[1].line, 7); // deployerInContract
        assert_eq!(locations[2].line, 9); // SomeStringInContract

        let code_no_violations = r#"
            pragma solidity ^0.8.10;

            uint constant MY_CONSTANT = 10;
            address immutable DEPLOYER_ADDRESS;

            contract Test {
                uint constant MY_OTHER_CONSTANT = 20;
                address immutable ANOTHER_IMMUTABLE;
                uint public normal_var;
                 uint immutable public override OVERRIDE_ME = 1; // Ignored: Override
            }
        "#;
        let detector = Arc::new(ConstantCaseDetector::default());
        let locations = run_detector_on_code(detector, code_no_violations, "no_violations.sol");
        assert_eq!(locations.len(), 0, "Should detect 0 violations");
    }
}
