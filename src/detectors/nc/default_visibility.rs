use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{
    ContractPart, FunctionAttribute, FunctionDefinition, FunctionTy, SourceUnitPart,
    VariableAttribute, VariableDefinition, Visibility,
};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct DefaultVisibilityDetector {
    locations: Arc<Mutex<Vec<Location>>>,
}

/// Checks if a variable definition has explicit visibility.
fn has_explicit_visibility_var(var_def: &VariableDefinition) -> bool {
    var_def.attrs.iter().any(|attr| {
        matches!(
            attr,
            VariableAttribute::Visibility(Visibility::Public(_))
                | VariableAttribute::Visibility(Visibility::Private(_))
                | VariableAttribute::Visibility(Visibility::Internal(_))
        )
    })
}

/// Checks if a function definition has explicit visibility.
fn has_explicit_visibility_func(func_def: &FunctionDefinition) -> bool {
    func_def.attributes.iter().any(|attr| {
        matches!(
            attr,
            FunctionAttribute::Visibility(Visibility::Public(_))
                | FunctionAttribute::Visibility(Visibility::Private(_))
                | FunctionAttribute::Visibility(Visibility::Internal(_))
                | FunctionAttribute::Visibility(Visibility::External(_))
        )
    })
}

impl Detector for DefaultVisibilityDetector {
    fn id(&self) -> &str {
        "default-visibility"
    }

    fn name(&self) -> &str {
        "Explicitly Specify Visibility"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "State variables and functions should explicitly specify their visibility (public, private, internal, external). Default visibility (internal for state variables, public for functions) can be less clear."
    }

    fn gas_savings(&self) -> Option<usize> {
        None
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
uint stateVar; // Default internal
function getValue() returns (uint) { ... } // Default public

// Explicitly specify visibility:
uint internal stateVar;
function getValue() public returns (uint) { ... }
function _internalHelper() internal { ... }
address private owner;
```"#
                .to_string(),
        )
    }

    fn get_locations_arc(&self) -> &Arc<Mutex<Vec<Location>>> {
        &self.locations
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_arc = self.clone();

        // Check file-level state variables
        visitor.on_source_unit_part(move |part, file| {
            if let SourceUnitPart::VariableDefinition(var_def) = part {
                if !has_explicit_visibility_var(var_def) {
                    detector_arc.add_location(loc_to_location(&var_def.loc, file));
                }
            }
        });

        // Check contract-level state variables
        let detector_arc = self.clone();
        visitor.on_contract_part(move |part, file| {
            if let ContractPart::VariableDefinition(var_def) = part {
                if !has_explicit_visibility_var(var_def) {
                    detector_arc.add_location(loc_to_location(&var_def.loc, file));
                }
            }
        });

        // Check functions
        let detector_arc = self.clone();
        visitor.on_function(move |func_def, file| {
            // Ignore constructors and special fallbacks/receive functions
            match func_def.ty {
                FunctionTy::Constructor | FunctionTy::Fallback | FunctionTy::Receive => return,
                _ => {}
            }

            if !has_explicit_visibility_func(func_def) {
                detector_arc.add_location(loc_to_location(&func_def.loc, file));
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
    fn test_default_visibility_detector() {
        let code = r#"
            pragma solidity ^0.8.0;

            uint fileVar; // Positive
            address internal fileVarInternal; // Negative

            contract Test {
                uint stateVar; // Positive
                mapping(address => uint) internal balances; // Negative
                bool public flag; // Negative
                address private owner; // Negative

                constructor() {} // Ignored

                function getValue() returns (uint) { // Positive
                    return stateVar;
                }

                function _internalHelper() internal {} // Negative

                function sendValue() external {} // Negative

                function updateValue(uint _newValue) private {} // Negative

                fallback() external payable {} // Ignored
                receive() external payable {} // Ignored
            }

             function fileLevelFunc() pure returns(uint) { // Positive
                uint localVar; // Local vars ignored
                return 5;
             }
        "#;

        let detector = Arc::new(DefaultVisibilityDetector::default());
        let locations = run_detector_on_code(detector, code, "default_vis.sol");

        assert_eq!(locations.len(), 4, "Should detect 4 default visibilities");
        assert_eq!(locations[0].line, 4); // fileVar
        assert_eq!(locations[1].line, 8); // stateVar
        assert_eq!(locations[2].line, 15); // getValue function
        assert_eq!(locations[3].line, 29); // fileLevelFunc

        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("uint fileVar"),
            "Snippet for first assert is incorrect"
        );

        let code_no_violations = r#"
            pragma solidity ^0.8.10;

            uint internal fileVar;
            contract Test {
                uint internal stateVar;
                function getValue() public pure returns (uint) { return 1; }
                function _internalHelper() internal pure {}
                constructor() {}
                fallback() external payable {}
            }
        "#;
        let detector = Arc::new(DefaultVisibilityDetector::default());
        let locations = run_detector_on_code(detector, code_no_violations, "no_violations.sol");
        assert_eq!(locations.len(), 0, "Should detect 0 violations");
    }
}
