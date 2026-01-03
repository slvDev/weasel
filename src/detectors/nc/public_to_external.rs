use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::scope::FunctionVisibility;
use crate::models::FindingData;
use crate::utils::ast_utils::{collect_function_calls, get_contract_info};
use solang_parser::pt::ContractPart;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct PublicToExternalDetector;

impl Detector for PublicToExternalDetector {
    fn id(&self) -> &'static str {
        "public-to-external"
    }

    fn name(&self) -> &str {
        "Public functions not called internally should be external"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Public functions that are not called by the contract internally should be declared \
         external instead. External functions have slightly lower gas costs for calldata parameters."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
function withdraw(uint256 amount) public {
    // never called internally
}

// Good
function withdraw(uint256 amount) external {
    // declared external since not called internally
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            let Some(contract_info) = get_contract_info(contract_def, file) else {
                return Vec::new();
            };

            // Get public functions that could be external
            let public_functions: Vec<_> = contract_info
                .function_definitions
                .iter()
                .filter(|f| {
                    matches!(f.visibility, FunctionVisibility::Public)
                        && !f.is_virtual
                        && !f.is_override
                        && !f.name.is_empty()
                })
                .collect();

            if public_functions.is_empty() {
                return Vec::new();
            }

            // Collect all function calls in the contract
            let mut called_functions = HashSet::new();
            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    if let Some(body) = &func_def.body {
                        collect_function_calls(body, &mut called_functions);
                    }
                }
            }

            // Report public functions not called internally
            let mut findings = Vec::new();
            for func in public_functions {
                if !called_functions.contains(&func.name) {
                    findings.push(FindingData {
                        detector_id: self.id(),
                        location: func.loc.clone(),
                    });
                }
            }

            findings
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_public_not_called() {
        let code = r#"
            contract Test {
                function notCalled() public {}
                function alsoNotCalled(uint256 x) public returns (uint256) {
                    return x;
                }
            }
        "#;
        let detector = Arc::new(PublicToExternalDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 3, "notCalled");
        assert_eq!(locations[1].line, 4, "alsoNotCalled");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                function calledInternally() public {
                    // called by another function
                }

                function caller() external {
                    calledInternally();
                }

                function alreadyExternal() external {}

                function virtualFunc() public virtual {}

                function overrideFunc() public override {}
            }
        "#;
        let detector = Arc::new(PublicToExternalDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
