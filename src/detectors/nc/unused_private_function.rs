use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::scope::FunctionVisibility;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::ast_utils::{collect_function_calls, get_contract_info};
use solang_parser::pt::ContractPart;
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnusedPrivateFunctionDetector;

impl Detector for UnusedPrivateFunctionDetector {
    fn id(&self) -> &'static str {
        "unused-private-function"
    }

    fn name(&self) -> &str {
        "Unused private functions can be removed"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Private functions that are never called within the contract are dead code and should \
         be removed to improve code clarity and reduce deployment costs."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - unused private function
contract Example {
    function unused() private {} // never called
    function main() external {}
}

// Good - remove unused code
contract Example {
    function main() external {}
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

            // Collect all private function names and their locations
            let private_funcs: Vec<_> = contract_info
                .function_definitions
                .iter()
                .filter(|f| matches!(f.visibility, FunctionVisibility::Private))
                .collect();

            if private_funcs.is_empty() {
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

            // Find unused private functions
            let mut findings = Vec::new();
            for func in private_funcs {
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
    fn test_detects_issue() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function notUsed() private {}   // Line 5 - unused
                function used() private {}      // used - not flagged
                function init() external {
                    used();
                }
            }
        "#;
        let detector = Arc::new(UnusedPrivateFunctionDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 1, "Should detect 1 unused private function");
        assert_eq!(locations[0].line, 5, "notUsed on line 5");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function helper() private returns (uint256) {
                    return 42;
                }
                function main() external returns (uint256) {
                    return helper();  // helper is used
                }
            }
        "#;
        let detector = Arc::new(UnusedPrivateFunctionDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "All private functions are used");
    }
}
