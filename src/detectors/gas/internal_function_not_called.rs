use crate::detectors::Detector;
use crate::models::scope::{FunctionType, FunctionVisibility};
use crate::models::severity::Severity;
use crate::utils::ast_utils::{collect_function_calls, get_contract_info};
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::ContractPart;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct InternalFunctionNotCalledDetector;

impl Detector for InternalFunctionNotCalledDetector {
    fn id(&self) -> &'static str {
        "internal-function-not-called"
    }

    fn name(&self) -> &str {
        "Internal Function Not Called"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Internal functions that are not called by the contract or its derived contracts \
         should be removed to save deployment gas. If the function is required by an interface, \
         the contract should inherit from that interface and use the `override` keyword."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - unused internal function wastes gas
contract Example {
    function unusedHelper() internal pure returns (uint) {
        return 42;
    }

    function publicFunc() public pure returns (uint) {
        return 100;
    }
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

            let mut internal_funcs = HashMap::new();
            for func_info in &contract_info.function_definitions {
                if matches!(func_info.visibility, FunctionVisibility::Internal)
                    && !func_info.is_virtual
                    && !func_info.is_override
                    && !func_info.name.is_empty()
                    && !matches!(
                        func_info.function_type,
                        FunctionType::Constructor | FunctionType::Fallback | FunctionType::Receive
                    )
                {
                    internal_funcs.insert(func_info.name.clone(), func_info);
                }
            }

            if internal_funcs.is_empty() {
                return Vec::new();
            }

            let mut called_functions = HashSet::new();
            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    if let Some(body) = &func_def.body {
                        collect_function_calls(body, &mut called_functions);
                    }
                }
            }

            let mut findings = Vec::new();
            for (name, func_info) in &internal_funcs {
                if !called_functions.contains(name) {
                    findings.push(FindingData {
                        detector_id: self.id(),
                        location: func_info.loc.clone(),
                    });
                }
            }

            findings.sort_by_key(|f| f.location.line);

            findings
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_unused_internal_function() {
        let code = r#"
            contract Test {
                function unusedHelper() internal pure returns (uint) {
                    return 42;
                }

                function anotherUnused() internal view returns (uint) {
                    return block.timestamp;
                }

                function publicFunc() public pure returns (uint) {
                    return 100;
                }
            }
        "#;
        let detector = Arc::new(InternalFunctionNotCalledDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 3, "function unusedHelper()");
        assert_eq!(locations[1].line, 7, "function anotherUnused()");
    }

    #[test]
    fn test_skips_used_internal_functions() {
        let code = r#"
            contract Test {
                function helper() internal pure returns (uint) {
                    return 42;
                }

                function publicFunc() public pure returns (uint) {
                    return helper();
                }
            }
        "#;
        let detector = Arc::new(InternalFunctionNotCalledDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
