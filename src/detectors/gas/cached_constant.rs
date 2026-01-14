use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::{find_statement_types, get_contract_info};
use solang_parser::pt::{ContractPart, Expression, Identifier, Statement};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct CachedConstantDetector;

impl Detector for CachedConstantDetector {
    fn id(&self) -> &'static str {
        "cached-constant"
    }

    fn name(&self) -> &str {
        "Do not cache constants to save gas"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Using constant variables directly is the most gas-efficient approach, \
        as Solidity's compiler optimizes their usage. Caching them wastes gas."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
uint256 public constant FEE = 100;

// Bad - unnecessary caching
function bad() external {
    uint256 fee = FEE;
    // use fee...
}

// Good - use constant directly
function good() external {
    // use FEE directly...
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

            // Get constant state variable names
            let constants: HashSet<&str> = contract_info
                .state_variables
                .iter()
                .filter(|v| v.is_constant)
                .map(|v| v.name.as_str())
                .collect();

            if constants.is_empty() {
                return Vec::new();
            }

            let mut findings = Vec::new();

            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    if let Some(body) = &func_def.body {
                        findings.extend(find_statement_types(body, file, self.id(), |stmt| {
                            if let Statement::VariableDefinition(_, _, Some(init)) = stmt {
                                if let Expression::Variable(Identifier { name, .. }) = init {
                                    return constants.contains(name.as_str());
                                }
                            }
                            false
                        }));
                    }
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
    fn test_detects_cached_constant() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256 public constant CONSTANT_VAR = 1;

                function test() public {
                    uint256 cacheVar = CONSTANT_VAR;
                }
            }
        "#;

        let detector = Arc::new(CachedConstantDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 8, "uint256 cacheVar = CONSTANT_VAR");
    }

    #[test]
    fn test_skips_non_constant() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256 public stateVar = 1;

                function test() public {
                    uint256 cacheVar = stateVar;
                }
            }
        "#;

        let detector = Arc::new(CachedConstantDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
