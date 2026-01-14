use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::{find_statement_types, get_contract_info};
use solang_parser::pt::{ContractPart, Expression, Identifier, Statement};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct CachedImmutableDetector;

impl Detector for CachedImmutableDetector {
    fn id(&self) -> &'static str {
        "cached-immutable"
    }

    fn name(&self) -> &str {
        "Use immutable variables directly instead of caching in stack"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Caching immutable variables in stack is not necessary and costs more gas. \
        Immutable values are embedded directly into the bytecode at deployment, \
        making direct access cheaper than copying to a local variable."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
uint256 public immutable DEPLOY_TIME;

// Bad - unnecessary stack caching
function bad() external view returns (uint256) {
    uint256 deployTime = DEPLOY_TIME;
    return deployTime;
}

// Good - use immutable directly
function good() external view returns (uint256) {
    return DEPLOY_TIME;
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

            // Get immutable state variable names
            let immutables: HashSet<&str> = contract_info
                .state_variables
                .iter()
                .filter(|v| v.is_immutable)
                .map(|v| v.name.as_str())
                .collect();

            if immutables.is_empty() {
                return Vec::new();
            }

            let mut findings = Vec::new();

            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    if let Some(body) = &func_def.body {
                        findings.extend(find_statement_types(body, file, self.id(), |stmt| {
                            if let Statement::VariableDefinition(_, _, Some(init)) = stmt {
                                if let Expression::Variable(Identifier { name, .. }) = init {
                                    return immutables.contains(name.as_str());
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
    fn test_detects_cached_immutable() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256 public immutable IMMUTABLE_VAR;

                constructor() {
                    IMMUTABLE_VAR = block.timestamp;
                }

                function test() public view {
                    uint256 cacheVar = IMMUTABLE_VAR;
                }
            }
        "#;

        let detector = Arc::new(CachedImmutableDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 12, "uint256 cacheVar = IMMUTABLE_VAR");
    }

    #[test]
    fn test_skips_non_immutable() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256 public stateVar = 1;

                function test() public view {
                    uint256 cacheVar = stateVar;
                }
            }
        "#;

        let detector = Arc::new(CachedImmutableDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
