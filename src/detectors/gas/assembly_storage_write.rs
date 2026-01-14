use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::{find_in_statement, get_contract_info};
use solang_parser::pt::{ContractPart, Expression, Identifier};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct AssemblyStorageWriteDetector;

impl Detector for AssemblyStorageWriteDetector {
    fn id(&self) -> &'static str {
        "assembly-storage-write"
    }

    fn name(&self) -> &str {
        "Use `assembly` to write mutable storage values"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Writing to storage using `assembly` is more gas efficient. \
        Using `sstore` directly can save around 11 gas per write operation."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
storageNumber = 10; // 2358 gas
storageAddr = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc3; // 2411 gas

// Good
assembly {
    sstore(storageNumber.slot, 10) // 2350 gas
    sstore(storageAddr.slot, 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc3) // 2350 gas
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

            // Get mutable state variable names
            let mutable_vars: HashSet<&str> = contract_info
                .state_variables
                .iter()
                .filter(|v| !v.is_immutable && !v.is_constant)
                .map(|v| v.name.as_str())
                .collect();

            if mutable_vars.is_empty() {
                return Vec::new();
            }

            let mut findings = Vec::new();

            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    if let Some(body) = &func_def.body {
                        findings.extend(find_in_statement(body, file, self.id(), |expr| {
                            if let Expression::Assign(_, left, _) = expr {
                                if let Some(var_name) = get_var_name(left) {
                                    return mutable_vars.contains(var_name.as_str());
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

fn get_var_name(expr: &Expression) -> Option<String> {
    match expr {
        Expression::Variable(Identifier { name, .. }) => Some(name.clone()),
        Expression::MemberAccess(_, inner, _) | Expression::ArraySubscript(_, inner, _) => {
            get_var_name(inner)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_storage_writes() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256 storageVariable;
                mapping(uint256 => mapping(address => uint256)) mappingVariable;

                struct TestStruct {
                    mapping(address => uint256) user;
                }
                TestStruct structVariable;

                function test(uint256 funcParam) external {
                    funcParam = 10;
                    uint256 localVariable;
                    localVariable = 20;
                    storageVariable = 30;
                    mappingVariable[funcParam][msg.sender] = 40;
                    structVariable.user[msg.sender] = 50;
                }
            }
        "#;

        let detector = Arc::new(AssemblyStorageWriteDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 17, "storageVariable = 30");
        assert_eq!(locations[1].line, 18, "mappingVariable assignment");
        assert_eq!(locations[2].line, 19, "structVariable assignment");
    }

    #[test]
    fn test_skips_excluded_variables() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256 immutable immutableVar;
                uint256 constant CONST = 1;

                constructor() {
                    immutableVar = 100;
                }

                function test(uint256 param) external returns (uint256 result) {
                    param = 10;
                    result = 20;
                    uint256 local;
                    local = 30;
                }
            }
        "#;

        let detector = Arc::new(AssemblyStorageWriteDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
