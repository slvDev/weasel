use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::{FindingData, SolidityFile};
use crate::utils::ast_utils::find_locations_in_statement;
use solang_parser::pt::{ContractPart, Expression, FunctionDefinition, Loc, Statement};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct CacheStateVariablesDetector;

impl Detector for CacheStateVariablesDetector {
    fn id(&self) -> &'static str {
        "cache-state-variables"
    }

    fn name(&self) -> &str {
        "State variables should be cached in stack variables rather than re-reading them from storage"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Caching of a state variable replaces each Gwarmaccess (100 gas) with a much cheaper \
        stack read. The instances point to the second+ access of a state variable within a \
        function. Saves 100 gas per instance."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - reading state variable multiple times
function bad() external view returns (uint256) {
    uint256 a = stateVar + 1;
    uint256 b = stateVar + 2;
    return a + b + stateVar;
}

// Good - cache in local variable
function good() external view returns (uint256) {
    uint256 cached = stateVar;
    uint256 a = cached + 1;
    uint256 b = cached + 2;
    return a + b + cached;
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, context| {
            let contract_name = match contract_def.name.as_ref() {
                Some(name) => name.name.as_str(),
                None => return Vec::new(),
            };

            let qualified_name = context.get_qualified_name_for_contract(contract_name);
            let state_vars = context.get_all_state_variables(&qualified_name);

            if state_vars.is_empty() {
                return Vec::new();
            }

            let mut findings = Vec::new();

            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    if let Some(body) = &func_def.body {
                        let local_vars = Self::get_local_vars(func_def, body);

                        for state_var in &state_vars {
                            // Skip if shadowed by local variable
                            if local_vars.contains(&state_var.name) {
                                continue;
                            }

                            let var_name = state_var.name.as_str();
                            let mut occurrences = Vec::new();

                            let mut predicate =
                                |expr: &Expression, _: &SolidityFile| -> Option<Loc> {
                                    if let Expression::Variable(ident) = expr {
                                        if ident.name == var_name {
                                            return Some(ident.loc);
                                        }
                                    }
                                    None
                                };

                            find_locations_in_statement(
                                body,
                                file,
                                &mut predicate,
                                &mut occurrences,
                            );

                            // Report 2nd+ occurrences
                            if occurrences.len() > 1 {
                                for loc in occurrences.into_iter().skip(1) {
                                    findings.push(FindingData {
                                        detector_id: self.id(),
                                        location: loc,
                                    });
                                }
                            }
                        }
                    }
                }
            }

            findings
        });
    }
}

impl CacheStateVariablesDetector {
    fn get_local_vars(func_def: &FunctionDefinition, body: &Statement) -> HashSet<String> {
        let mut local_vars = HashSet::new();

        // Add function parameters
        for (_, param_opt) in &func_def.params {
            if let Some(param) = param_opt {
                if let Some(name) = &param.name {
                    local_vars.insert(name.name.clone());
                }
            }
        }

        // Add local variable declarations
        Self::collect_local_declarations(body, &mut local_vars);

        local_vars
    }

    fn collect_local_declarations(stmt: &Statement, local_vars: &mut HashSet<String>) {
        match stmt {
            Statement::VariableDefinition(_, decl, _) => {
                if let Some(name) = &decl.name {
                    local_vars.insert(name.name.clone());
                }
            }
            Statement::Block { statements, .. } => {
                for s in statements {
                    Self::collect_local_declarations(s, local_vars);
                }
            }
            Statement::If(_, _, then_stmt, else_stmt) => {
                Self::collect_local_declarations(then_stmt, local_vars);
                if let Some(else_s) = else_stmt {
                    Self::collect_local_declarations(else_s, local_vars);
                }
            }
            Statement::For(_, init, _, _, body_opt) => {
                if let Some(init_stmt) = init {
                    Self::collect_local_declarations(init_stmt, local_vars);
                }
                if let Some(body) = body_opt {
                    Self::collect_local_declarations(body, local_vars);
                }
            }
            Statement::While(_, _, body) | Statement::DoWhile(_, body, _) => {
                Self::collect_local_declarations(body, local_vars);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_multiple_reads() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256 public stateVar;
                uint256 public otherVar;

                function multipleReads() external view returns (uint256) {
                    uint256 a = stateVar + 1;
                    uint256 b = stateVar + 2;
                    return a + b + stateVar;
                }

                function twoVarsMultipleReads() external view returns (uint256) {
                    return stateVar + otherVar + stateVar + otherVar;
                }
            }
        "#;

        let detector = Arc::new(CacheStateVariablesDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        // multipleReads: 2nd and 3rd read of stateVar
        // twoVarsMultipleReads: 2nd read of stateVar, 2nd read of otherVar
        assert_eq!(locations.len(), 4);
    }

    #[test]
    fn test_skips_single_reads_and_local_vars() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256 public stateVar;

                function singleRead() external view returns (uint256) {
                    return stateVar;
                }

                function localShadowing() external view returns (uint256) {
                    uint256 stateVar = 42;
                    return stateVar + stateVar;
                }

                function parameterShadowing(uint256 stateVar) external pure returns (uint256) {
                    return stateVar + stateVar;
                }
            }
        "#;

        let detector = Arc::new(CacheStateVariablesDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
