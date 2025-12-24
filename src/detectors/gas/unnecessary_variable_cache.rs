use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::{FindingData, SolidityFile};
use crate::utils::ast_utils::{find_variable_uses, get_local_variable_names};
use crate::utils::location::loc_to_location;
use solang_parser::pt::{ContractPart, Expression, FunctionDefinition, Loc, Statement};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnnecessaryVariableCacheDetector;

impl Detector for UnnecessaryVariableCacheDetector {
    fn id(&self) -> &'static str {
        "unnecessary-variable-cache"
    }

    fn name(&self) -> &str {
        "Stack variable used as a cache for state variable is only used once"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "If a variable caching a state variable is only accessed once, it's cheaper to use \
        the state variable directly and save the 3 gas the extra stack assignment would spend."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - unnecessary cache (only used once)
function bad() external view returns (uint256) {
    uint256 cached = stateVar;
    return cached;
}

// Good - use state variable directly
function good() external view returns (uint256) {
    return stateVar;
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
            let state_var_names: HashSet<&str> =
                state_vars.iter().map(|v| v.name.as_str()).collect();

            if state_var_names.is_empty() {
                return Vec::new();
            }

            let mut findings = Vec::new();

            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    if let Some(body) = &func_def.body {
                        Self::check_function(
                            &self,
                            func_def,
                            body,
                            file,
                            &state_var_names,
                            &mut findings,
                        );
                    }
                }
            }

            findings
        });
    }
}

impl UnnecessaryVariableCacheDetector {
    fn check_function(
        &self,
        func_def: &FunctionDefinition,
        body: &Statement,
        file: &SolidityFile,
        state_var_names: &HashSet<&str>,
        findings: &mut Vec<FindingData>,
    ) {
        // Get local variable names to handle shadowing
        let local_vars = get_local_variable_names(func_def, body);

        // Filter state vars that aren't shadowed by locals
        let effective_state_vars: HashSet<&str> = state_var_names
            .iter()
            .filter(|name| !local_vars.contains(**name))
            .copied()
            .collect();

        let caches = Self::find_state_var_caches(body, &effective_state_vars);

        for (loc, var_name) in caches {
            let total_uses = find_variable_uses(&var_name, body, file).len();

            // Only flag if used once AND not used in any loop
            if total_uses == 1 && !Self::is_used_in_loop(&var_name, body, file) {
                findings.push(FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&loc, file),
                });
            }
        }
    }

    fn find_state_var_caches(
        stmt: &Statement,
        state_var_names: &HashSet<&str>,
    ) -> Vec<(Loc, String)> {
        let mut caches = Vec::new();
        Self::find_caches_recursive(stmt, state_var_names, &mut caches);
        caches
    }

    fn find_caches_recursive(
        stmt: &Statement,
        state_var_names: &HashSet<&str>,
        caches: &mut Vec<(Loc, String)>,
    ) {
        match stmt {
            Statement::VariableDefinition(loc, decl, Some(init)) => {
                if let Expression::Variable(ident) = init {
                    if state_var_names.contains(ident.name.as_str()) {
                        if let Some(var_name) = &decl.name {
                            caches.push((*loc, var_name.name.clone()));
                        }
                    }
                }
            }
            Statement::Block { statements, .. } => {
                for s in statements {
                    Self::find_caches_recursive(s, state_var_names, caches);
                }
            }
            Statement::If(_, _, then_stmt, else_stmt) => {
                Self::find_caches_recursive(then_stmt, state_var_names, caches);
                if let Some(else_s) = else_stmt {
                    Self::find_caches_recursive(else_s, state_var_names, caches);
                }
            }
            Statement::For(_, init, _, _, body_opt) => {
                if let Some(init_stmt) = init {
                    Self::find_caches_recursive(init_stmt, state_var_names, caches);
                }
                if let Some(body) = body_opt {
                    Self::find_caches_recursive(body, state_var_names, caches);
                }
            }
            Statement::While(_, _, body) | Statement::DoWhile(_, body, _) => {
                Self::find_caches_recursive(body, state_var_names, caches);
            }
            _ => {}
        }
    }

    fn is_used_in_loop(var_name: &str, stmt: &Statement, file: &SolidityFile) -> bool {
        match stmt {
            Statement::For(_, _, _, _, Some(body))
            | Statement::While(_, _, body)
            | Statement::DoWhile(_, body, _) => {
                // If used in this loop body, we're done
                if !find_variable_uses(var_name, body, file).is_empty() {
                    return true;
                }
                // Also check for nested loops inside the body
                Self::is_used_in_loop(var_name, body, file)
            }
            Statement::Block { statements, .. } => {
                statements.iter().any(|s| Self::is_used_in_loop(var_name, s, file))
            }
            Statement::If(_, _, then_stmt, else_stmt) => {
                Self::is_used_in_loop(var_name, then_stmt, file)
                    || else_stmt.as_ref().map_or(false, |e| Self::is_used_in_loop(var_name, e, file))
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_unnecessary_cache() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256 public stateVar;
                address public owner;

                function singleUse() external view returns (uint256) {
                    uint256 cached = stateVar;
                    return cached;
                }

                function singleUseAddress() external view returns (address) {
                    address cachedOwner = owner;
                    return cachedOwner;
                }
            }
        "#;

        let detector = Arc::new(UnnecessaryVariableCacheDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 9, "cached = stateVar");
        assert_eq!(locations[1].line, 14, "cachedOwner = owner");
    }

    #[test]
    fn test_skips_multi_use_cache() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256 public stateVar;

                function multipleUses() external view returns (uint256) {
                    uint256 cached = stateVar;
                    uint256 a = cached + 1;
                    uint256 b = cached + 2;
                    return a + b;
                }

                function usedInLoop() external view returns (uint256) {
                    uint256 cached = stateVar;
                    uint256 sum = 0;
                    for (uint i = 0; i < 10; i++) {
                        sum += cached;
                    }
                    return sum;
                }

                function notFromStateVar() external pure returns (uint256) {
                    uint256 local = 42;
                    uint256 cached = local;
                    return cached;
                }
            }
        "#;

        let detector = Arc::new(UnnecessaryVariableCacheDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
