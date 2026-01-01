use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::{FindingData, SolidityFile, TypeInfo};
use crate::utils::ast_utils::{collect_local_variables, find_locations_in_statement, get_contract_info};
use crate::core::visitor::ASTVisitor;
use solang_parser::pt::{ContractPart, Expression, FunctionDefinition, Loc, Statement};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnsafeIntToUintCastDetector;

impl Detector for UnsafeIntToUintCastDetector {
    fn id(&self) -> &'static str {
        "math-max-after-uint-cast"
    }

    fn name(&self) -> &str {
        "`Math.max(<x>,0)` used with `int` cast to `uint`"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "The code casts an `int` to a `uint` before passing it to `Math.max()`. It seems as though the \
         `Math.max()` call is attempting to prevent values from being negative, but since the `int` is being \
         cast to `uint`, the value will never be negative, and instead will overflow if the int value is negative. \
         The `Math.max()` call is sending misleading signals. Move it to inside the cast to `uint`: \
         use `uint(Math.max(intValue, 0))` instead of `Math.max(uint(intValue), 0)`."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - int is cast to uint BEFORE Math.max, causing overflow
function calculate(int256 value) public pure returns (uint256) {
    return Math.max(uint256(value), 0);
    // If value = -1, then uint256(-1) = 2^256 - 1 (overflow!)
    // Math.max(2^256-1, 0) = 2^256-1 (wrong!)
}

// Good - Math.max happens in int space, THEN cast to uint
function calculate(int256 value) public pure returns (uint256) {
    return uint256(Math.max(value, 0));
    // If value = -1, then Math.max(-1, 0) = 0
    // uint256(0) = 0 (correct!)
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

            // Get state variable types
            let state_var_types: HashMap<String, TypeInfo> = contract_info
                .state_variables
                .iter()
                .map(|v| (v.name.clone(), v.type_info.clone()))
                .collect();

            let mut all_findings = Vec::new();

            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    let Some(body) = &func_def.body else {
                        continue;
                    };

                    // Build variable type map
                    let var_types = Self::build_variable_type_map(func_def, body, &state_var_types);

                    let mut findings = Vec::new();
                    let mut predicate = |expr: &Expression, _file: &SolidityFile| -> Option<Loc> {
                        if let Expression::FunctionCall(loc, func_expr, args) = expr {
                            if let Expression::MemberAccess(_, _, member) = func_expr.as_ref() {
                                if member.name == "max" {
                                    for arg in args {
                                        if Self::is_uint_cast_of_int(arg, &var_types) {
                                            return Some(loc.clone());
                                        }
                                    }
                                }
                            }
                        }
                        None
                    };

                    find_locations_in_statement(body, file, &mut predicate, &mut findings);

                    all_findings.extend(findings.into_iter().map(|loc| FindingData {
                        detector_id: self.id(),
                        location: loc,
                    }));
                }
            }

            all_findings
        });
    }
}

impl UnsafeIntToUintCastDetector {
    fn build_variable_type_map(
        func_def: &FunctionDefinition,
        body: &Statement,
        state_var_types: &HashMap<String, TypeInfo>,
    ) -> HashMap<String, TypeInfo> {
        let mut var_types = state_var_types.clone();

        // Add function parameters
        for (_loc, param_opt) in &func_def.params {
            if let Some(param) = param_opt {
                if let Some(name) = &param.name {
                    let type_info = TypeInfo::from_expression(&param.ty);
                    var_types.insert(name.name.clone(), type_info);
                }
            }
        }

        // Add return parameters
        for (_loc, return_param_opt) in &func_def.returns {
            if let Some(return_param) = return_param_opt {
                if let Some(name) = &return_param.name {
                    let type_info = TypeInfo::from_expression(&return_param.ty);
                    var_types.insert(name.name.clone(), type_info);
                }
            }
        }

        // Add local variable declarations
        collect_local_variables(body, &mut |decl| {
            if let Some(name) = &decl.name {
                let type_info = TypeInfo::from_expression(&decl.ty);
                var_types.insert(name.name.clone(), type_info);
            }
        });

        var_types
    }

    fn is_uint_cast_of_int(expr: &Expression, var_types: &HashMap<String, TypeInfo>) -> bool {
        if let Expression::FunctionCall(_, func, args) = expr {
            if let Expression::Type(_, ty) = func.as_ref() {
                let cast_type = TypeInfo::from_solang_type(ty);
                // Check if casting to uint
                if cast_type.is_uint() && !args.is_empty() {
                    // Check if argument is int variable or int cast
                    return Self::contains_int_value(&args[0], var_types);
                }
            }
        }
        false
    }

    fn contains_int_value(expr: &Expression, var_types: &HashMap<String, TypeInfo>) -> bool {
        match expr {
            Expression::Variable(id) => {
                if let Some(var_type) = var_types.get(&id.name) {
                    return var_type.is_int();
                }
                false
            }
            Expression::FunctionCall(_, func, _) => {
                if let Expression::Type(_, ty) = func.as_ref() {
                    return TypeInfo::from_solang_type(ty).is_int();
                }
                false
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
    fn test_detects_unsafe_uint_cast_of_int() {
        let code = r#"
            contract Test {
                int256 stateVar;

                function nested(int256 value) public pure returns (uint256) {
                    return Math.max(uint256(int256(value)), 0);
                }

                function directVar(int256 value) public pure returns (uint256) {
                    return Math.max(uint256(value), 0);
                }

                function local() public pure returns (uint256) {
                    int256 x = -5;
                    return Math.max(uint256(x), 100);
                }

                function state() public view returns (uint256) {
                    return SignedMath.max(uint256(stateVar), 0);
                }

                function smallInt(int128 val) public pure returns (uint256) {
                    return Math.max(uint256(val), 1);
                }
            }
        "#;
        let detector = Arc::new(UnsafeIntToUintCastDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 5);
        assert_eq!(locations[0].line, 6);
        assert_eq!(locations[1].line, 10);
        assert_eq!(locations[2].line, 15);
        assert_eq!(locations[3].line, 19);
        assert_eq!(locations[4].line, 23);
    }

    #[test]
    fn test_skips_safe_patterns() {
        let code = r#"
            contract Test {
                uint256 uintState;

                function correctOrder(int256 value) public pure returns (uint256) {
                    return uint256(Math.max(value, 0));
                }

                function bothUint(uint256 a, uint256 b) public pure returns (uint256) {
                    return Math.max(a, b);
                }

                function uintVar(uint256 x) public pure returns (uint256) {
                    return Math.max(uint256(x), 0);
                }

                function stateUint() public view returns (uint256) {
                    return Math.max(uint256(uintState), 0);
                }

                function noCast(int256 val) public pure returns (int256) {
                    return Math.max(val, 0);
                }
            }
        "#;
        let detector = Arc::new(UnsafeIntToUintCastDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
