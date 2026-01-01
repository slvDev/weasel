use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::{FindingData, SolidityFile, TypeInfo};
use crate::utils::ast_utils::{collect_local_variables, find_locations_in_statement, get_contract_info};
use crate::core::visitor::ASTVisitor;
use solang_parser::pt::{ContractPart, Expression, FunctionDefinition, FunctionTy, Loc, Statement};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnsafeIntCastDetector;

impl Detector for UnsafeIntCastDetector {
    fn id(&self) -> &'static str {
        "unsafe-int-cast"
    }

    fn name(&self) -> &str {
        "Unsafe cast from `int` to `uint`"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Casting a signed integer (`int`, `int256`, etc.) to an unsigned integer (`uint`, `uint256`, etc.) \
         is unsafe when the signed value is negative. Negative values will overflow to very large unsigned values. \
         Use OpenZeppelin's `SafeCast` library or check that the value is non-negative before casting."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - direct cast can overflow
function convert(int256 value) public pure returns (uint256) {
    return uint256(value);
}

// Good - use SafeCast library
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

function convert(int256 value) public pure returns (uint256) {
    return SafeCast.toUint256(value);  // Reverts if negative
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
                    if matches!(func_def.ty, FunctionTy::Constructor) {
                        continue;
                    }
                    let Some(body) = &func_def.body else {
                        continue;
                    };

                    // Build variable type map
                    let var_types = Self::build_variable_type_map(func_def, body, &state_var_types);

                    let mut findings = Vec::new();
                    let mut predicate = |expr: &Expression, _file: &SolidityFile| -> Option<Loc> {
                        if let Expression::FunctionCall(loc, func, args) = expr {
                            if let Expression::Type(_, ty) = func.as_ref() {
                                let cast_type = TypeInfo::from_solang_type(ty);
                                if cast_type.is_uint() && !args.is_empty() {
                                    // Check if argument is an int variable
                                    if let Some(var_name) = Self::get_variable_name(&args[0]) {
                                        if let Some(var_type) = var_types.get(var_name) {
                                            if var_type.is_int() {
                                                return Some(loc.clone());
                                            }
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

impl UnsafeIntCastDetector {
    fn build_variable_type_map(
        func_def: &FunctionDefinition,
        body: &Statement,
        state_var_types: &HashMap<String, TypeInfo>,
    ) -> HashMap<String, TypeInfo> {
        // Clonestate variables
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

    fn get_variable_name(expr: &Expression) -> Option<&str> {
        match expr {
            Expression::Variable(id) => Some(&id.name),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_unsafe_int_to_uint_cast() {
        let code = r#"
            contract Test {
                function convert(int256 value) public pure returns (uint256) {
                    return uint256(value);
                }

                function convert2(int128 x) public pure {
                    uint128 y = uint128(x);
                }
            }
        "#;
        let detector = Arc::new(UnsafeIntCastDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 4, "uint256(value) where value is int256");
        assert_eq!(locations[1].line, 8, "uint128(x) where x is int128");
    }

    #[test]
    fn test_skips_safe_patterns() {
        let code = r#"
            contract Test {
                function convert(uint256 value) public pure returns (uint256) {
                    return uint256(value);
                }

                function convert2(int256 a, int256 b) public pure {
                    uint256 x = uint256(a + b);
                }
            }
        "#;
        let detector = Arc::new(UnsafeIntCastDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
