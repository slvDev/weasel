use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::TypeInfo;
use crate::utils::ast_utils::{collect_local_variables, find_in_statement, get_contract_info};
use solang_parser::pt::{ContractPart, Expression, FunctionDefinition, FunctionTy, Statement};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnsafeDowncastDetector;

impl Detector for UnsafeDowncastDetector {
    fn id(&self) -> &'static str {
        "unsafe-downcast"
    }

    fn name(&self) -> &str {
        "Consider using SafeCast library for downcasting"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Downcasting from `uint256`/`int256` in Solidity does not revert on overflow. This can result \
         in undesired exploitation or bugs, since developers usually assume that overflows raise errors. \
         OpenZeppelin's SafeCast library restores this intuition by reverting the transaction when such \
         an operation overflows. Using this library eliminates an entire class of bugs."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - silent overflow on downcast
function convert(uint256 value) public pure returns (uint128) {
    return uint128(value);  // Silently overflows if value > type(uint128).max
}

// Good - use SafeCast library
import "@openzeppelin/contracts/utils/math/SafeCast.sol";

function convert(uint256 value) public pure returns (uint128) {
    return SafeCast.toUint128(value);  // Reverts on overflow
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

                    let findings = find_in_statement(body, file, self.id(), |expr| {
                        Self::is_unsafe_downcast(expr, &var_types)
                    });

                    all_findings.extend(findings);
                }
            }

            all_findings
        });
    }
}

impl UnsafeDowncastDetector {
    /// Bit sizes for int/uint types
    const MAX_BITS: u16 = 256;

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

    fn is_unsafe_downcast(expr: &Expression, var_types: &HashMap<String, TypeInfo>) -> bool {
        let Expression::FunctionCall(_, func, args) = expr else {
            return false;
        };
        let Expression::Type(_, ty) = func.as_ref() else {
            return false;
        };

        let target_type = TypeInfo::from_solang_type(ty);

        // Only check int/uint downcasts
        if !target_type.is_int() && !target_type.is_uint() {
            return false;
        }

        let target_bits = Self::get_type_bits(&target_type);

        // Only flag if target is smaller than 256 bits (downcasting)
        if target_bits >= Self::MAX_BITS {
            return false;
        }

        if args.is_empty() {
            return false;
        }

        // Skip time-related variables (common acceptable pattern)
        if Self::is_time_related(&args[0]) {
            return false;
        }

        // Check if argument is a larger type being downcast
        if let Some(source_bits) = Self::get_expression_bits(&args[0], var_types) {
            return source_bits > target_bits;
        }

        false
    }

    /// Check if expression references time-related variables (common skip pattern)
    fn is_time_related(expr: &Expression) -> bool {
        match expr {
            Expression::Variable(id) => {
                let name_lower = id.name.to_lowercase();
                name_lower.contains("block")
                    || name_lower.contains("time")
                    || name_lower.contains("timestamp")
            }
            Expression::MemberAccess(_, base, member) => {
                let member_lower = member.name.to_lowercase();
                if member_lower.contains("time") || member_lower.contains("timestamp") {
                    return true;
                }
                // Check base.member like block.timestamp
                if let Expression::Variable(id) = base.as_ref() {
                    if id.name == "block" {
                        return true;
                    }
                }
                false
            }
            // Recursively check nested casts like uint64(uint256(timestamp))
            Expression::FunctionCall(_, func, args) => {
                if let Expression::Type(_, _) = func.as_ref() {
                    if !args.is_empty() {
                        return Self::is_time_related(&args[0]);
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Get bit size of a type
    fn get_type_bits(type_info: &TypeInfo) -> u16 {
        match type_info {
            TypeInfo::Uint(bits) => *bits,
            TypeInfo::Int(bits) => *bits,
            _ => 0,
        }
    }

    /// Get bit size of an expression's type
    fn get_expression_bits(
        expr: &Expression,
        var_types: &HashMap<String, TypeInfo>,
    ) -> Option<u16> {
        match expr {
            Expression::Variable(id) => {
                var_types.get(&id.name).map(Self::get_type_bits)
            }
            // Nested type cast - get the target type bits
            Expression::FunctionCall(_, func, _) => {
                if let Expression::Type(_, ty) = func.as_ref() {
                    let type_info = TypeInfo::from_solang_type(ty);
                    let bits = Self::get_type_bits(&type_info);
                    if bits > 0 {
                        return Some(bits);
                    }
                }
                None
            }
            // Address cast like uint256(uint160(address(x))) - uint160 is 160 bits
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_unsafe_downcasts() {
        let code = r#"
            contract Test {
                uint256 largeValue;

                function downcastUint(uint256 value) public pure returns (uint128) {
                    return uint128(value);
                }

                function downcastInt(int256 value) public pure returns (int64) {
                    return int64(value);
                }

                function downcastState() public view returns (uint64) {
                    return uint64(largeValue);
                }

                function downcast128to64(uint128 value) public pure returns (uint64) {
                    return uint64(value);
                }

                function nestedDowncast(uint256 x) public pure returns (uint32) {
                    return uint32(uint128(x));
                }
            }
        "#;
        let detector = Arc::new(UnsafeDowncastDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 6);
        assert_eq!(locations[0].line, 6, "uint128(uint256)");
        assert_eq!(locations[1].line, 10, "int64(int256)");
        assert_eq!(locations[2].line, 14, "uint64(stateVar)");
        assert_eq!(locations[3].line, 18, "uint64(uint128)");
        assert_eq!(locations[4].line, 22, "uint32(uint128)");
        assert_eq!(locations[5].line, 22, "uint128(x)");
    }

    #[test]
    fn test_skips_safe_patterns() {
        let code = r#"
            contract Test {
                function sameSize(uint256 value) public pure returns (uint256) {
                    return uint256(value);
                }

                function upcast(uint128 value) public pure returns (uint256) {
                    return uint256(value);
                }

                function addressCast(address addr) public pure returns (uint256) {
                    return uint256(uint160(addr));
                }

                function timestampCast() public view returns (uint64) {
                    return uint64(block.timestamp);
                }

                function timeVar(uint256 blockTime) public pure returns (uint32) {
                    return uint32(blockTime);
                }
            }
        "#;
        let detector = Arc::new(UnsafeDowncastDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
