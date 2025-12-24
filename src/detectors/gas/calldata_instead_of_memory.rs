use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::{FindingData, SolidityFile};
use crate::utils::ast_utils::find_locations_in_statement;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{
    Expression, FunctionAttribute, FunctionDefinition, FunctionTy, Loc, Statement, StorageLocation,
    Type, Visibility,
};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct CalldataInsteadOfMemoryDetector;

impl Detector for CalldataInsteadOfMemoryDetector {
    fn id(&self) -> &'static str {
        "calldata-instead-of-memory"
    }

    fn name(&self) -> &str {
        "Use calldata instead of memory for function arguments that do not get mutated"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "When a function with a `memory` array is called externally, the `abi.decode()` step has to \
        use a for-loop to copy each index of the `calldata` to the `memory` index. Each iteration \
        of this for-loop costs at least 60 gas (i.e. `60 * <mem_array>.length`). Using `calldata` \
        directly bypasses this loop. Saves 60 gas per instance."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - using memory for unmodified parameter
function processData(uint256[] memory data) external {
    for (uint i = 0; i < data.length; i++) {
        emit DataProcessed(data[i]);
    }
}

// Good - using calldata for unmodified parameter
function processData(uint256[] calldata data) external {
    for (uint i = 0; i < data.length; i++) {
        emit DataProcessed(data[i]);
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            // Skip constructors - they cannot use calldata
            if matches!(func_def.ty, FunctionTy::Constructor) {
                return Vec::new();
            }

            // Only check external and public functions
            if !self.is_external_or_public(func_def) {
                return Vec::new();
            }

            let mut findings = Vec::new();

            // Get function body for modification analysis
            let body = match &func_def.body {
                Some(body) => body,
                None => return Vec::new(), // Interface functions have no body
            };

            // Check each parameter
            for (loc, param_opt) in &func_def.params {
                if let Some(param) = param_opt {
                    // Check if parameter uses memory storage
                    if let Some(StorageLocation::Memory(_)) = &param.storage {
                        // Check if type is a reference type (arrays, bytes, string, structs)
                        if self.is_reference_type(&param.ty) {
                            // Get parameter name
                            let param_name = param
                                .name
                                .as_ref()
                                .map(|id| id.name.as_str())
                                .unwrap_or("");

                            // Check if parameter is modified in function body
                            if !param_name.is_empty()
                                && !self.is_modified_in_body(param_name, body, file)
                            {
                                findings.push(FindingData {
                                    detector_id: self.id(),
                                    location: loc_to_location(loc, file),
                                });
                            }
                        }
                    }
                }
            }

            findings
        });
    }
}

impl CalldataInsteadOfMemoryDetector {
    fn is_external_or_public(&self, func_def: &FunctionDefinition) -> bool {
        func_def.attributes.iter().any(|attr| {
            matches!(
                attr,
                FunctionAttribute::Visibility(Visibility::External(_))
                    | FunctionAttribute::Visibility(Visibility::Public(_))
            )
        })
    }

    fn is_reference_type(&self, type_expr: &Expression) -> bool {
        match type_expr {
            // Array types (dynamic or fixed)
            Expression::ArraySubscript(_, _, _) => true,
            // Type expressions
            Expression::Type(_, ty) => matches!(
                ty,
                Type::String | Type::DynamicBytes | Type::Bytes(_) | Type::Mapping { .. }
            ),
            // User-defined types (structs, etc.) - identified by variable name
            Expression::Variable(_) => true,
            _ => false,
        }
    }

    fn is_modified_in_body(&self, param_name: &str, body: &Statement, file: &SolidityFile) -> bool {
        let mut found = Vec::new();
        let mut predicate = |expr: &Expression, _: &SolidityFile| -> Option<Loc> {
            if Self::is_assignment_to_param(param_name, expr) {
                Some(Loc::Implicit)
            } else {
                None
            }
        };
        find_locations_in_statement(body, file, &mut predicate, &mut found);
        !found.is_empty()
    }

    fn is_assignment_to_param(param_name: &str, expr: &Expression) -> bool {
        match expr {
            Expression::Assign(_, left, _)
            | Expression::AssignAdd(_, left, _)
            | Expression::AssignSubtract(_, left, _)
            | Expression::AssignMultiply(_, left, _)
            | Expression::AssignDivide(_, left, _)
            | Expression::AssignModulo(_, left, _)
            | Expression::AssignOr(_, left, _)
            | Expression::AssignAnd(_, left, _)
            | Expression::AssignXor(_, left, _)
            | Expression::AssignShiftLeft(_, left, _)
            | Expression::AssignShiftRight(_, left, _) => Self::is_param_target(param_name, left),
            _ => false,
        }
    }

    fn is_param_target(param_name: &str, expr: &Expression) -> bool {
        match expr {
            // Array index access: param[i]
            Expression::ArraySubscript(_, base, _) => {
                if let Expression::Variable(ident) = base.as_ref() {
                    ident.name == param_name
                } else {
                    Self::is_param_target(param_name, base)
                }
            }
            // Member access: param.field
            Expression::MemberAccess(_, base, _) => {
                if let Expression::Variable(ident) = base.as_ref() {
                    ident.name == param_name
                } else {
                    Self::is_param_target(param_name, base)
                }
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
    fn test_detects_unmodified_memory_params() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                event DataProcessed(uint256 value);

                function processArray(uint256[] memory data) external {
                    for (uint i = 0; i < data.length; i++) {
                        emit DataProcessed(data[i]);
                    }
                }

                function processString(string memory name) public pure returns (bytes32) {
                    return keccak256(bytes(name));
                }

                function processBytes(bytes memory payload) external pure returns (uint256) {
                    return payload.length;
                }
            }
        "#;

        let detector = Arc::new(CalldataInsteadOfMemoryDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 7, "processArray");
        assert_eq!(locations[1].line, 13, "processString");
        assert_eq!(locations[2].line, 17, "processBytes");
    }

    #[test]
    fn test_skips_valid_memory_usage() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                string public storedName;

                struct User {
                    uint256 id;
                    string name;
                }

                function modifyArray(uint256[] memory data) external pure returns (uint256[] memory) {
                    data[0] = 999;
                    return data;
                }

                function modifyStruct(User memory user) external pure returns (User memory) {
                    user.id = 123;
                    return user;
                }

                function internalProcess(uint256[] memory data) internal pure returns (uint256) {
                    return data.length;
                }

                function privateProcess(bytes memory data) private pure returns (uint256) {
                    return data.length;
                }

                constructor(string memory _name) {
                    storedName = _name;
                }

                function processValues(uint256 value, address addr, bool flag) external pure returns (uint256) {
                    return value;
                }

                function processCalldata(uint256[] calldata data) external pure returns (uint256) {
                    return data.length;
                }
            }
        "#;

        let detector = Arc::new(CalldataInsteadOfMemoryDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
