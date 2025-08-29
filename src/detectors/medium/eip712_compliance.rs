use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::{ast_utils, location::loc_to_location};
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct Eip712ComplianceDetector;

impl Detector for Eip712ComplianceDetector {
    fn id(&self) -> &'static str {
        "eip712-compliance"
    }

    fn name(&self) -> &str {
        "Lack of EIP-712 compliance: using keccak256() directly on an array or struct variable"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "Directly using the actual variable instead of encoding the array values goes against the EIP-712 specification. \
        Arrays and structs should be encoded properly before hashing. Using keccak256 directly on complex types can lead to \
        signature collisions and doesn't follow the EIP-712 standard for structured data hashing."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - direct hashing of struct/array:
bytes32 hash = keccak256(myStruct);
bytes32 hash2 = keccak256(myArray);
bytes32 hash3 = keccak256(mapping[key]);

// Good - properly encode before hashing:
bytes32 hash = keccak256(abi.encode(
    myStruct.field1,
    myStruct.field2
));

bytes32 hash2 = keccak256(abi.encodePacked(arrayValues));
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func_expr, args) = expr {
                // Check if this is a keccak256 call
                if !self.is_keccak256_call(func_expr) {
                    return Vec::new();
                }
                
                // Check each argument for complex types
                for arg in args {
                    // Skip if it's already encoded with abi.encode/encodePacked
                    if self.is_abi_encoded(arg) {
                        continue;
                    }
                    
                    // First check structural patterns (definite complex types)
                    if ast_utils::is_complex_type_structure(arg) {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(&loc, file),
                        }
                        .into();
                    }
                    
                    // Then check heuristics for likely complex types (variables)
                    if self.is_likely_complex_variable(arg) {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(&loc, file),
                        }
                        .into();
                    }
                }
            }
            Vec::new()
        });
    }
}

impl Eip712ComplianceDetector {
    fn is_keccak256_call(&self, expr: &Expression) -> bool {
        match expr {
            Expression::Variable(var) => var.name == "keccak256",
            Expression::MemberAccess(_, _, member) => member.name == "keccak256",
            _ => false,
        }
    }
    
    fn is_abi_encoded(&self, expr: &Expression) -> bool {
        // Check if expression is a call to abi.encode or abi.encodePacked
        if let Expression::FunctionCall(_, func, _) = expr {
            if let Expression::MemberAccess(_, base, member) = func.as_ref() {
                if let Expression::Variable(var) = base.as_ref() {
                    // abi.encode, abi.encodePacked are properly encoded
                    if var.name == "abi" && (member.name == "encode" || member.name == "encodePacked") {
                        return true;
                    }
                }
            }
        }
        false
    }
    
    fn is_likely_complex_variable(&self, expr: &Expression) -> bool {
        // Simple heuristics for variable names that likely represent complex types
        if let Expression::Variable(var) = expr {
            let name_lower = var.name.to_lowercase();
            // Common patterns for arrays/structs/mappings
            return name_lower.ends_with("s") && !name_lower.ends_with("ss") || // plural
                   name_lower.contains("array") ||
                   name_lower.contains("list") ||
                   name_lower.contains("data") ||
                   name_lower.contains("struct") ||
                   name_lower.contains("order") ||
                   name_lower.contains("record");
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_eip712_compliance() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract TestEIP712 {
                struct Order {
                    address user;
                    uint256 amount;
                }
                
                Order[] public orders;
                mapping(address => Order) public userOrders;
                uint256[] public amounts;
                
                function badHash1() public view returns (bytes32) {
                    Order memory order = orders[0];
                    return keccak256(order); // Should detect - struct
                }
                
                function badHash2() public view returns (bytes32) {
                    return keccak256(orders); // Should detect - array
                }
                
                function badHash3() public view returns (bytes32) {
                    return keccak256(amounts); // Should detect - array
                }
                
                function badHash4() public view returns (bytes32) {
                    return keccak256(userOrders[msg.sender]); // Should detect - mapping access
                }
                
                function badHash5() public view returns (bytes32) {
                    uint256[] memory data = amounts;
                    return keccak256(data); // Should detect - array variable
                }
                
                function goodHash1() public view returns (bytes32) {
                    Order memory order = orders[0];
                    return keccak256(abi.encode(order.user, order.amount)); // Good - properly encoded
                }
                
                function goodHash2() public pure returns (bytes32) {
                    return keccak256(abi.encodePacked("test")); // Good - encoded
                }
                
                function goodHash3() public pure returns (bytes32) {
                    uint256 simple = 123;
                    return keccak256(simple); // Good - simple type
                }
            }
        "#;

        let detector = Arc::new(Eip712ComplianceDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 5, "Should detect 5 violations");
        assert_eq!(locations[0].line, 16, "badHash1 - struct");
        assert_eq!(locations[1].line, 20, "badHash2 - array");
        assert_eq!(locations[2].line, 24, "badHash3 - array");
        assert_eq!(locations[3].line, 28, "badHash4 - mapping");
        assert_eq!(locations[4].line, 33, "badHash5 - array variable");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract Test {
                function test() public pure {
                    // Should NOT detect - simple types
                    bytes32 h1 = keccak256(abi.encode(1, 2, 3));
                    bytes32 h2 = keccak256(abi.encodePacked("hello"));
                    bytes32 h3 = keccak256("direct string");
                    
                    uint256 num = 42;
                    bytes32 h4 = keccak256(num);
                    
                    address addr = address(0);
                    bytes32 h5 = keccak256(addr);
                }
            }
        "#;

        let detector = Arc::new(Eip712ComplianceDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0, "Should not detect any violations");
    }
}