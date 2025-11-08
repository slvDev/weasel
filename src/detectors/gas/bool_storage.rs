use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{ContractPart, Expression, Type};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct BoolStorageDetector;

impl Detector for BoolStorageDetector {
    fn id(&self) -> &'static str {
        "bool-storage"
    }

    fn name(&self) -> &str {
        "Using bools for storage incurs overhead"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Use uint256(1) and uint256(2) for true/false to avoid a Gwarmaccess (100 gas), and to avoid Gsset (20000 gas) when changing from 'false' to 'true', after having been 'true' in the past."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Less efficient - bool storage
bool public isActive;
mapping(address => bool) public hasVoted;

// More efficient - uint256 storage
uint256 public isActive; // 1 for true, 2 for false
mapping(address => uint256) public hasVoted;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract_part(move |part, file, _context| {
            if let ContractPart::VariableDefinition(var) = part {
                // Check if it's a bool type or contains bool
                if let Expression::Type(_, ty) = &var.ty {
                    if self.has_bool(ty) {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(&var.loc, file),
                        }
                        .into();
                    }
                }
            }
            Vec::new()
        });
    }
}

impl BoolStorageDetector {
    fn has_bool(&self, ty: &Type) -> bool {
        match ty {
            Type::Bool => true,
            Type::Mapping { value, .. } => {
                // Check if mapping value is bool
                if let Expression::Type(_, inner_ty) = value.as_ref() {
                    self.has_bool(inner_ty)
                } else {
                    false
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
    fn test_bool_storage() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract BoolStorage {
                bool public isActive;  // Should detect
                bool private hasStarted;  // Should detect
                mapping(address => bool) public hasVoted;  // Should detect
                mapping(uint256 => mapping(address => bool)) public nestedBool;  // Should detect
                
                uint256 public counter;  // Should not detect
                address public owner;  // Should not detect
                
                function test() public {
                    bool localBool = true;  // Should not detect (local variable)
                }
            }
        "#;

        let detector = Arc::new(BoolStorageDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4, "Should detect 4 bool storage variables");
        assert_eq!(locations[0].line, 5);  // isActive
        assert_eq!(locations[1].line, 6);  // hasStarted
        assert_eq!(locations[2].line, 7);  // hasVoted
        assert_eq!(locations[3].line, 8);  // nestedBool
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract NoBoolStorage {
                uint256 public value;
                address public admin;
                mapping(address => uint256) public balances;
                
                function process(bool flag) public pure returns (bool) {
                    bool result = flag;  // Local variables OK
                    return result;
                }
            }
        "#;

        let detector = Arc::new(BoolStorageDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0, "Should not detect any bool storage");
    }
}