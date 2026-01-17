use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, VariableAttribute, Visibility};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ArrayRangedGetterDetector;

impl Detector for ArrayRangedGetterDetector {
    fn id(&self) -> &'static str {
        "array-ranged-getter"
    }

    fn name(&self) -> &str {
        "Consider providing a ranged getter for array state variables"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "While the compiler automatically provides a getter for accessing single elements within \
         a public state variable array, it doesn't provide a way to fetch the whole array, or \
         subsets thereof. Consider adding a function to allow the fetching of slices of the array, \
         especially if the contract doesn't already have multicall functionality."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Current - only single element access
address[] public addresses;
// addresses(0) returns first element only

// Recommended - add ranged getter
function getAddresses(uint256 start, uint256 end) external view returns (address[] memory) {
    address[] memory result = new address[](end - start);
    for (uint256 i = start; i < end; i++) {
        result[i - start] = addresses[i];
    }
    return result;
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_variable(move |var_def, file, _context| {
            // Check if it's an array type
            if !matches!(var_def.ty, Expression::ArraySubscript(_, _, _)) {
                return Vec::new();
            }

            // Check if it's public
            let is_public = var_def
                .attrs
                .iter()
                .any(|attr| matches!(attr, VariableAttribute::Visibility(Visibility::Public(_))));

            if !is_public {
                return Vec::new();
            }

            FindingData {
                detector_id: self.id(),
                location: loc_to_location(&var_def.loc, file),
            }
            .into()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_issue() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                address[] public addresses;              // Line 5 - public array
                uint256[] public amounts;                // Line 6 - public array
            }
        "#;
        let detector = Arc::new(ArrayRangedGetterDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 issues");
        assert_eq!(locations[0].line, 5, "addresses array");
        assert_eq!(locations[1].line, 6, "amounts array");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                address[] private privateAddresses;      // Private array - OK
                address[] internal internalAddresses;    // Internal array - OK
                address[] addresses;                     // Default (internal) - OK
                uint256 public singleValue;              // Not an array - OK
                mapping(address => uint) public balances; // Mapping - OK
            }
        "#;
        let detector = Arc::new(ArrayRangedGetterDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
