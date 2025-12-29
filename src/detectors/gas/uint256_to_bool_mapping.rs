use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::helpers::CodeLocation;
use solang_parser::pt::{Expression, Type};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct Uint256ToBoolMappingDetector;

impl Detector for Uint256ToBoolMappingDetector {
    fn id(&self) -> &'static str {
        "uint256-to-bool-mapping"
    }

    fn name(&self) -> &str {
        "Uint256 to Bool Mapping"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Detects `mapping(uint256 => bool)` which can be optimized using bitmaps. \
         BitMaps pack 256 booleans across each bit of a single 256-bit slot, \
         resulting in gas savings by setting zero to non-zero only once every 256 times \
         and accessing the same warm slot for every 256 sequential indices. \
         See: https://soliditydeveloper.com/bitmaps and OpenZeppelin's BitMaps library."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - uses more gas for sequential indices
mapping(uint256 => bool) public claimed;

// Good - use OpenZeppelin's BitMaps library
import "@openzeppelin/contracts/utils/structs/BitMaps.sol";

using BitMaps for BitMaps.BitMap;
BitMaps.BitMap private claimedBitmap;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_variable(move |var, file, _context| {
            if Self::is_uint256_to_bool_mapping(&var.ty) {
                return vec![FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&var.ty.loc(), file),
                }];
            }
            Vec::new()
        });
    }
}

impl Uint256ToBoolMappingDetector {
    /// Check if the type expression represents `mapping(uint256 => bool)`
    fn is_uint256_to_bool_mapping(ty: &Expression) -> bool {
        if let Expression::Type(_, Type::Mapping { key, value, .. }) = ty {
            // Check if key is uint256
            let is_uint256_key = matches!(
                key.as_ref(),
                Expression::Type(_, Type::Uint(256))
            );

            // Check if value is bool (not another mapping)
            let is_bool_value = matches!(
                value.as_ref(),
                Expression::Type(_, Type::Bool)
            );

            is_uint256_key && is_bool_value
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_uint256_to_bool_mapping() {
        let code = r#"
            contract Test {
                mapping(uint256 => bool) public claimed;
                mapping(uint256 => bool) private processed;
            }
        "#;
        let detector = Arc::new(Uint256ToBoolMappingDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 3, "mapping(uint256 => bool) public claimed");
        assert_eq!(locations[1].line, 4, "mapping(uint256 => bool) private processed");
    }

    #[test]
    fn test_skips_other_mappings() {
        let code = r#"
            contract Test {
                mapping(address => bool) public whitelist;
                mapping(uint256 => address) public owners;
                mapping(uint256 => mapping(address => bool)) public approvals;
            }
        "#;
        let detector = Arc::new(Uint256ToBoolMappingDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
