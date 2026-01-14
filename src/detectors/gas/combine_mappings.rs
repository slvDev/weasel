use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::scope::TypeInfo;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::ast_utils::get_contract_info;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct CombineMappingsDetector;

impl Detector for CombineMappingsDetector {
    fn id(&self) -> &'static str {
        "combine-mappings"
    }

    fn name(&self) -> &str {
        "Multiple mappings with same key can be combined into a struct"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Combining multiple address/ID mappings into a single mapping to a struct can save gas. \
        By refactoring multiple mappings into a singular mapping with a struct, you can save on \
        storage slots, which reduces gas cost in certain operations."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - multiple mappings with same key
mapping(address => uint256) public balances;
mapping(address => bool) public isActive;
mapping(address => uint256) public lastUpdate;

// Good - combined into struct
struct UserData {
    uint256 balance;
    bool isActive;
    uint256 lastUpdate;
}
mapping(address => UserData) public users;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            let Some(contract_info) = get_contract_info(contract_def, file) else {
                return Vec::new();
            };

            // Group mappings by their key type
            let mut mappings_by_key: HashMap<String, Vec<Location>> = HashMap::new();

            for var in &contract_info.state_variables {
                if let TypeInfo::Mapping { key, .. } = &var.type_info {
                    let key_str = format!("{}", key);
                    mappings_by_key
                        .entry(key_str)
                        .or_default()
                        .push(var.loc.clone());
                }
            }

            // Report findings for groups with 2+ mappings
            let mut findings = Vec::new();
            for (_, locs) in mappings_by_key {
                if locs.len() > 1 {
                    for loc in locs {
                        findings.push(FindingData {
                            detector_id: self.id(),
                            location: loc,
                        });
                    }
                }
            }

            findings
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_combinable_mappings() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                mapping(address => bool) foo;
                mapping(address => uint256) bar;
                mapping(uint256 => bool) baz;
            }
        "#;

        let detector = Arc::new(CombineMappingsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        // foo and bar have same key (address), baz has different key
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 5, "mapping(address => bool) foo");
        assert_eq!(locations[1].line, 6, "mapping(address => uint256) bar");
    }

    #[test]
    fn test_skips_single_mappings() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                mapping(address => bool) foo;
                mapping(uint256 => bool) bar;
                mapping(bytes32 => bool) baz;
            }
        "#;

        let detector = Arc::new(CombineMappingsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
