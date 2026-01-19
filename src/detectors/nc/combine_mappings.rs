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
        "nc-combine-mappings"
    }

    fn name(&self) -> &str {
        "Multiple mappings with same key can be combined into a struct"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Multiple mappings with the same key type can be combined into a single mapping to a \
         struct for better code organization and readability. This makes it easier to understand \
         related data and maintain the contract."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - separate mappings
mapping(address => uint256) balances;
mapping(address => bool) isActive;

// Good - combined into struct
struct UserData {
    uint256 balance;
    bool isActive;
}
mapping(address => UserData) users;
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
            for locs in mappings_by_key.into_values() {
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
    fn test_detects_issue() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                mapping(address => bool) foo;       // Line 5
                mapping(address => uint256) bar;    // Line 6
                mapping(uint256 => uint256) baz;    // different key - OK
            }
        "#;
        let detector = Arc::new(CombineMappingsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 address mappings");
        assert_eq!(locations[0].line, 5, "foo mapping");
        assert_eq!(locations[1].line, 6, "bar mapping");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                mapping(address => uint256) balances;   // only one address mapping
                mapping(uint256 => bool) flags;         // only one uint256 mapping
            }
        "#;
        let detector = Arc::new(CombineMappingsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Single mappings per key should not be flagged");
    }
}
