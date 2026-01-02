use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::get_contract_info;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::ContractTy;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct MissingGapStorageDetector;

impl Detector for MissingGapStorageDetector {
    fn id(&self) -> &'static str {
        "missing-gap-storage"
    }

    fn name(&self) -> &str {
        "Upgradeable contract missing __gap storage variable"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Upgradeable contracts should include a __gap storage variable to allow for new storage \
         variables in later versions without shifting storage slots. This protects against storage \
         collision when the contract is upgraded."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - missing __gap
contract MyUpgradeable is Initializable {
    uint256 public value;
}

// Good - has __gap for future storage
contract MyUpgradeable is Initializable {
    uint256 public value;
    uint256[49] private __gap;
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, context| {
            if matches!(
                contract_def.ty,
                ContractTy::Interface(_) | ContractTy::Library(_)
            ) {
                return Vec::new();
            }

            if !context.contract_inherits_from(contract_def, file, "Upgradeable") {
                return Vec::new();
            }

            let Some(contract_info) = get_contract_info(contract_def, file) else {
                return Vec::new();
            };

            let has_gap = contract_info
                .state_variables
                .iter()
                .any(|v| v.name == "__gap");

            if !has_gap {
                return FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&contract_def.loc, file),
                }
                .into();
            }

            Vec::new()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_with_mock_inheritance;

    #[test]
    fn test_detects_missing_gap() {
        let code = r#"
            contract MyContract is OwnableUpgradeable {
                uint256 public value;
                address public admin;
            }
        "#;
        let mock = vec![("MyContract", vec!["OwnableUpgradeable", "MyContract"])];
        let detector = Arc::new(MissingGapStorageDetector::default());
        let locations = run_detector_with_mock_inheritance(detector, code, "test.sol", mock);
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, "MyContract missing __gap");
    }

    #[test]
    fn test_skips_contracts_with_gap() {
        let code = r#"
            contract WithGap is OwnableUpgradeable {
                uint256 public value;
                uint256[49] private __gap;
            }

            contract RegularContract {
                uint256 public value;
            }
        "#;
        let mock = vec![
            ("WithGap", vec!["OwnableUpgradeable", "WithGap"]),
            ("RegularContract", vec!["RegularContract"]),
        ];
        let detector = Arc::new(MissingGapStorageDetector::default());
        let locations = run_detector_with_mock_inheritance(detector, code, "test.sol", mock);
        assert_eq!(locations.len(), 0);
    }
}
