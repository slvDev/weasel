use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::get_contract_info;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::ContractTy;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UninitializedUpgradeableDetector;

impl Detector for UninitializedUpgradeableDetector {
    fn id(&self) -> &'static str {
        "uninitialized-upgradeable"
    }

    fn name(&self) -> &str {
        "Upgradeable contract not initialized"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Upgradeable contracts are initialized via an initializer function rather than by a \
         constructor. Leaving such a contract uninitialized may lead to it being taken over \
         by a malicious user."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no initializer function
contract MyUpgradeable is Initializable {
    uint256 public value;
}

// Good - has initializer
contract MyUpgradeable is Initializable {
    uint256 public value;

    function initialize(uint256 _value) external initializer {
        value = _value;
    }
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

            let has_initializer = contract_info.function_definitions.iter().any(|f| {
                let name = f.name.to_lowercase();
                name == "initialize" || name == "init" || name.contains("_init")
            });

            if !has_initializer {
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
    fn test_detects_uninitialized_upgradeable() {
        let code = r#"
            contract MyContract is OwnableUpgradeable {
                uint256 public value;
                address public admin;
            }
        "#;
        let mock = vec![("MyContract", vec!["OwnableUpgradeable", "MyContract"])];
        let detector = Arc::new(UninitializedUpgradeableDetector::default());
        let locations = run_detector_with_mock_inheritance(detector, code, "test.sol", mock);
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 2, "MyContract missing initializer");
    }

    #[test]
    fn test_skips_initialized_contracts() {
        let code = r#"
            contract WithInitialize is OwnableUpgradeable {
                uint256 public value;

                function initialize(uint256 _value) external {
                    value = _value;
                }
            }

            contract WithInit is OwnableUpgradeable {
                uint256 public value;

                function __MyContract_init() internal {
                    value = 100;
                }
            }

            contract RegularContract {
                uint256 public value;
            }
        "#;
        let mock = vec![
            (
                "WithInitialize",
                vec!["OwnableUpgradeable", "WithInitialize"],
            ),
            ("WithInit", vec!["OwnableUpgradeable", "WithInit"]),
            ("RegularContract", vec!["RegularContract"]),
        ];
        let detector = Arc::new(UninitializedUpgradeableDetector::default());
        let locations = run_detector_with_mock_inheritance(detector, code, "test.sol", mock);
        assert_eq!(locations.len(), 0);
    }
}
