use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::ContractTy;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct TwoStepOwnershipTransferDetector;

impl Detector for TwoStepOwnershipTransferDetector {
    fn id(&self) -> &'static str {
        "two-step-ownership-transfer"
    }

    fn name(&self) -> &str {
        "Use a 2-Step Ownership Transfer Pattern"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Recommend implementing a two step process where the owner nominates an account \
         and the nominated account needs to call an `acceptOwnership()` function for the \
         transfer of ownership to fully succeed. This ensures the nominated EOA account \
         is a valid and active account. Consider using Ownable2Step instead of Ownable."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - single-step ownership transfer
import "@openzeppelin/contracts/access/Ownable.sol";

contract MyContract is Ownable {
    // Risk: typo in newOwner address = permanent loss of control
}

// Good - two-step ownership transfer
import "@openzeppelin/contracts/access/Ownable2Step.sol";

contract MyContract is Ownable2Step {
    // Safer: new owner must call acceptOwnership()
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, context| {
            // Skip interfaces and libraries
            if !matches!(contract_def.ty, ContractTy::Contract(_)) {
                return Vec::new();
            }

            // Get contract name
            let contract_name = match contract_def.name.as_ref() {
                Some(name) => name.name.as_str(),
                None => return Vec::new(),
            };

            // Skip the base Ownable contracts themselves (library contracts)
            if contract_name == "Ownable" || contract_name.starts_with("Ownable2") {
                return Vec::new();
            }

            // Check if inherits from Ownable
            if !context.contract_inherits_from(contract_def, file, "Ownable") {
                return Vec::new();
            }

            // Skip if inherits from Ownable2Step or Ownable2
            if context.contract_inherits_from(contract_def, file, "Ownable2") {
                return Vec::new();
            }

            // Flag: inherits from Ownable but not Ownable2
            FindingData {
                detector_id: self.id(),
                location: loc_to_location(&contract_def.loc, file),
            }
            .into()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_with_mock_inheritance;

    #[test]
    fn test_detects_single_step_ownable() {
        let code = r#"
            contract Ownable {}

            // Should detect: inherits Ownable (not Ownable2)
            contract MyContract is Ownable {
                uint256 public value;
            }
        "#;
        let detector = Arc::new(TwoStepOwnershipTransferDetector::default());
        let mock = vec![
            ("Ownable", vec!["Ownable"]),
            ("MyContract", vec!["Ownable", "MyContract"]),
        ];
        let locations = run_detector_with_mock_inheritance(detector, code, "test.sol", mock);
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 5, "MyContract is Ownable");
    }

    #[test]
    fn test_skips_two_step_ownable() {
        let code = r#"
            contract Ownable {}
            contract Ownable2Step is Ownable {}

            // Should NOT detect: uses Ownable2Step
            contract MyContract is Ownable2Step {
                uint256 public value;
            }

            // Should NOT detect: no ownership
            contract NoOwnership {
                uint256 public value;
            }
        "#;
        let detector = Arc::new(TwoStepOwnershipTransferDetector::default());
        let mock = vec![
            ("Ownable", vec!["Ownable"]),
            ("Ownable2Step", vec!["Ownable", "Ownable2Step"]),
            ("MyContract", vec!["Ownable", "Ownable2Step", "MyContract"]),
        ];
        let locations = run_detector_with_mock_inheritance(detector, code, "test.sol", mock);
        assert_eq!(locations.len(), 0);
    }
}
