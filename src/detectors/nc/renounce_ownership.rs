use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Base, ContractPart, ContractTy};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct RenounceOwnershipDetector;

fn is_ownable_inheritance(base: &Base) -> bool {
    base.name
        .identifiers
        .iter()
        .any(|ident| ident.name == "Ownable" || ident.name == "Ownable2Step")
}

impl Detector for RenounceOwnershipDetector {
    fn id(&self) -> &'static str {
        "renounce-ownership-risk"
    }

    fn name(&self) -> &str {
        "Consider Disabling `renounceOwnership()`"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Leaving `renounceOwnership()` enabled on Ownable/Ownable2Step contracts without a specific plan to use it introduces risk. If renouncing ownership is not intended, consider overriding the function to disable it (e.g., by reverting)."
    }


    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Recommended
contract MySaferContract is Ownable {
    // Override and disable the function
    function renounceOwnership() public virtual override onlyOwner {
        revert("Renouncing ownership is disabled for this contract");
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file| {
            if matches!(contract_def.ty, ContractTy::Interface(_)) {
                return Vec::new();
            }

            let mut inherits_ownable = false;
            let mut loc = contract_def.loc.clone();

            for base in &contract_def.base {
                if is_ownable_inheritance(base) {
                    inherits_ownable = true;
                    loc.use_end_from(&base.loc);
                    break;
                }
            }

            if !inherits_ownable {
                return Vec::new();
            }

            let mut defines_renounce_ownership = false;
            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    if let Some(name_ident) = &func_def.name {
                        if name_ident.name == "renounceOwnership" {
                            defines_renounce_ownership = true;
                            break;
                        }
                    }
                }
            }

            if inherits_ownable && !defines_renounce_ownership {
                return FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&loc, file),
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
    use crate::utils::test_utils::run_detector_on_code;
    use std::sync::Arc;

    #[test]
    fn test_renounce_ownership_detector() {
        let code_positive = r#"
            pragma solidity ^0.8.0;
            import "@openzeppelin/contracts/access/Ownable.sol";

            // Positive: Inherits Ownable, no override
            contract VulnerableContract is IVulnerableContract, Ownable {
                uint256 public constant MAX_SUPPLY = 1000000000000000000000000;
            }

            // Positive: Inherits Ownable2Step, no override
            contract VulnerableContract2 is Ownable2Step {}
        "#;
        let detector = Arc::new(RenounceOwnershipDetector::default());
        let locations = run_detector_on_code(detector, code_positive, "positive.sol");
        assert_eq!(
            locations.len(),
            2,
            "Should detect 2 contracts missing override"
        );
        assert_eq!(locations[0].line, 6);
        assert_eq!(locations[1].line, 11);

        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("contract VulnerableContract is IVulnerableContract, Ownable"),
            "Snippet for first assert is incorrect"
        );
        assert!(locations[1]
            .snippet
            .as_deref()
            .unwrap_or("")
            .eq("contract VulnerableContract2 is Ownable2Step"),);

        let code_negative = r#"
            pragma solidity ^0.8.10;
            import "@openzeppelin/contracts/access/Ownable.sol";

            // Negative: Inherits Ownable, overrides renounceOwnership
            contract SafeContract is Ownable {
                function renounceOwnership() public virtual override onlyOwner {
                    revert("Disabled");
                }
            }

             // Negative: Does not inherit Ownable
            contract NonOwnableContract {}

            // Negative: Interface inheriting Ownable (should be ignored)
            interface IOwnableContract is Ownable {}

        "#;
        let detector = Arc::new(RenounceOwnershipDetector::default());
        let locations = run_detector_on_code(detector, code_negative, "negative.sol");
        assert_eq!(
            locations.len(),
            0,
            "Should detect 0 violations for safe/ignored patterns"
        );
    }
}
