use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::ContractTy;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct RenounceOwnershipDetector;

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
        visitor.on_contract(move |contract_def, file, context| {
            // Skip interfaces
            if matches!(contract_def.ty, ContractTy::Interface(_)) {
                return Vec::new();
            }

            if !context.contract_inherits_from(contract_def, file, "Ownable") {
                return Vec::new();
            }

            // Check if THIS contract defines/overrides renounceOwnership
            let defines_renounce_ownership =
                context.contract_defines_function(contract_def, file, "renounceOwnership");

            // Flag if inherits Ownable but doesn't override renounceOwnership
            if !defines_renounce_ownership {
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
    use std::sync::Arc;

    #[test]
    fn test_renounce_ownership_detector() {
        // Simplified test - just declare contracts that inherit from Ownable
        let code_positive = r#"
            pragma solidity ^0.8.0;
            
            // Stub Ownable with renounceOwnership defined
            contract Ownable {
                function renounceOwnership() public {}
            }
            contract Ownable2Step is Ownable {}
            
            interface IVulnerableContract {
                function someFunction() external;
            }

            // Positive: Inherits Ownable, no override
            contract VulnerableContract is IVulnerableContract, Ownable {
                uint256 public constant MAX_SUPPLY = 1000000000000000000000000;
            }

            // Positive: Inherits Ownable2Step, no override
            contract VulnerableContract2 is Ownable2Step {}
        "#;
        let detector = Arc::new(RenounceOwnershipDetector::default());

        // Use the mock inheritance helper to inject proper inheritance chains
        let mock_contracts = vec![
            ("Ownable", vec!["Ownable"]),
            ("Ownable2Step", vec!["Ownable", "Ownable2Step"]),
            ("VulnerableContract", vec!["Ownable", "VulnerableContract"]),
            (
                "VulnerableContract2",
                vec!["Ownable", "Ownable2Step", "VulnerableContract2"],
            ),
        ];

        let locations = run_detector_with_mock_inheritance(
            detector,
            code_positive,
            "positive.sol",
            mock_contracts,
        );

        // Should detect 3 violations: VulnerableContract, VulnerableContract2, and Ownable2Step
        assert_eq!(
            locations.len(),
            3,
            "Should detect 3 contracts missing override: VulnerableContract, VulnerableContract2, and Ownable2Step"
        );

        let code_negative = r#"
            pragma solidity ^0.8.10;
            
            // Stub Ownable with renounceOwnership defined
            contract Ownable {
                function renounceOwnership() public {}
            }

            // Negative: Inherits Ownable, overrides renounceOwnership
            contract SafeContract is Ownable {
                function renounceOwnership() public virtual onlyOwner {
                    revert("Disabled");
                }
            }

            // Negative: Does not inherit Ownable
            contract NonOwnableContract {
                uint256 public value;
            }

            // Negative: Interface (should be ignored)
            interface IOwnableContract {
                function someFunction() external;
            }
        "#;
        let detector = Arc::new(RenounceOwnershipDetector::default());

        // Mock inheritance for SafeContract only
        let mock_contracts = vec![
            ("Ownable", vec!["Ownable"]),
            ("SafeContract", vec!["Ownable", "SafeContract"]),
        ];

        let locations = run_detector_with_mock_inheritance(
            detector,
            code_negative,
            "negative.sol",
            mock_contracts,
        );

        assert_eq!(
            locations.len(),
            0,
            "Should detect 0 violations for safe/ignored patterns"
        );
    }
}
