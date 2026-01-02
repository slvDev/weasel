use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::ContractTy;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct RenounceWhilePausedDetector;

impl Detector for RenounceWhilePausedDetector {
    fn id(&self) -> &'static str {
        "renounce-while-paused"
    }

    fn name(&self) -> &str {
        "Owner can renounce while system is paused"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "The contract owner is not prevented from renouncing ownership while the contract is paused. \
         If the owner renounces while paused, any user assets stored in the protocol could be locked \
         indefinitely since there would be no owner to unpause. Consider overriding `renounceOwnership()` \
         to check that the contract is not paused before allowing renunciation."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - can renounce while paused
contract Vulnerable is Ownable, Pausable {
    // Uses default renounceOwnership from Ownable
}

// Good - prevents renouncing while paused
contract Safe is Ownable, Pausable {
    function renounceOwnership() public override onlyOwner {
        require(!paused(), "Cannot renounce while paused");
        super.renounceOwnership();
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

            if !context.contract_inherits_from(contract_def, file, "Ownable") {
                return Vec::new();
            }

            let has_pausable = context.contract_inherits_from(contract_def, file, "Pausable")
                || context.contract_defines_function(contract_def, file, "pause")
                || context.contract_defines_function(contract_def, file, "_pause");

            if !has_pausable {
                return Vec::new();
            }

            if context.contract_defines_function(contract_def, file, "renounceOwnership") {
                return Vec::new();
            }

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
    fn test_detects_renounce_while_paused() {
        let code = r#"
            contract Ownable {
                function renounceOwnership() public {}
            }
            contract Pausable {
                function pause() public {}
            }

            contract Vulnerable is Ownable, Pausable {
                uint256 public value;
            }

            contract CustomPausable is Ownable {
                function pause() public {}
            }
        "#;

        let detector = Arc::new(RenounceWhilePausedDetector::default());
        let mock_contracts = vec![
            ("Ownable", vec!["Ownable"]),
            ("Pausable", vec!["Pausable"]),
            ("Vulnerable", vec!["Ownable", "Pausable", "Vulnerable"]),
            ("CustomPausable", vec!["Ownable", "CustomPausable"]),
        ];

        let locations =
            run_detector_with_mock_inheritance(detector, code, "test.sol", mock_contracts);

        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 9, "Vulnerable is Ownable, Pausable");
        assert_eq!(locations[1].line, 13, "CustomPausable with pause()");
    }

    #[test]
    fn test_skips_safe_contracts() {
        let code = r#"
            contract Ownable {
                function renounceOwnership() public {}
            }
            contract Pausable {
                function pause() public {}
            }

            contract SafeContract is Ownable, Pausable {
                function renounceOwnership() public override {}
            }

            contract OnlyOwnable is Ownable {
                uint256 public value;
            }

            contract OnlyPausable is Pausable {
                uint256 public value;
            }

            contract PlainContract {
                uint256 public value;
            }

            interface IContract {
                function test() external;
            }
        "#;

        let detector = Arc::new(RenounceWhilePausedDetector::default());
        let mock_contracts = vec![
            ("Ownable", vec!["Ownable"]),
            ("Pausable", vec!["Pausable"]),
            ("SafeContract", vec!["Ownable", "Pausable", "SafeContract"]),
            ("OnlyOwnable", vec!["Ownable", "OnlyOwnable"]),
            ("OnlyPausable", vec!["Pausable", "OnlyPausable"]),
        ];

        let locations =
            run_detector_with_mock_inheritance(detector, code, "test.sol", mock_contracts);

        assert_eq!(locations.len(), 0);
    }
}
