use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use solang_parser::{
    helpers::OptionalCodeLocation,
    pt::{Expression, Loc, Type},
};
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct TwoStepCriticalChangesDetector {
    locations: Arc<Mutex<Vec<Location>>>,
}

const DANGEROUS_PREFIXES: [&str; 4] = ["set", "change", "update", "transfer"];
const CRITICAL_ROLE_NAMES: [&str; 4] = ["owner", "admin", "governor", "guardian"];

impl Detector for TwoStepCriticalChangesDetector {
    fn id(&self) -> &str {
        "two-step-critical-changes"
    }

    fn name(&self) -> &str {
        "Critical Changes Should Use Two-step Procedure"
    }

    fn severity(&self) -> Severity {
        Severity::NC // Can be Low/Medium depending on context, but NC is safe baseline
    }

    fn description(&self) -> &str {
        "Functions that change critical addresses like owner or admin in a single step are prone to errors (e.g., setting the wrong address). Consider implementing a two-step process (e.g., propose/accept) for safer changes."
    }

    fn gas_savings(&self) -> Option<usize> {
        None
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Potentially problematic:
function setOwner(address _newOwner) external onlyOwner { ... }
function transferAdmin(address _newAdmin) external onlyAdmin { ... }

// Recommended (Two-Step):
address public pendingOwner;

function proposeOwner(address _newOwner) external onlyOwner {
    pendingOwner = _newOwner;
}

function acceptOwner() external {
    require(msg.sender == pendingOwner, "Not proposed owner");
    owner = pendingOwner;
    delete pendingOwner;
}
```"#
                .to_string(),
        )
    }

    fn get_locations_arc(&self) -> &Arc<Mutex<Vec<Location>>> {
        &self.locations
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_arc = self.clone();

        visitor.on_function(move |func_def, file| {
            if let Some(name_ident) = &func_def.name {
                let func_name = name_ident.name.to_lowercase();

                let has_dangerous_prefix = DANGEROUS_PREFIXES
                    .iter()
                    .any(|prefix| func_name.starts_with(prefix));

                if !has_dangerous_prefix {
                    return;
                }

                let mut found_critical_param = false;
                for (_, param_opt) in &func_def.params {
                    if let Some(param) = param_opt {
                        match &param.ty {
                            Expression::Type(_, Type::Address)
                            | Expression::Type(_, Type::AddressPayable) => {
                                if let Some(param_name_ident) = &param.name {
                                    let param_name = param_name_ident.name.to_lowercase();
                                    if CRITICAL_ROLE_NAMES
                                        .iter()
                                        .any(|role| param_name.contains(role))
                                    {
                                        found_critical_param = true;
                                        break;
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }

                if found_critical_param {
                    let body_loc = func_def.body.loc_opt().unwrap_or(func_def.loc);
                    let issue_loc = Loc::default()
                        .with_start(func_def.loc.start())
                        .with_end(body_loc.start());
                    detector_arc.add_location(loc_to_location(&issue_loc, file));
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;
    use std::sync::Arc;

    #[test]
    fn test_two_step_critical_changes_detector() {
        let code_positive = r#"
            pragma solidity ^0.8.0;
            contract Test {
                address owner;
                address admin;

                function setOwner(address _newOwner) public {} // Positive
                function changeAdmin(address _newAdmin) public {} // Positive
                function updateGuardian(address _newGuardian) public {} // Positive
                function transferOwnership(address _newOwner) public {} // Positive
                function setSomethingElse(uint _val) public {} // Negative
                function proposeOwner(address _newOwner) public {} // Negative
                function setAdminRole(address _admin, bool _flag) public {} // Positive
            }
        "#;
        let detector = Arc::new(TwoStepCriticalChangesDetector::default());
        let locations = run_detector_on_code(detector, code_positive, "positive.sol");
        assert_eq!(
            locations.len(),
            5,
            "Should detect 5 potential single-step changes"
        );
        assert_eq!(locations[0].line, 7); // setOwner
        assert_eq!(locations[1].line, 8); // changeAdmin
        assert_eq!(locations[2].line, 9); // updateGuardian
        assert_eq!(locations[3].line, 10); // transferOwnership
        assert_eq!(locations[4].line, 13); // setAdminRole

        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("function setOwner(address _newOwner) public"),
            "Snippet for first assert is incorrect"
        );

        let code_negative = r#"
            pragma solidity ^0.8.10;
            contract Test {
                address owner;
                address admin;
                address pendingOwner;

                function getOwner() public view returns (address) { return owner; }
                function setMetadata(string memory _uri) public {}
                function initiateOwnerChange(address _propose) public {}
                function proposeOwner(address _newOwner) public {
                    pendingOwner = _newOwner;
                }
                function acceptOwner() public {
                   require(msg.sender == pendingOwner);
                   owner = pendingOwner;
                }
                function transferFunds(address _to, uint _amount) public {}
                function transfer(address _to, uint _amount) public {}
            }
        "#;
        let detector = Arc::new(TwoStepCriticalChangesDetector::default());
        let locations = run_detector_on_code(detector, code_negative, "negative.sol");
        assert_eq!(
            locations.len(),
            0,
            "Should detect 0 violations for safe patterns"
        );
    }
}
