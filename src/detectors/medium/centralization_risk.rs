use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{FunctionAttribute, FunctionDefinition};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct CentralizationRiskDetector;

// Common access control modifiers that indicate centralization
const PRIVILEGED_MODIFIERS: [&str; 20] = [
    "onlyowner",      // onlyOwner - OpenZeppelin Ownable
    "onlyadmin",      // onlyAdmin - General admin pattern
    "onlygovernor",   // onlyGovernor - Governance contracts
    "onlyguardian",   // onlyGuardian - Guardian pattern
    "onlyoperator",   // onlyOperator - Operator pattern
    "onlycontroller", // onlyController - Controller pattern
    "onlymanager",    // onlyManager - Manager pattern
    "onlyminter",     // onlyMinter - Minting privileges
    "onlypauser",     // onlyPauser - Pause functionality
    "onlyrole",       // onlyRole - OpenZeppelin AccessControl
    "onlytimelock",   // onlyTimelock - Compound-style timelock
    "onlymultisig",   // onlyMultisig - Multi-signature
    "onlykeeper",     // onlyKeeper - Automation protocols
    "onlystrategist", // onlyStrategist - Yield strategies
    "onlyvault",      // onlyVault - Vault protocols
    "onlybridge",     // onlyBridge - Bridge protocols
    "onlyvalidator",  // onlyValidator - Validation protocols
    "authorized",     // authorized - General authorization
    "requiresauth",   // requiresAuth - Auth requirement
    "hasrole",        // hasRole - OpenZeppelin AccessControl
];

impl Detector for CentralizationRiskDetector {
    fn id(&self) -> &'static str {
        "centralization-risk"
    }

    fn name(&self) -> &str {
        "Centralization Risk for trusted owners"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "Functions with privileged access control modifiers introduce centralization risk. \
        These functions can only be called by specific addresses (owners, admins, etc.) and require trust \
        that these privileged users won't perform malicious actions like draining funds, pausing the protocol, \
        or making harmful parameter changes. Consider implementing timelocks, multi-signatures, or decentralized governance."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Centralization risks:
function pause() external onlyOwner { }  // Can pause protocol
function withdraw() external onlyAdmin { }  // Can drain funds
function setFee(uint256 _fee) external onlyGovernor { }  // Can change params

// Mitigations:
// - Use timelocks for critical changes
// - Implement multi-signature requirements
// - Add decentralized governance
// - Document admin capabilities clearly
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            if self.has_privileged_modifier(func_def) {
                // Report finding at the function signature location
                let loc = if let Some(name) = &func_def.name {
                    name.loc
                } else {
                    func_def.loc
                };
                
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

impl CentralizationRiskDetector {
    fn has_privileged_modifier(&self, func_def: &FunctionDefinition) -> bool {
        // Check attributes for modifier names
        for attr in &func_def.attributes {
            if let FunctionAttribute::BaseOrModifier(_, base) = attr {
                // Get the modifier name from the identifier path
                let modifier_name = base.name.identifiers
                    .last()
                    .map(|id| id.name.to_lowercase())
                    .unwrap_or_default();
                
                // Check if modifier matches any privileged pattern
                for pattern in PRIVILEGED_MODIFIERS {
                    if modifier_name.contains(pattern) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_centralization_risk_detection() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract TestContract {
                address owner;
                mapping(address => bool) admins;
                
                modifier onlyOwner() {
                    require(msg.sender == owner);
                    _;
                }
                
                modifier onlyAdmin() {
                    require(admins[msg.sender]);
                    _;
                }
                
                modifier onlyRole(bytes32 role) {
                    // role check
                    _;
                }
                
                function pause() external onlyOwner {  // Should detect
                    // pause logic
                }
                
                function withdraw(uint amount) external onlyAdmin {  // Should detect
                    // withdraw logic
                }
                
                function setFee(uint fee) external onlyRole(GOVERNOR_ROLE) {  // Should detect
                    // set fee
                }
                
                function upgrade() external onlyOwner onlyAdmin {  // Should detect (has onlyOwner)
                    // upgrade
                }
                
                // Regular functions - should NOT detect
                function deposit() external {
                    // no modifier
                }
                
                function balanceOf() external view returns (uint) {
                    return 0;
                }
            }
        "#;

        let detector = Arc::new(CentralizationRiskDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4, "Should detect 4 functions with privileged modifiers");
        
        // Check detection lines (function names)
        assert_eq!(locations[0].line, 23, "pause function");
        assert_eq!(locations[1].line, 27, "withdraw function");
        assert_eq!(locations[2].line, 31, "setFee function");
        assert_eq!(locations[3].line, 35, "upgrade function");
    }

    #[test]
    fn test_various_modifiers() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract TestContract {
                modifier onlyGovernor() { _; }
                modifier onlyGuardian() { _; }
                modifier onlyOperator() { _; }
                modifier onlyController() { _; }
                modifier onlyMinter() { _; }
                modifier authorized() { _; }
                modifier requiresAuth() { _; }
                modifier onlyTimelock() { _; }
                modifier onlyMultisig() { _; }
                modifier hasRole(bytes32) { _; }
                modifier notPrivileged() { _; }  // Should NOT match
                
                function test1() external onlyGovernor { }  // Should detect
                function test2() external onlyGuardian { }  // Should detect
                function test3() external onlyOperator { }  // Should detect
                function test4() external onlyController { }  // Should detect
                function test5() external onlyMinter { }  // Should detect
                function test6() external authorized { }  // Should detect
                function test7() external requiresAuth { }  // Should detect
                function test8() external onlyTimelock { }  // Should detect
                function test9() external onlyMultisig { }  // Should detect
                function test10() external hasRole(ADMIN_ROLE) { }  // Should detect
                function test11() external notPrivileged { }  // Should NOT detect
                function test12() external { }  // Should NOT detect
            }
        "#;

        let detector = Arc::new(CentralizationRiskDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 10, "Should detect 10 functions with privileged modifiers");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract TestContract {
                modifier onlyAfter(uint time) { _; }
                modifier onlyIf(bool condition) { _; }
                modifier nonReentrant() { _; }
                modifier whenNotPaused() { _; }
                
                // None of these should trigger
                function test1() external onlyAfter(block.timestamp) { }
                function test2() external onlyIf(true) { }
                function test3() external nonReentrant { }
                function test4() external whenNotPaused { }
                function test5() public pure { }
                function test6() internal { }
                function test7() private { }
            }
        "#;

        let detector = Arc::new(CentralizationRiskDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            0,
            "Should not detect any false positives"
        );
    }
}