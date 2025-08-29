use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DirectSupportsInterfaceDetector;

impl Detector for DirectSupportsInterfaceDetector {
    fn id(&self) -> &'static str {
        "direct-supports-interface"
    }

    fn name(&self) -> &str {
        "Direct supportsInterface() calls may cause caller to revert"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "Calling supportsInterface() on a contract that doesn't implement the ERC-165 standard will \
        result in the call reverting. Even if the caller does support the function, the contract may \
        be malicious and consume all of the transaction's available gas. Call it via a low-level \
        staticcall() with a fixed amount of gas, and check the return code, or use OpenZeppelin's \
        ERC165Checker.supportsInterface()."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - direct call can revert or consume all gas
if (token.supportsInterface(interfaceId)) {
    // ...
}

// Good - using OpenZeppelin's ERC165Checker
using ERC165Checker for address;
if (address(token).supportsInterface(interfaceId)) {
    // ...
}

// Good - using low-level staticcall with gas limit
(bool success, bytes memory result) = address(token).staticcall{gas: 30000}(
    abi.encodeWithSelector(IERC165.supportsInterface.selector, interfaceId)
);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func, _) = expr {
                if let Expression::MemberAccess(_, _, member) = func.as_ref() {
                    if member.name == "supportsInterface" {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(&loc, file),
                        }
                        .into();
                    }
                }
            }
            
            Vec::new()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_direct_supports_interface() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            interface IERC165 {
                function supportsInterface(bytes4 interfaceId) external view returns (bool);
            }
            
            contract TokenChecker {
                function badCheck1(address token, bytes4 interfaceId) public view returns (bool) {
                    // Bad - direct call
                    return IERC165(token).supportsInterface(interfaceId);
                }
                
                function badCheck2(IERC165 token, bytes4 interfaceId) public view {
                    // Bad - direct call in if statement
                    if (token.supportsInterface(interfaceId)) {
                        // do something
                    }
                }
                
                function badCheck3(IERC165 token, bytes4 interfaceId) public view returns (bool) {
                    // Bad - direct call in conditional
                    bool supported = token.supportsInterface(interfaceId) && true;
                    return supported;
                }
                
                function goodCheck(address token, bytes4 interfaceId) public view returns (bool) {
                    // Good - using staticcall (simulated)
                    (bool success, bytes memory result) = token.staticcall(
                        abi.encodeWithSelector(IERC165.supportsInterface.selector, interfaceId)
                    );
                    return success && abi.decode(result, (bool));
                }
            }
        "#;

        let detector = Arc::new(DirectSupportsInterfaceDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3, "Should detect 3 direct supportsInterface calls");
        assert_eq!(locations[0].line, 11, "First direct call");
        assert_eq!(locations[1].line, 16, "Second direct call in if");
        assert_eq!(locations[2].line, 23, "Third direct call in conditional");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract NoInterfaceChecks {
                function someFunction() public pure returns (uint256) {
                    uint256 value = 100;
                    return value;
                }
                
                function otherFunction(address target) public {
                    // Using staticcall but not for supportsInterface
                    (bool success, ) = target.staticcall("");
                    require(success, "Call failed");
                }
            }
        "#;

        let detector = Arc::new(DirectSupportsInterfaceDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}