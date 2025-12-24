use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct AvoidContractExistenceChecksDetector;

impl Detector for AvoidContractExistenceChecksDetector {
    fn id(&self) -> &'static str {
        "avoid-contract-existence-checks"
    }

    fn name(&self) -> &str {
        "Avoid contract existence checks by using low level calls"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Prior to 0.8.10 the compiler inserted extra code, including EXTCODESIZE (100 gas), \
        to check for contract existence for external function calls. In more recent Solidity \
        versions, the compiler will not insert these checks if the external call has a return \
        value. Similar behavior can be achieved in earlier versions by using low-level calls, \
        since low level calls never check for contract existence."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Gas-intensive - compiler adds EXTCODESIZE check
uint256 balance = token.balanceOf(user);

// More efficient in older Solidity versions - no existence check
(bool success, bytes memory data) = address(token).staticcall(
    abi.encodeWithSignature("balanceOf(address)", user)
);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func_expr, _) = expr {
                if let Expression::MemberAccess(_, _, member) = func_expr.as_ref() {
                    let name = member.name.as_str();
                    if name == "delegatecall" || name == "balanceOf" || name == "recover" {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(loc, file),
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
    fn test_detects_existence_check_calls() {
        let code = r#"
            pragma solidity ^0.8.0;

            interface IERC20 {
                function balanceOf(address) external view returns (uint256);
            }

            interface ECDSA {
                function recover(bytes32, bytes memory) external pure returns (address);
            }

            contract Test {
                function checkBalance(IERC20 token, address user) external view returns (uint256) {
                    return token.balanceOf(user);
                }

                function recoverSigner(ECDSA lib, bytes32 hash, bytes memory sig) external pure returns (address) {
                    return lib.recover(hash, sig);
                }

                function delegate(address target, bytes memory data) external returns (bytes memory) {
                    (bool success, bytes memory result) = target.delegatecall(data);
                    require(success);
                    return result;
                }
            }
        "#;

        let detector = Arc::new(AvoidContractExistenceChecksDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 14, "balanceOf");
        assert_eq!(locations[1].line, 18, "recover");
        assert_eq!(locations[2].line, 22, "delegatecall");
    }

    #[test]
    fn test_skips_other_calls() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function transfer(address to, uint256 amount) external {}
                function approve(address spender, uint256 amount) external {}

                function doTransfer(address token) external {
                    Test(token).transfer(msg.sender, 100);
                    Test(token).approve(msg.sender, 100);
                }

                function lowLevel(address target, bytes memory data) external {
                    (bool success, ) = target.call(data);
                    require(success);
                }
            }
        "#;

        let detector = Arc::new(AvoidContractExistenceChecksDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
