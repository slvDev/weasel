use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct EcrecoverMalleabilityDetector;

impl Detector for EcrecoverMalleabilityDetector {
    fn id(&self) -> &'static str {
        "ecrecover-malleability"
    }

    fn name(&self) -> &str {
        "Use of `ecrecover` is susceptible to signature malleability"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "The built-in EVM precompile `ecrecover` is susceptible to signature malleability, \
         which could lead to replay attacks. References: https://swcregistry.io/docs/SWC-117, \
         https://swcregistry.io/docs/SWC-121, and \
         https://medium.com/cryptronics/signature-replay-vulnerabilities-in-smart-contracts-3b6f7596df57. \
         While this is not immediately exploitable, this may become a vulnerability if used elsewhere."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - direct use of ecrecover (susceptible to malleability)
function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s, address signer) public pure returns (bool) {
    return ecrecover(hash, v, r, s) == signer;
}

// Good - use OpenZeppelin's ECDSA library (handles malleability)
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

function verify(bytes32 hash, bytes memory signature, address signer) public pure returns (bool) {
    return ECDSA.recover(hash, signature) == signer;
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func_expr, _args) = expr {
                if let Expression::Variable(identifier) = func_expr.as_ref() {
                    if identifier.name == "ecrecover" {
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
    fn test_detects_ecrecover_usage() {
        let code = r#"
            contract Test {
                function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
                    return ecrecover(hash, v, r, s);
                }
            }
        "#;
        let detector = Arc::new(EcrecoverMalleabilityDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 4, "ecrecover call");
    }

    #[test]
    fn test_skips_when_no_ecrecover() {
        let code = r#"
            import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

            contract Test {
                using ECDSA for bytes32;

                function verifyWithECDSA(bytes32 hash, bytes memory signature, address signer) public pure returns (bool) {
                    // Good - uses OpenZeppelin's ECDSA library
                    return hash.recover(signature) == signer;
                }

                function verifyWithCustom(bytes32 hash, address signer) public pure returns (bool) {
                    // Some other verification logic
                    return keccak256(abi.encodePacked(hash)) == keccak256(abi.encodePacked(signer));
                }
            }
        "#;
        let detector = Arc::new(EcrecoverMalleabilityDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
