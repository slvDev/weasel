use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{FunctionAttribute, FunctionTy, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct EmptyEtherReceiverDetector;

impl Detector for EmptyEtherReceiverDetector {
    fn id(&self) -> &'static str {
        "empty-ether-receiver"
    }

    fn name(&self) -> &str {
        "Empty `receive()/payable fallback()` function does not authenticate requests"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "If the intention is for the Ether to be used, the function should call another function, \
         otherwise it should revert (e.g. require(msg.sender == address(weth))). Having no access \
         control on the function means that someone may send Ether to the contract, and have no way \
         to get anything back out, which is a loss of funds. If the concern is having to spend a \
         small amount of gas to check the sender against an immutable address, the code should at \
         least have a function to rescue unused Ether."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - empty receive function locks Ether
contract MyContract {
    receive() external payable {}
    fallback() external payable {}
}

// Good - forward to handler
contract MyContract {
    receive() external payable {
        _handleEther();
    }

    function _handleEther() internal {
        // Handle Ether
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            if !matches!(func_def.ty, FunctionTy::Fallback | FunctionTy::Receive) {
                return Vec::new();
            }

            if func_def.attributes.iter().any(|attr| matches!(attr, FunctionAttribute::Virtual(_))) {
                return Vec::new();
            }

            if Self::is_empty_body(&func_def.body) {
                return FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&func_def.loc, file),
                }
                .into();
            }

            Vec::new()
        });
    }
}

impl EmptyEtherReceiverDetector {
    fn is_empty_body(body: &Option<Statement>) -> bool {
        match body {
            None => true,
            Some(Statement::Block { statements, .. }) => statements.is_empty(),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_empty_fallback_receive() {
        let code = r#"
            contract Test {
                receive() external payable {}

                fallback() external payable {}
            }
        "#;
        let detector = Arc::new(EmptyEtherReceiverDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 3, "empty receive");
        assert_eq!(locations[1].line, 5, "empty fallback");
    }

    #[test]
    fn test_skips_non_empty_and_virtual() {
        let code = r#"
            contract Test {
                receive() external payable {
                    require(msg.sender == address(0), "Invalid sender");
                }

                fallback() external payable virtual {}

                function normalFunc() public {}
            }
        "#;
        let detector = Arc::new(EmptyEtherReceiverDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
