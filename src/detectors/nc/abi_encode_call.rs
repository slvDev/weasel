use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use solang_parser::pt::Expression;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct AbiEncodeCallDetector {
    locations: Arc<Mutex<Vec<Location>>>,
}

impl Detector for AbiEncodeCallDetector {
    fn id(&self) -> &str {
        "prefer-encode-call"
    }

    fn name(&self) -> &str {
        "Prefer `abi.encodeCall` over `abi.encodeWithSignature`/`abi.encodeWithSelector`"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "When using `abi.encodeWithSignature`, it is possible to include a typo for the correct function signature. \
        When using `abi.encodeWithSignature` or `abi.encodeWithSelector`, it is also possible to provide parameters \
        that are not of the correct type for the function. To avoid these pitfalls, it would be best to use \
        `abi.encodeCall` instead. [Read more about type safety](https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3693)"
    }

    fn gas_savings(&self) -> Option<usize> {
        None
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Instead of:
bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", recipient, amount);
bytes memory otherData = abi.encodeWithSelector(IERC20.transfer.selector, recipient, amount);

// Consider using:
bytes memory data = abi.encodeCall(IERC20.transfer, (recipient, amount));
```"#
                .to_string(),
        )
    }

    fn get_locations_arc(&self) -> &Arc<Mutex<Vec<Location>>> {
        &self.locations
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_arc = self.clone();

        visitor.on_expression(move |expr, file| {
            if let Expression::FunctionCall(loc, func_expr, _args) = expr {
                if let Expression::MemberAccess(_member_loc, base_expr, member_ident) =
                    func_expr.as_ref()
                {
                    if let Expression::Variable(abi_ident) = base_expr.as_ref() {
                        if abi_ident.name == "abi" {
                            let member_name = &member_ident.name;
                            if member_name == "encodeWithSignature"
                                || member_name == "encodeWithSelector"
                            {
                                detector_arc.add_location(loc_to_location(loc, file));
                            }
                        }
                    }
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
    fn test_detects_encode_with_signature_and_selector() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function vulnerableCall() public {
                    // Positive
                    bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", recipient, amount);
                    // Positive
                    bytes memory otherData = abi.encodeWithSelector(IERC20.transfer.selector, recipient, amount);
                }

                function safeCall() public {
                    // Negative case
                    bytes memory safeData = abi.encodeCall(IERC20.transfer, (recipient, amount));

                    // Negative case - different object
                    bytes memory unrelated = recipient.call(otherContract.encodeWithSignature("foo()"));
                }
            }
        "#;

        let detector = Arc::new(AbiEncodeCallDetector::default());
        let locations = run_detector_on_code(detector, code, "encode_call_test.sol");

        assert_eq!(locations.len(), 2, "Should detect exactly two instances");

        assert_eq!(
            locations[0].line, 7,
            "Line number for encodeWithSignature should be 7"
        );
        assert_eq!(
            locations[1].line, 9,
            "Line number for encodeWithSelector should be 9"
        );

        assert!(
            locations[0]
                .snippet
                .as_deref()
                .unwrap_or("")
                .eq("abi.encodeWithSignature(\"transfer(address,uint256)\", recipient, amount)"),
            "Snippet for encodeWithSignature is incorrect"
        );
    }
}
