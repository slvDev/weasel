use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::FindingData;
use crate::models::severity::Severity;
use crate::utils::ast_utils;
use solang_parser::pt::{ContractPart, Expression, Loc};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct MsgSenderUsageDetector;

impl Detector for MsgSenderUsageDetector {
    fn id(&self) -> &'static str {
        "msg-sender-usage"
    }

    fn name(&self) -> &str {
        "Avoid Using `_msgSender()` if not Supporting EIP-2771"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "From a gas efficiency perspective, using `_msgSender()` in a contract not intended to support EIP-2771 \
        could add unnecessary overhead. The _msgSender() function includes checks to determine if the transaction \
        was forwarded, which involves extra function calls that consume more gas than a simple msg.sender. \
        If a contract doesn't require EIP-2771 meta-transaction support, using msg.sender directly is more gas efficient."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"
```solidity
// Instead of:
function transfer() public {
    address sender = _msgSender();  // Extra overhead for EIP-2771 support
    // ...
}

// Use:
function transfer() public {
    address sender = msg.sender;  // Direct access, more gas efficient
    // ...
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        // Use contract callback to know which contract we're analyzing
        visitor.on_contract(move |contract_def, file, context| {
            // Skip if contract inherits from Context or meta-transaction related contracts
            // These contracts legitimately need _msgSender() for EIP-2771 support
            if context.contract_inherits_from(contract_def, file, "Context")
                || context.contract_inherits_from(contract_def, file, "BaseRelayRecipient")
                || context.contract_inherits_from(contract_def, file, "ERC2771Context")
                || context.contract_inherits_from(contract_def, file, "GSNRecipient")
            {
                // Contract intentionally supports meta-transactions, skip detection
                return Vec::new();
            }

            // Now search for _msgSender() usage in this contract
            let mut findings = Vec::new();

            // Define predicate to find _msgSender() calls
            let mut is_msg_sender_call = |expr: &Expression, _: &_| -> Option<Loc> {
                if let Expression::FunctionCall(loc, func_expr, args) = expr {
                    if let Expression::Variable(identifier) = func_expr.as_ref() {
                        if identifier.name == "_msgSender" && args.is_empty() {
                            return Some(loc.clone());
                        }
                    }
                }
                None
            };

            // Search through all contract parts for _msgSender() usage
            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func) = part {
                    // This catches both functions AND modifiers (both are FunctionDefinition in AST)
                    if let Some(body) = &func.body {
                        ast_utils::find_locations_in_statement(
                            body,
                            file,
                            &mut is_msg_sender_call,
                            &mut findings,
                        );
                    }
                }
            }

            // Convert findings to FindingData
            findings
                .into_iter()
                .map(|location| FindingData {
                    detector_id: self.id(),
                    location,
                })
                .collect()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{run_detector_on_code, run_detector_with_mock_inheritance};
    use std::sync::Arc;

    #[test]
    fn test_msg_sender_usage_detection_without_context() {
        // Minimal test - only what's needed to verify detection logic
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract Test {
                address owner;
                
                function foo() public {
                    _msgSender();
                }
                
                function bar() public {
                    if (_msgSender() != address(0)) {
                        _msgSender();
                    }
                }
                
                modifier onlyOwner() {
                    require(_msgSender() == owner);
                    _;
                }
                
                function baz() public {
                    msg.sender;  // Good practice - direct access
                }
            }
        "#;

        let detector = Arc::new(MsgSenderUsageDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4, "Should detect 4 _msgSender() calls");

        // Verify exact line numbers
        assert_eq!(locations[0].line, 8, "First in foo()");
        assert_eq!(locations[1].line, 12, "Second in bar() condition");
        assert_eq!(locations[2].line, 13, "Third in bar() body");
        assert_eq!(locations[3].line, 18, "Fourth in modifier");
    }

    #[test]
    fn test_no_detection_with_context_inheritance() {
        // Test contracts that DO inherit from Context - should NOT detect
        let code = r#"
            pragma solidity ^0.8.0;
            
            // Stub Context contract
            abstract contract Context {
                function _msgSender() internal view virtual returns (address) {
                    return msg.sender;
                }
            }
            
            contract TestWithContext is Context {
                address public owner;
                
                function transferOwnership() public {
                    address sender = _msgSender();  // Should NOT detect - inherits Context
                    owner = sender;
                }
                
                function checkSender() public view returns (bool) {
                    return _msgSender() == owner;  // Should NOT detect
                }
            }
            
            contract AnotherContract {
                // Contract without Context inheritance
                address public owner;
                
                function usesMsgSender() public {
                    address sender = _msgSender();  // Should detect - no inheritance
                    owner = sender;
                }
            }
        "#;

        let detector = Arc::new(MsgSenderUsageDetector::default());

        // Use mock inheritance to properly set up inheritance chains
        let mock_contracts = vec![
            ("Context", vec!["Context"]),
            ("TestWithContext", vec!["Context", "TestWithContext"]),
            ("AnotherContract", vec!["AnotherContract"]),
        ];

        let locations =
            run_detector_with_mock_inheritance(detector, code, "test.sol", mock_contracts);

        // Should only detect in AnotherContract, not in TestWithContext
        assert_eq!(
            locations.len(),
            1,
            "Should only detect 1 _msgSender() call in AnotherContract"
        );
        assert_eq!(
            locations[0].line, 29,
            "Detection should be in AnotherContract"
        );
    }

    #[test]
    fn test_detection_with_meta_transaction_contracts() {
        // Test with various meta-transaction related base contracts
        let code = r#"
            pragma solidity ^0.8.0;
            
            abstract contract BaseRelayRecipient {
                function _msgSender() internal view virtual returns (address);
            }
            
            abstract contract ERC2771Context {
                function _msgSender() internal view virtual returns (address);
            }
            
            contract TestWithBaseRelay is BaseRelayRecipient {
                function test() public {
                    _msgSender();  // Should NOT detect - meta-tx support
                }
            }
            
            contract TestWithERC2771 is ERC2771Context {
                function test() public {
                    _msgSender();  // Should NOT detect - meta-tx support
                }
            }
            
            contract TestPlain {
                function test() public {
                    _msgSender();  // Should detect - no meta-tx support
                }
            }
        "#;

        let detector = Arc::new(MsgSenderUsageDetector::default());

        let mock_contracts = vec![
            ("BaseRelayRecipient", vec!["BaseRelayRecipient"]),
            ("ERC2771Context", vec!["ERC2771Context"]),
            (
                "TestWithBaseRelay",
                vec!["BaseRelayRecipient", "TestWithBaseRelay"],
            ),
            ("TestWithERC2771", vec!["ERC2771Context", "TestWithERC2771"]),
            ("TestPlain", vec!["TestPlain"]),
        ];

        let locations =
            run_detector_with_mock_inheritance(detector, code, "test.sol", mock_contracts);

        assert_eq!(locations.len(), 1, "Should only detect in TestPlain");
        assert_eq!(locations[0].line, 26, "Detection should be in TestPlain");
    }

    #[test]
    fn test_modifier_detection() {
        // Minimal test proving modifiers are detected
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract Test {
                modifier check() {
                    _msgSender();
                    _;
                }
                
                function foo() public check {
                    // No _msgSender() here
                }
            }
        "#;

        let detector = Arc::new(MsgSenderUsageDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 1, "Should detect in modifier");
        assert_eq!(locations[0].line, 6, "Detection in modifier");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract Test {
                address public owner;
                
                function goodPractice() public {
                    address sender = msg.sender;  // Should NOT detect
                    owner = sender;
                }
                
                function otherFunction() public {
                    // Some other function call that's not _msgSender
                    owner = address(0);
                }
                
                function callOtherMsgFunction() public {
                    // This should not match since it's not exactly _msgSender
                    someOtherMsgFunction();
                    // This should NOT be detected as it has arguments
                    someFunction("_msgSender", 123);
                }
            }
        "#;

        let detector = Arc::new(MsgSenderUsageDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            0,
            "Should not detect any issues in good code"
        );
    }
}
