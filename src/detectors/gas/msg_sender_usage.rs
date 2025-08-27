use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::FindingData;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use solang_parser::pt::Expression;
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
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func_expr, args) = expr {
                // Check if it's a simple identifier call to _msgSender with no arguments
                if let Expression::Variable(identifier) = func_expr.as_ref() {
                    if identifier.name == "_msgSender" && args.is_empty() {
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
    use std::sync::Arc;

    #[test]
    fn test_msg_sender_usage_detection() {
        let code = r#"
            pragma solidity ^0.8.0;
            import "@openzeppelin/contracts/utils/Context.sol";
            
            contract Test is Context {
                address public owner;
                
                function transferOwnership() public {
                    address sender = _msgSender();  // Should detect
                    owner = sender;
                }
                
                function checkSender() public view returns (bool) {
                    return _msgSender() == owner;  // Should detect
                }
                
                function complexCall() public {
                    if (_msgSender() != address(0)) {  // Should detect
                        owner = _msgSender();  // Should detect
                    }
                }
                
                function goodPractice() public {
                    address sender = msg.sender;  // Should NOT detect
                    owner = sender;
                }
            }
        "#;

        let detector = Arc::new(MsgSenderUsageDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4, "Should detect 4 _msgSender() calls");

        // Check specific detections (adjusting for actual line numbers)
        assert_eq!(
            locations[0].line, 9,
            "Should detect _msgSender() in assignment"
        );
        assert_eq!(
            locations[1].line, 14,
            "Should detect _msgSender() in comparison"
        );
        assert_eq!(
            locations[2].line, 18,
            "Should detect _msgSender() in condition"
        );
        assert_eq!(
            locations[3].line, 19,
            "Should detect _msgSender() in assignment"
        );
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
                    // This should NOT be detected as it has arguments (not the OpenZeppelin _msgSender)
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
