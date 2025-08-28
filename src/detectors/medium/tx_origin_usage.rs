use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct TxOriginUsageDetector;

impl Detector for TxOriginUsageDetector {
    fn id(&self) -> &'static str {
        "tx-origin-usage"
    }

    fn name(&self) -> &str {
        "Use of `tx.origin` is unsafe"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "Using `tx.origin` for authorization is vulnerable to phishing attacks and may break with future Ethereum upgrades. \
        According to Vitalik Buterin, contracts should not assume that `tx.origin` will continue to be usable or meaningful. \
        Use `msg.sender` for authorization checks instead. If you need the original transaction sender for logging or \
        non-critical purposes, document why `tx.origin` is necessary and ensure it's not used for authorization."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
function withdraw() public {
    require(tx.origin == owner);  // Vulnerable to phishing
    // ...
}

// Good
function withdraw() public {
    require(msg.sender == owner);  // Checks direct caller
    // ...
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::MemberAccess(loc, base_expr, member) = expr {
                if let Expression::Variable(var) = base_expr.as_ref() {
                    if var.name == "tx" && member.name == "origin" {
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
    fn test_tx_origin_usage_detection() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract TestContract {
                address owner;
                
                modifier onlyOwner() {
                    require(tx.origin == owner);  // Should detect
                    _;
                }
                
                function withdraw() public {
                    if (tx.origin != owner) {  // Should detect
                        revert();
                    }
                    payable(tx.origin).transfer(1 ether);  // Should detect
                }
                
                function logCaller() public {
                    emit CallerLogged(tx.origin);  // Should detect (even for logging)
                }
                
                function goodPractice() public {
                    require(msg.sender == owner);  // Should NOT detect
                    address sender = msg.sender;  // Should NOT detect
                }
            }
        "#;

        let detector = Arc::new(TxOriginUsageDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4, "Should detect 4 uses of tx.origin");
        
        // Check line numbers
        assert_eq!(locations[0].line, 8, "First detection in modifier");
        assert_eq!(locations[1].line, 13, "Second detection in if condition");
        assert_eq!(locations[2].line, 16, "Third detection in transfer");
        assert_eq!(locations[3].line, 20, "Fourth detection in emit");
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract TestContract {
                address owner;
                address origin;  // Variable named origin
                
                function test() public {
                    require(msg.sender == owner);  // Good
                    address sender = msg.sender;  // Good
                    
                    // These should NOT trigger
                    origin = msg.sender;  // Just a variable named origin
                    uint tx = 5;  // Variable named tx
                    
                    // tx as a local variable, not the global tx
                    TxData memory tx;
                    address myOrigin = getOrigin();  // Function call
                }
                
                function getOrigin() internal returns (address) {
                    return msg.sender;  // Not tx.origin
                }
                
                struct TxData {
                    address origin;  // Struct field
                }
            }
        "#;

        let detector = Arc::new(TxOriginUsageDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            0,
            "Should not detect any false positives"
        );
    }
}