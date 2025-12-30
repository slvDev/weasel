use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{FunctionAttribute, FunctionTy, Mutability};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct FallbackLackingPayableDetector;

impl Detector for FallbackLackingPayableDetector {
    fn id(&self) -> &'static str {
        "fallback-lacking-payable"
    }

    fn name(&self) -> &str {
        "Fallback lacking `payable`"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Fallback functions without the `payable` modifier cannot receive Ether sent directly \
         to the contract. If the fallback function is intended to receive Ether, add the `payable` \
         modifier. If not receiving Ether is intentional, consider adding a comment to document \
         this design decision."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - fallback cannot receive Ether
fallback() external {
    // Will revert if Ether is sent
}

// Good - fallback can receive Ether
fallback() external payable {
    // Can receive Ether
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            if !matches!(func_def.ty, FunctionTy::Fallback) {
                return Vec::new();
            }

            let is_payable = func_def.attributes.iter().any(|attr| {
                matches!(attr, FunctionAttribute::Mutability(Mutability::Payable(_)))
            });

            if !is_payable {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_fallback_without_payable() {
        let code = r#"
            contract Test {
                fallback() external {
                    // Cannot receive Ether
                }
            }
        "#;
        let detector = Arc::new(FallbackLackingPayableDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 3, "fallback without payable");
    }

    #[test]
    fn test_skips_payable_fallback() {
        let code = r#"
            contract Test {
                fallback() external payable {
                    // Can receive Ether
                }

                receive() external payable {
                    // receive is always payable
                }
            }
        "#;
        let detector = Arc::new(FallbackLackingPayableDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
