use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{FunctionAttribute, Mutability};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct PayableFunctionDetector;

impl Detector for PayableFunctionDetector {
    fn id(&self) -> &'static str {
        "payable-function"
    }

    fn name(&self) -> &str {
        "Functions with access control can be marked `payable`"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "If a function modifier such as `onlyOwner` is used, the function will revert if a \
        normal user tries to pay the function. Marking the function as `payable` will lower \
        the gas cost for legitimate callers because the compiler will not include checks for \
        whether a payment was provided."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - not payable
function withdraw() external onlyOwner {
    // ...
}

// Good - marked payable
function withdraw() external payable onlyOwner {
    // ...
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            let has_only_modifier = func_def.attributes.iter().any(|attr| {
                if let FunctionAttribute::BaseOrModifier(_, base) = attr {
                    if let Some(ident) = base.name.identifiers.first() {
                        return ident.name.starts_with("only");
                    }
                }
                false
            });

            if !has_only_modifier {
                return Vec::new();
            }

            let is_payable = func_def.attributes.iter().any(|attr| {
                matches!(attr, FunctionAttribute::Mutability(Mutability::Payable(_)))
            });

            if is_payable {
                return Vec::new();
            }

            FindingData {
                detector_id: self.id(),
                location: loc_to_location(&func_def.loc, file),
            }
            .into()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_non_payable_with_modifier() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                address public owner;

                modifier onlyOwner() {
                    require(msg.sender == owner);
                    _;
                }

                modifier onlyAdmin() {
                    require(msg.sender == owner);
                    _;
                }

                function withdraw() external onlyOwner {
                }

                function setFee(uint256 fee) external onlyAdmin {
                }

                function emergencyStop() public onlyOwner {
                }
            }
        "#;

        let detector = Arc::new(PayableFunctionDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 17, "withdraw");
        assert_eq!(locations[1].line, 20, "setFee");
        assert_eq!(locations[2].line, 23, "emergencyStop");
    }

    #[test]
    fn test_skips_payable_and_no_modifier() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                address public owner;

                modifier onlyOwner() {
                    require(msg.sender == owner);
                    _;
                }

                function withdraw() external payable onlyOwner {
                }

                function publicFunction() external {
                }

                function deposit() external payable {
                }
            }
        "#;

        let detector = Arc::new(PayableFunctionDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
