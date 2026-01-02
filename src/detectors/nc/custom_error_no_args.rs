use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::Statement;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct CustomErrorNoArgsDetector;

impl Detector for CustomErrorNoArgsDetector {
    fn id(&self) -> &'static str {
        "custom-error-no-args"
    }

    fn name(&self) -> &str {
        "Take advantage of Custom Error's return value property"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Custom Errors can include values such as address, tokenID, or msg.value in their \
         arguments. This provides valuable debugging information in tools like Tenderly \
         when examining reverted transactions."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no useful information
error InsufficientBalance();
revert InsufficientBalance();

// Good - includes debugging values
error InsufficientBalance(address account, uint256 balance, uint256 required);
revert InsufficientBalance(msg.sender, balance, amount);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file, _context| {
            if let Statement::Revert(loc, error_path, args) = stmt {
                if error_path.is_some() && args.is_empty() {
                    return FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(loc, file),
                    }
                    .into();
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
    fn test_detects_empty_custom_errors() {
        let code = r#"
            error InsufficientBalance();
            error Unauthorized();

            contract Test {
                function bad1() public {
                    revert InsufficientBalance();
                }

                function bad2() public {
                    revert Unauthorized();
                }
            }
        "#;
        let detector = Arc::new(CustomErrorNoArgsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 7, "InsufficientBalance()");
        assert_eq!(locations[1].line, 11, "Unauthorized()");
    }

    #[test]
    fn test_skips_errors_with_args() {
        let code = r#"
            error InsufficientBalance(address account, uint256 balance);
            error Unauthorized(address caller);

            contract Test {
                function good1(uint256 balance) public {
                    revert InsufficientBalance(msg.sender, balance);
                }

                function good2() public {
                    revert Unauthorized(msg.sender);
                }

                function good3() public {
                    revert("Simple message");
                }

                function good4() public {
                    revert();
                }
            }
        "#;
        let detector = Arc::new(CustomErrorNoArgsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
