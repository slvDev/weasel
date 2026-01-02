use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct MissingErrorMessageDetector;

impl Detector for MissingErrorMessageDetector {
    fn id(&self) -> &'static str {
        "missing-error-message"
    }

    fn name(&self) -> &str {
        "`require()` / `revert()` statements should have descriptive reason strings"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Adding descriptive error messages to `require()` and `revert()` statements helps with \
         debugging and provides better user experience when transactions fail."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
require(amount > 0);
revert();

// Good
require(amount > 0, "Amount must be positive");
revert("Operation failed");
revert InsufficientBalance();
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let self_clone = Arc::clone(&self);

        visitor.on_statement(move |stmt, file, _context| {
            if let Statement::Revert(loc, error_path, args) = stmt {
                if error_path.is_some() {
                    return Vec::new();
                }

                if args.is_empty() {
                    return FindingData {
                        detector_id: self_clone.id(),
                        location: loc_to_location(loc, file),
                    }
                    .into();
                }

                if let Some(Expression::StringLiteral(strs)) = args.first() {
                    let msg: String = strs.iter().map(|s| s.string.as_str()).collect();
                    if msg.len() < 6 {
                        return FindingData {
                            detector_id: self_clone.id(),
                            location: loc_to_location(loc, file),
                        }
                        .into();
                    }
                }
            }
            Vec::new()
        });

        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func, args) = expr {
                if let Expression::Variable(id) = func.as_ref() {
                    if id.name == "require" {
                        if args.len() == 1 {
                            return FindingData {
                                detector_id: self.id(),
                                location: loc_to_location(loc, file),
                            }
                            .into();
                        }

                        if let Some(Expression::StringLiteral(strs)) = args.get(1) {
                            let msg: String = strs.iter().map(|s| s.string.as_str()).collect();
                            if msg.len() < 6 {
                                return FindingData {
                                    detector_id: self.id(),
                                    location: loc_to_location(loc, file),
                                }
                                .into();
                            }
                        }
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
    fn test_detects_missing_or_short_messages() {
        let code = r#"
            contract Test {
                function bad1(uint256 amount) public {
                    require(amount > 0);
                }

                function bad2() public {
                    revert();
                }

                function bad3(bool ok) public {
                    require(ok, "err");
                    revert("bad");
                }
            }
        "#;
        let detector = Arc::new(MissingErrorMessageDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].line, 4, "require without message");
        assert_eq!(locations[1].line, 8, "revert without message");
        assert_eq!(locations[2].line, 12, "require with short message");
        assert_eq!(locations[3].line, 13, "revert with short message");
    }

    #[test]
    fn test_skips_with_proper_messages() {
        let code = r#"
            error InsufficientBalance();

            contract Test {
                function good1(uint256 amount) public {
                    require(amount > 0, "Amount must be positive");
                }

                function good2() public {
                    revert("Operation failed");
                }

                function good3() public {
                    revert InsufficientBalance();
                }
            }
        "#;
        let detector = Arc::new(MissingErrorMessageDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
