use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

const MAX_STRING_LENGTH: usize = 32;

#[derive(Debug, Default)]
pub struct LongRevertStringDetector;

impl Detector for LongRevertStringDetector {
    fn id(&self) -> &'static str {
        "long-revert-string"
    }

    fn name(&self) -> &str {
        "Reduce the size of error messages (Long revert Strings)"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Shortening revert strings to fit in 32 bytes will decrease deployment time gas and \
        runtime gas when the revert condition is met. Revert strings longer than 32 bytes \
        require at least one additional mstore, along with additional overhead for computing \
        memory offset. Consider shortening the revert strings to fit in 32 bytes. \
        Saves around 18 gas per instance."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - string longer than 32 bytes
require(balance > 0, "Insufficient balance to perform this operation");

// Good - string fits in 32 bytes
require(balance > 0, "Insufficient balance");
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let self_clone = self.clone();

        // Check require() calls
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(_, func_expr, args) = expr {
                if let Expression::Variable(ident) = func_expr.as_ref() {
                    if ident.name == "require" {
                        // require(condition, "message") - check second argument
                        if let Some(msg_arg) = args.get(1) {
                            if let Some(loc) = Self::get_long_string_loc(msg_arg) {
                                return FindingData {
                                    detector_id: self_clone.id(),
                                    location: loc_to_location(&loc, file),
                                }
                                .into();
                            }
                        }
                    }
                }
            }
            Vec::new()
        });

        // Check revert("message") statements
        visitor.on_statement(move |stmt, file, _context| {
            if let Statement::Revert(_, _, args) = stmt {
                // revert("message") - check first argument
                if let Some(msg_arg) = args.first() {
                    if let Some(loc) = Self::get_long_string_loc(msg_arg) {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(&loc, file),
                        }
                        .into();
                    }
                }
            }
            Vec::new()
        });
    }
}

impl LongRevertStringDetector {
    fn get_long_string_loc(expr: &Expression) -> Option<solang_parser::pt::Loc> {
        if let Expression::StringLiteral(strings) = expr {
            // Concatenate all string parts
            let total_len: usize = strings.iter().map(|s| s.string.len()).sum();
            if total_len > MAX_STRING_LENGTH {
                return strings.first().map(|s| s.loc);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_long_revert_strings() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function withdraw(uint256 amount) external {
                    require(amount > 0, "Amount must be greater than zero to withdraw");
                    require(msg.sender != address(0), "Caller address is invalid and not allowed");
                }

                function bad() external pure {
                    revert("This is a very long error message that exceeds limit");
                }
            }
        "#;

        let detector = Arc::new(LongRevertStringDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 6, "First require");
        assert_eq!(locations[1].line, 7, "Second require");
        assert_eq!(locations[2].line, 11, "revert");
    }

    #[test]
    fn test_skips_short_strings() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function good() external {
                    require(msg.sender != address(0), "Invalid sender");
                    require(amount > 0, "Amount is zero");
                    revert("Short error");
                }
            }
        "#;

        let detector = Arc::new(LongRevertStringDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
