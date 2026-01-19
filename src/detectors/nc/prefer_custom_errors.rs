use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use solang_parser::pt::{ContractPart, Expression};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct PreferCustomErrorsDetector;

impl Detector for PreferCustomErrorsDetector {
    fn id(&self) -> &'static str {
        "prefer-custom-errors"
    }

    fn name(&self) -> &str {
        "Use custom errors instead of require()/assert()"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Starting from Solidity 0.8.4, custom errors provide better readability and clarity. \
         Using custom errors instead of require()/assert() improves code quality and provides \
         more expressive error conditions."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - using require/assert
require(balance >= amount, "Insufficient");
assert(value > 0);

// Good - using custom errors
error InsufficientBalance();
if (balance < amount) revert InsufficientBalance();
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            let mut findings = Vec::new();

            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    if let Some(body) = &func_def.body {
                        let calls = find_in_statement(body, file, self.id(), |expr| {
                            if let Expression::FunctionCall(_, func_expr, _) = expr {
                                if let Expression::Variable(id) = func_expr.as_ref() {
                                    return id.name == "require" || id.name == "assert";
                                }
                            }
                            false
                        });
                        findings.extend(calls);
                    }
                }
            }

            findings
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_issue() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(uint256 fee) public {
                    require(fee > 0);                           // Line 6
                    assert(fee < 1000);                         // Line 7
                }
            }
        "#;
        let detector = Arc::new(PreferCustomErrorsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect require and assert");
        assert_eq!(locations[0].line, 6, "require");
        assert_eq!(locations[1].line, 7, "assert");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.4;

            error InvalidFee();

            contract Test {
                function test(uint256 fee) public {
                    if (fee == 0) revert InvalidFee();  // custom error - OK
                }
            }
        "#;
        let detector = Arc::new(PreferCustomErrorsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Custom errors should not be flagged");
    }
}
