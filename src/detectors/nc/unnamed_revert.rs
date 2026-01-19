use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_statement_types;
use solang_parser::pt::{ContractPart, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnnamedRevertDetector;

impl Detector for UnnamedRevertDetector {
    fn id(&self) -> &'static str {
        "unnamed-revert"
    }

    fn name(&self) -> &str {
        "Prefer custom errors over unnamed revert()"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Using custom error types with revert() provides clearer, more informative error handling. \
         Custom errors, introduced in Solidity 0.8.4, allow you to define specific error conditions \
         with descriptive names and optionally include additional data."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - unnamed revert
revert();
revert("Insufficient balance");

// Good - named custom errors
error InsufficientBalance();
revert InsufficientBalance();
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
                        let reverts = find_statement_types(body, file, self.id(), |stmt| {
                            matches!(stmt, Statement::Revert(_, None, _))
                        });
                        findings.extend(reverts);
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
                function test() public {
                    revert();                               // Line 6 - unnamed
                    if (true) revert("Not true");           // Line 7 - unnamed
                    revert CustomError();                   // named - OK
                    revert CustomErrorWithParam("param");   // named - OK
                }
            }
        "#;
        let detector = Arc::new(UnnamedRevertDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 unnamed reverts");
        assert_eq!(locations[0].line, 6, "first revert()");
        assert_eq!(locations[1].line, 7, "second revert()");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.4;

            error InsufficientBalance();
            error InvalidAmount(uint256 amount);

            contract Test {
                function test(uint256 amount) public {
                    if (amount == 0) revert InsufficientBalance();
                    revert InvalidAmount(amount);
                }
            }
        "#;
        let detector = Arc::new(UnnamedRevertDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(
            locations.len(),
            0,
            "Named custom errors should not be flagged"
        );
    }
}
