use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::ast_utils::find_in_statement;
use solang_parser::pt::{ContractPart, Expression};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DuplicateStringLiteralDetector;

impl Detector for DuplicateStringLiteralDetector {
    fn id(&self) -> &'static str {
        "duplicate-string-literal"
    }

    fn name(&self) -> &str {
        "Consider moving duplicated strings to constants"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Reusing string literals in this manner can lead to inconsistencies and makes the code \
         harder to maintain. It's recommended to define such strings as constants, which promotes \
         easier updates and ensures uniformity across the codebase."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - duplicated string literals
require(condition1, "Insufficient balance");
require(condition2, "Insufficient balance");

// Good - use a constant
string private constant INSUFFICIENT_BALANCE = "Insufficient balance";
require(condition1, INSUFFICIENT_BALANCE);
require(condition2, INSUFFICIENT_BALANCE);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            // Collect all string literal findings grouped by their snippet (content)
            let mut strings_by_value: HashMap<String, Vec<FindingData>> = HashMap::new();

            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    if let Some(body) = &func_def.body {
                        let findings = find_in_statement(body, file, self.id(), |expr| {
                            matches!(expr, Expression::StringLiteral(_))
                        });

                        for finding in findings {
                            if let Some(snippet) = &finding.location.snippet {
                                strings_by_value
                                    .entry(snippet.clone())
                                    .or_default()
                                    .push(finding);
                            }
                        }
                    }
                }
            }

            // Return only duplicates
            let mut result = Vec::new();
            for findings in strings_by_value.into_values() {
                if findings.len() > 1 {
                    result.extend(findings);
                }
            }
            result
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
                function test() external {
                    require(condition1, "Error");   // Line 6 - duplicate
                    require(condition2, "Error");   // Line 7 - duplicate
                }
            }
        "#;
        let detector = Arc::new(DuplicateStringLiteralDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 issues");
        assert_eq!(locations[0].line, 6, "first Error string");
        assert_eq!(locations[1].line, 7, "second Error string");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test() external {
                    require(condition1, "Error1");  // Unique string - OK
                    require(condition2, "Error2");  // Unique string - OK
                    require(condition3, "Error3");  // Unique string - OK
                }
            }
        "#;
        let detector = Arc::new(DuplicateStringLiteralDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
