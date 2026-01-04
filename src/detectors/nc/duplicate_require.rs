use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::Location;
use crate::models::severity::Severity;
use crate::models::{FindingData, SolidityFile};
use crate::utils::ast_utils::find_locations_in_statement;
use crate::utils::location::loc_to_location;
use solang_parser::helpers::CodeLocation;
use solang_parser::pt::{ContractPart, Expression, Loc};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DuplicateRequireDetector;

impl Detector for DuplicateRequireDetector {
    fn id(&self) -> &'static str {
        "duplicate-require"
    }

    fn name(&self) -> &str {
        "Duplicated require/revert checks should be refactored to a modifier or function"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "When the same require() or revert() check appears multiple times with the same condition, \
         consider refactoring to a modifier or internal function to reduce code duplication."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - duplicated require
function foo() external {
    require(msg.sender == owner, "Not owner");
}
function bar() external {
    require(msg.sender == owner, "Not owner");
}

// Good - use modifier
modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}
function foo() external onlyOwner {}
function bar() external onlyOwner {}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            let mut conditions: HashMap<String, Vec<Location>> = HashMap::new();

            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func) = part {
                    if let Some(body) = &func.body {
                        Self::collect_require_conditions(body, file, &mut conditions);
                    }
                }
            }

            conditions
                .into_values()
                .filter(|locs| locs.len() > 1)
                .flatten()
                .map(|loc| FindingData {
                    detector_id: self.id(),
                    location: loc,
                })
                .collect()
        });
    }
}

impl DuplicateRequireDetector {
    fn collect_require_conditions(
        body: &solang_parser::pt::Statement,
        file: &SolidityFile,
        conditions: &mut HashMap<String, Vec<Location>>,
    ) {
        let mut predicate = |expr: &Expression, file: &SolidityFile| -> Option<Loc> {
            if let Some((loc, key)) = Self::extract_require_condition(expr, file) {
                conditions
                    .entry(key)
                    .or_default()
                    .push(loc_to_location(&loc, file));
            }
            None // dont collect
        };

        let mut _unused = Vec::new();
        find_locations_in_statement(body, file, &mut predicate, &mut _unused);
    }

    fn extract_require_condition(expr: &Expression, file: &SolidityFile) -> Option<(Loc, String)> {
        if let Expression::FunctionCall(loc, func, args) = expr {
            if let Expression::Variable(ident) = func.as_ref() {
                if ident.name == "require" && !args.is_empty() {
                    if let Loc::File(_, start, end) = args[0].loc() {
                        if let Some(key) = file.content.get(start..end) {
                            return Some((loc.clone(), key.to_string()));
                        }
                    }
                }
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
    fn test_detects_duplicate_requires() {
        let code = r#"
            contract Test {
                address owner;

                function foo() external {
                    require(msg.sender == owner, "Not owner");
                }

                function bar() external {
                    require(msg.sender == owner, "Different message");
                }

                function baz() external {
                    require(x > 0, "Not owner");
                }
            }
        "#;
        let detector = Arc::new(DuplicateRequireDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        // Same condition "msg.sender == owner" appears twice - both flagged
        // Different condition "x > 0" is unique - not flagged
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 6, "first require same condition");
        assert_eq!(locations[1].line, 10, "second require same condition");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                function foo() external {
                    require(x > 0, "X must be positive");
                }

                function bar() external {
                    require(y > 0, "Y must be positive");
                }
            }
        "#;
        let detector = Arc::new(DuplicateRequireDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
