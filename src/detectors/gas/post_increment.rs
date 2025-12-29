use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Loc, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct PostIncrementDetector;

impl Detector for PostIncrementDetector {
    fn id(&self) -> &'static str {
        "post-increment"
    }

    fn name(&self) -> &str {
        "`++i` costs less gas compared to `i++` or `i += 1` (same for `--i` vs `i--` or `i -= 1`)"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Pre-increments and pre-decrements are cheaper. For a `uint256 i` variable, the \
        following is true with the Optimizer enabled at 10k:\n\n\
        **Increment:**\n\
        - `i += 1` is the most expensive form\n\
        - `i++` costs 6 gas less than `i += 1`\n\
        - `++i` costs 5 gas less than `i++` (11 gas less than `i += 1`)\n\n\
        **Decrement:**\n\
        - `i -= 1` is the most expensive form\n\
        - `i--` costs 11 gas less than `i -= 1`\n\
        - `--i` costs 5 gas less than `i--` (16 gas less than `i -= 1`)\n\n\
        *Saves 5 gas per instance*"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - wastes gas
for (uint256 i = 0; i < length; i++) {
    counter++;
}

// Good - saves 5 gas per iteration
for (uint256 i = 0; i < length; ++i) {
    ++counter;
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_statement(move |stmt, file, _context| {
            let mut findings = Vec::new();

            match stmt {
                // Standalone expression statements: i++;
                Statement::Expression(_, expr) => {
                    if let Some(loc) = Self::is_post_increment_decrement(expr) {
                        findings.push(FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(&loc, file),
                        });
                    }
                }
                // For loop update: for (...; ...; i++)
                Statement::For(_, _, _, Some(update_expr), _) => {
                    if let Some(loc) = Self::is_post_increment_decrement(update_expr) {
                        findings.push(FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(&loc, file),
                        });
                    }
                }
                _ => {}
            }

            findings
        });
    }
}

impl PostIncrementDetector {
    fn is_post_increment_decrement(expr: &Expression) -> Option<Loc> {
        match expr {
            Expression::PostIncrement(loc, _) | Expression::PostDecrement(loc, _) => Some(*loc),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_issues() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function loop() external {
                    uint256 counter = 0;

                    for (uint256 i = 0; i < 10; i++) {
                        counter++;
                    }

                    counter--;
                }

                function multipleIncrements() external {
                    uint256 a = 0;
                    uint256 b = 0;

                    // Standalone statements
                    a++;
                    b--;
                }
            }
        "#;

        let detector = Arc::new(PostIncrementDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 5);
        assert_eq!(locations[0].line, 8, "for loop i++");
        assert_eq!(locations[1].line, 9, "counter++");
        assert_eq!(locations[2].line, 12, "counter--");
        assert_eq!(locations[3].line, 20, "a++");
        assert_eq!(locations[4].line, 21, "b--");
    }

    #[test]
    fn test_skips_valid_cases() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function good() external {
                    uint256 counter = 0;

                    // Pre-increment - no issue
                    for (uint256 i = 0; i < 10; ++i) {
                        ++counter;
                    }

                    --counter;
                }

                function semanticsDiffer() external returns (uint256) {
                    uint256 i = 0;
                    uint256[] memory arr = new uint256[](5);

                    // Return value is used - should not be flagged
                    uint256 x = i++;
                    arr[i++] = 10;

                    return arr[i++];
                }
            }
        "#;

        let detector = Arc::new(PostIncrementDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
