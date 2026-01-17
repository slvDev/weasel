use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct BoolInitFalseDetector;

impl Detector for BoolInitFalseDetector {
    fn id(&self) -> &'static str {
        "bool-init-false"
    }

    fn name(&self) -> &str {
        "Variables need not be initialized to false"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "By default, boolean variables in Solidity are initialized to `false`. Explicitly setting \
         variables to `false` during their declaration is redundant and might cause confusion. \
         Removing the explicit false initialization can improve code readability."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - redundant initialization
bool public paused = false;

// Good - default is already false
bool public paused;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector_id = self.id();

        // Check state variables
        visitor.on_variable(move |var_def, file, _context| {
            if let Some(Expression::BoolLiteral(loc, false)) = &var_def.initializer {
                return FindingData {
                    detector_id,
                    location: loc_to_location(loc, file),
                }
                .into();
            }
            Vec::new()
        });

        // Check local variables
        visitor.on_statement(move |stmt, file, _context| {
            if let Statement::VariableDefinition(loc, _, Some(Expression::BoolLiteral(_, false))) =
                stmt
            {
                return FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(loc, file),
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
    fn test_detects_issue() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                bool bar = false;                       // Line 5 - state var
                function test() public {
                    bool foo = false;                   // Line 7 - local var
                }
            }
        "#;
        let detector = Arc::new(BoolInitFalseDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 issues");
        assert_eq!(locations[0].line, 5, "state variable");
        assert_eq!(locations[1].line, 7, "local variable");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                bool public paused;                     // No init - OK
                bool public active = true;              // Init to true - OK
                function test(bool flag) public {
                    bool foo;                           // No init - OK
                    bool bar = true;                    // Init to true - OK
                    if (flag == false) {}               // Comparison - OK
                    require(active != false, "err");    // Comparison - OK
                }
            }
        "#;
        let detector = Arc::new(BoolInitFalseDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
