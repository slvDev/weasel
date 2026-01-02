use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct Year365DaysDetector;

impl Detector for Year365DaysDetector {
    fn id(&self) -> &'static str {
        "year-365-days"
    }

    fn name(&self) -> &str {
        "A year is not always 365 days"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "On leap years, the number of days is 366, so calculations during those years will \
         return the wrong value."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - doesn't account for leap years
uint256 constant SECONDS_PER_YEAR = 365 days;

// Good - use average accounting for leap years
uint256 constant SECONDS_PER_YEAR = 365.25 days;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let detector = self.clone();
        visitor.on_variable(move |var_def, file, _context| {
            let Some(name) = &var_def.name else {
                return Vec::new();
            };

            if !name.name.to_lowercase().contains("year") {
                return Vec::new();
            }

            if let Some(init) = &var_def.initializer {
                if Self::contains_365(init) {
                    return FindingData {
                        detector_id: detector.id(),
                        location: loc_to_location(&var_def.loc, file),
                    }
                    .into();
                }
            }

            Vec::new()
        });

        visitor.on_statement(move |stmt, file, _context| {
            if let Statement::VariableDefinition(loc, decl, Some(init)) = stmt {
                if let Some(name) = &decl.name {
                    if name.name.to_lowercase().contains("year") && Self::contains_365(init) {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(loc, file),
                        }
                        .into();
                    }
                }
            }
            Vec::new()
        });
    }
}

impl Year365DaysDetector {
    fn contains_365(expr: &Expression) -> bool {
        match expr {
            Expression::NumberLiteral(_, value, _, _) => value == "365",
            Expression::Multiply(_, left, right)
            | Expression::Add(_, left, right)
            | Expression::Divide(_, left, right) => {
                Self::contains_365(left) || Self::contains_365(right)
            }
            Expression::Parenthesis(_, inner) => Self::contains_365(inner),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_year_365() {
        let code = r#"
            contract Test {
                uint256 constant SECONDS_PER_YEAR = 365 days;
                uint256 public daysInYear = 365;

                function calc() external {
                    uint256 secondsPerYear = 365 * 24 * 60 * 60;
                }
            }
        "#;
        let detector = Arc::new(Year365DaysDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 3, "SECONDS_PER_YEAR constant");
        assert_eq!(locations[1].line, 4, "daysInYear state var");
        assert_eq!(locations[2].line, 7, "secondsPerYear local var");
    }

    #[test]
    fn test_skips_non_year_variables() {
        let code = r#"
            contract Test {
                uint256 constant DAYS = 365;
                uint256 public count = 365;

                function calc() external {
                    uint256 value = 365;
                }
            }
        "#;
        let detector = Arc::new(Year365DaysDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
