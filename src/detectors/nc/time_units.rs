use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct TimeUnitsDetector;

impl Detector for TimeUnitsDetector {
    fn id(&self) -> &'static str {
        "time-units"
    }

    fn name(&self) -> &str {
        "Use time units for readability"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Numeric values having to do with time should use time units for readability. \
         Solidity provides units for seconds, minutes, hours, days, and weeks."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
uint256 lockupPeriod = 86400;
uint256 delay = 3600;

// Good
uint256 lockupPeriod = 1 days;
uint256 delay = 1 hours;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        // State variables
        let self_clone = Arc::clone(&self);
        visitor.on_variable(move |var_def, file, _context| {
            let name = var_def.name.as_ref().map(|n| &n.name);
            Self::check_variable(
                name,
                &var_def.initializer,
                &var_def.loc,
                file,
                self_clone.id(),
            )
        });

        // Local variables
        visitor.on_statement(move |stmt, file, _context| {
            if let Statement::VariableDefinition(loc, decl, init) = stmt {
                let name = decl.name.as_ref().map(|n| &n.name);
                return Self::check_variable(name, init, loc, file, self.id());
            }
            Vec::new()
        });
    }
}

impl TimeUnitsDetector {
    fn check_variable(
        name: Option<&String>,
        init: &Option<Expression>,
        loc: &solang_parser::pt::Loc,
        file: &crate::models::SolidityFile,
        detector_id: &'static str,
    ) -> Vec<FindingData> {
        let Some(name) = name else {
            return Vec::new();
        };

        let name_lower = name.to_lowercase();

        let is_time_related = name_lower.contains("epoch")
            || name_lower.contains("expiry")
            || name_lower.contains("period")
            || name_lower.contains("warmup")
            || name_lower.contains("time")
            || name_lower.contains("delay")
            || name_lower.contains("duration")
            || name_lower.contains("timeout")
            || name_lower.contains("interval")
            || name_lower.contains("cooldown");

        if !is_time_related {
            return Vec::new();
        }

        let Some(init) = init else {
            return Vec::new();
        };

        if matches!(init, Expression::NumberLiteral(_, _, _, None)) {
            return FindingData {
                detector_id,
                location: loc_to_location(loc, file),
            }
            .into();
        }

        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_plain_numbers() {
        let code = r#"
            contract Test {
                uint256 lockupPeriod = 86400;
                uint256 delay = 3600;

                function foo() public {
                    uint256 timeout = 300;
                    uint256 cooldownInterval = 60;
                }
            }
        "#;
        let detector = Arc::new(TimeUnitsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].line, 3, "lockupPeriod state var");
        assert_eq!(locations[1].line, 4, "delay state var");
        assert_eq!(locations[2].line, 7, "timeout local var");
        assert_eq!(locations[3].line, 8, "cooldownInterval local var");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                uint256 lockupPeriod = 1 days;
                uint256 delay = 1 hours;
                uint256 amount = 100;

                function foo() public {
                    uint256 timeout = 5 minutes;
                    uint256 count = 50;
                }
            }
        "#;
        let detector = Arc::new(TimeUnitsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
