use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct NumericUnderscoresDetector;

impl Detector for NumericUnderscoresDetector {
    fn id(&self) -> &'static str {
        "numeric-underscores"
    }

    fn name(&self) -> &str {
        "Use underscores for number literals"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Large number literals should use underscores for readability (e.g., 1_000_000 instead \
         of 1000000). Add an underscore every 3 digits."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
uint256 amount = 1000000;
uint256 supply = 10000000000;

// Good
uint256 amount = 1_000_000;
uint256 supply = 10_000_000_000;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::NumberLiteral(loc, value, _, _) = expr {
                let digits_only: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits_only.len() < 4 {
                    return Vec::new();
                }

                let location = loc_to_location(loc, file);
                let has_underscore = location
                    .snippet
                    .as_ref()
                    .map(|s| s.contains('_'))
                    .unwrap_or(false);

                if !has_underscore {
                    return FindingData {
                        detector_id: self.id(),
                        location,
                    }
                    .into();
                }
            }
            Vec::new()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_missing_underscores() {
        let code = r#"
            contract Test {
                uint256 a = 1000;
                uint256 b = 10000;
                uint256 c = 1000000;
                uint256 d = 10000000000000000000;
            }
        "#;
        let detector = Arc::new(NumericUnderscoresDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].line, 3, "1000");
        assert_eq!(locations[1].line, 4, "10000");
        assert_eq!(locations[2].line, 5, "1000000");
        assert_eq!(locations[3].line, 6, "10000000000000000000");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                uint256 a = 1;
                uint256 b = 10;
                uint256 c = 100;
                uint256 d = 1_000;
                uint256 e = 1_000_000;
                uint256 f = 10_000_000_000;
            }
        "#;
        let detector = Arc::new(NumericUnderscoresDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
