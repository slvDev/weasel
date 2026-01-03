use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct LargeLiteralDetector;

impl Detector for LargeLiteralDetector {
    fn id(&self) -> &'static str {
        "large-literal"
    }

    fn name(&self) -> &str {
        "Use scientific notation for large numbers"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Large multiples of ten should use scientific notation for readability. \
         Numbers with many zeros are harder to read and verify."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
uint256 amount = 1000000;

// Good
uint256 amount = 1e6;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::NumberLiteral(loc, value, _, _) = expr {
                // Check for 5+ trailing zeros (like 100000, 1000000, etc.)
                if value.len() >= 6 && value.ends_with("00000") {
                    return FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(loc, file),
                    }
                    .into();
                }
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
    fn test_detects_large_literals() {
        let code = r#"
            contract Test {
                uint256 a = 100000;
                uint256 b = 1000000;
                uint256 c = 10000000;
            }
        "#;
        let detector = Arc::new(LargeLiteralDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 3, "100000");
        assert_eq!(locations[1].line, 4, "1000000");
        assert_eq!(locations[2].line, 5, "10000000");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                uint256 a = 1e6;
                uint256 b = 1e18;
                uint256 c = 10000;
                uint256 d = 12345;
            }
        "#;
        let detector = Arc::new(LargeLiteralDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
