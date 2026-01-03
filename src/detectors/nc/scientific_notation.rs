use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ScientificNotationDetector;

impl Detector for ScientificNotationDetector {
    fn id(&self) -> &'static str {
        "scientific-notation"
    }

    fn name(&self) -> &str {
        "Use scientific notation rather than exponentiation"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Use scientific notation (e.g. 1e18) rather than exponentiation (e.g. 10**18). \
         This is shorter and more readable, especially in calculations."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
uint256 amount = value * 10**18;
uint256 decimals = 10**6;

// Good
uint256 amount = value * 1e18;
uint256 decimals = 1e6;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::Power(loc, base, _exp) = expr {
                if matches!(base.as_ref(), Expression::NumberLiteral(_, v, _, _) if v == "10") {
                    return FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(loc, file),
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
    fn test_detects_exponentiation() {
        let code = r#"
            contract Test {
                uint256 a = 10**18;
                uint256 b = 10**6;
                uint256 c = value * 10**18;
            }
        "#;
        let detector = Arc::new(ScientificNotationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 3, "10**18");
        assert_eq!(locations[1].line, 4, "10**6");
        assert_eq!(locations[2].line, 5, "10**18 in multiplication");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                uint256 a = 1e18;
                uint256 b = 1e6;
                uint256 c = 2**256;
                uint256 d = base**exp;
            }
        "#;
        let detector = Arc::new(ScientificNotationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
