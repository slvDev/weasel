use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::finding::FindingData;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct BooleanComparisonDetector;

impl Detector for BooleanComparisonDetector {
    fn id(&self) -> &'static str {
        "boolean-comparison"
    }

    fn name(&self) -> &str {
        "Avoid Comparisons of Boolean Expressions to Boolean Literals"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Direct comparisons of boolean expressions to boolean literals (true or false) can lead \
        to unnecessary gas costs. Instead, use the boolean expression directly or its negation \
        in conditional statements for better gas efficiency."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"
```solidity
// Instead of:
if (condition == true) { }
require(value == false);

// Use:
if (condition) { }
require(!value);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file| {
            if let Expression::Equal(loc, left, right) | Expression::NotEqual(loc, left, right) =
                expr
            {
                if matches!(left.as_ref(), Expression::BoolLiteral(_, _))
                    || matches!(right.as_ref(), Expression::BoolLiteral(_, _))
                {
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
    use std::sync::Arc;

    #[test]
    fn test_boolean_comparison_detection() {
        let code = r#"
            pragma solidity ^0.8.0;
            contract Test {
                bool condition;
                
                function testIfStatements() public {
                    if (condition == true) {  // Should detect
                        // do something
                    }
                    if (false != condition) {  // Should detect
                        // do something
                    }
                    if (condition) {  // Should NOT detect - good practice
                        // do something  
                    }
                }
                
                function testRequire() public {
                    require(condition == false);  // Should detect
                    require(!condition);  // Should NOT detect - good practice
                }
                
                function testComplexExpressions() public {
                    if (condition == true || false != condition) {  // Should detect both
                        // do something
                    }
                }
            }
        "#;

        let detector = Arc::new(BooleanComparisonDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            5,
            "Should detect 5 boolean literal comparisons"
        );

        // Check specific detections
        assert_eq!(locations[0].line, 7, "Should detect condition == true");
        assert_eq!(locations[1].line, 10, "Should detect false != condition");
        assert_eq!(locations[2].line, 19, "Should detect condition == false");
        assert_eq!(
            locations[3].line, 24,
            "Should detect condition == true in complex expression"
        );
        assert_eq!(
            locations[4].line, 24,
            "Should detect false != condition in complex expression"
        );
    }

    #[test]
    fn test_no_false_positives() {
        let code = r#"
            pragma solidity ^0.8.0;
            contract Test {
                bool condition;
                uint value;
                
                function goodPractices() public {
                    if (condition) {  // Good - direct boolean
                        // do something
                    }
                    if (!condition) {  // Good - negated boolean
                        // do something
                    }
                    require(condition);  // Good - direct boolean
                    require(!condition);  // Good - negated boolean
                    
                    if (value == 42) {  // Good - not boolean literal
                        // do something
                    }
                }
            }
        "#;

        let detector = Arc::new(BooleanComparisonDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            0,
            "Should not detect any issues in good code"
        );
    }
}
