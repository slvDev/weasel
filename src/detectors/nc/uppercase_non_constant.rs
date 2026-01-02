use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::VariableAttribute;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UppercaseNonConstantDetector;

impl Detector for UppercaseNonConstantDetector {
    fn id(&self) -> &'static str {
        "uppercase-non-constant"
    }

    fn name(&self) -> &str {
        "All-caps variable names should be reserved for constant/immutable variables"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Variable names that consist of all capital letters should be reserved for `constant` \
         or `immutable` variables. If the variable needs to be different based on which class \
         it comes from, a `view`/`pure` function should be used instead."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
uint256 public MAX_SUPPLY;

// Good
uint256 public constant MAX_SUPPLY = 1000000;
uint256 public immutable MAX_SUPPLY;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_variable(move |var_def, file, _context| {
            let name = match &var_def.name {
                Some(id) => &id.name,
                None => return Vec::new(),
            };

            if !Self::looks_like_constant_name(name) {
                return Vec::new();
            }

            let is_constant_or_immutable = var_def.attrs.iter().any(|attr| {
                matches!(
                    attr,
                    VariableAttribute::Constant(_) | VariableAttribute::Immutable(_)
                )
            });

            if !is_constant_or_immutable {
                return FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&var_def.loc, file),
                }
                .into();
            }

            Vec::new()
        });
    }
}

impl UppercaseNonConstantDetector {
    fn looks_like_constant_name(name: &str) -> bool {
        let mut consecutive_upper = 0;
        for c in name.chars() {
            if c.is_ascii_uppercase() {
                consecutive_upper += 1;
                if consecutive_upper >= 2 {
                    return true;
                }
            } else {
                consecutive_upper = 0;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_uppercase_non_constant() {
        let code = r#"
            contract Test {
                uint256 public MAX_SUPPLY;
                uint256 public TOTAL_AMOUNT;
                address public OWNER;
            }
        "#;
        let detector = Arc::new(UppercaseNonConstantDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 3, "MAX_SUPPLY");
        assert_eq!(locations[1].line, 4, "TOTAL_AMOUNT");
        assert_eq!(locations[2].line, 5, "OWNER");
    }

    #[test]
    fn test_skips_constant_and_immutable() {
        let code = r#"
            contract Test {
                uint256 public constant MAX_SUPPLY = 1000000;
                uint256 public immutable TOTAL_AMOUNT;
                address public immutable OWNER;

                // Regular camelCase variables are fine
                uint256 public totalSupply;
                address public owner;
            }
        "#;
        let detector = Arc::new(UppercaseNonConstantDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }

}
