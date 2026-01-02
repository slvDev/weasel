use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::FunctionAttribute;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct NonReentrantBeforeModifiersDetector;

impl Detector for NonReentrantBeforeModifiersDetector {
    fn id(&self) -> &'static str {
        "nonreentrant-before-modifiers"
    }

    fn name(&self) -> &str {
        "The `nonReentrant` modifier should occur before all other modifiers"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "This is a best-practice to protect against reentrancy in other modifiers. \
         The `nonReentrant` modifier should be the first modifier in the function signature."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
function withdraw() external onlyOwner nonReentrant { }

// Good
function withdraw() external nonReentrant onlyOwner { }
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func, file, _context| {
            let modifiers: Vec<_> = func
                .attributes
                .iter()
                .filter_map(|attr| {
                    if let FunctionAttribute::BaseOrModifier(loc, base) = attr {
                        let name = base
                            .name
                            .identifiers
                            .first()
                            .map(|id| id.name.as_str())
                            .unwrap_or("");
                        Some((loc, name))
                    } else {
                        None
                    }
                })
                .collect();

            // Find position of nonReentrant modifier
            let nonreentrant_pos = modifiers
                .iter()
                .position(|(_, name)| *name == "nonReentrant");

            if let Some(pos) = nonreentrant_pos {
                if pos > 0 {
                    return FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(modifiers[pos].0, file),
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
    fn test_detects_nonreentrant_not_first() {
        let code = r#"
            contract Test {
                modifier nonReentrant() { _; }
                modifier onlyOwner() { _; }
                modifier whenNotPaused() { _; }

                function bad1() external onlyOwner nonReentrant { }
                function bad2() public whenNotPaused onlyOwner nonReentrant { }
            }
        "#;
        let detector = Arc::new(NonReentrantBeforeModifiersDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 7, "bad1 nonReentrant after onlyOwner");
        assert_eq!(locations[1].line, 8, "bad2 nonReentrant last");
    }

    #[test]
    fn test_skips_correct_ordering() {
        let code = r#"
            contract Test {
                modifier nonReentrant() { _; }
                modifier onlyOwner() { _; }
                modifier whenNotPaused() { _; }

                function good1() external nonReentrant { }
                function good2() public nonReentrant onlyOwner { }
                function good3() external nonReentrant onlyOwner whenNotPaused { }
                function noModifier() external pure returns (uint256) { return 1; }
            }
        "#;
        let detector = Arc::new(NonReentrantBeforeModifiersDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
