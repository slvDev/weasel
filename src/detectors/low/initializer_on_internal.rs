use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Visibility;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct InitializerOnInternalDetector;

impl Detector for InitializerOnInternalDetector {
    fn id(&self) -> &'static str {
        "initializer-on-internal"
    }

    fn name(&self) -> &str {
        "Internal function uses `initializer` instead of `onlyInitializing`"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Internal functions should use `onlyInitializing` modifier instead of `initializer`. \
         The `initializer` modifier is for public-facing functions only."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - internal with initializer
function __MyContract_init() internal initializer {
    __Ownable_init();
}

// Good - internal with onlyInitializing
function __MyContract_init() internal onlyInitializing {
    __Ownable_init();
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            let is_internal = func_def
                .attributes
                .iter()
                .any(|attr| matches!(attr, solang_parser::pt::FunctionAttribute::Visibility(Visibility::Internal(_))));

            if !is_internal {
                return Vec::new();
            }

            let has_initializer = func_def.attributes.iter().any(|attr| {
                if let solang_parser::pt::FunctionAttribute::BaseOrModifier(_, base) = attr {
                    return base.name.identifiers.iter().any(|id| id.name == "initializer");
                }
                false
            });

            if has_initializer {
                return FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&func_def.loc, file),
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
    fn test_detects_initializer_on_internal() {
        let code = r#"
            contract Test {
                function __Test_init() internal initializer {
                    // init logic
                }

                function __Test_init_unchained() internal initializer {
                    // init logic
                }
            }
        "#;
        let detector = Arc::new(InitializerOnInternalDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 3, "__Test_init internal initializer");
        assert_eq!(locations[1].line, 7, "__Test_init_unchained internal initializer");
    }

    #[test]
    fn test_skips_correct_patterns() {
        let code = r#"
            contract Test {
                function initialize() external initializer {
                    // public-facing init
                }

                function __Test_init() internal onlyInitializing {
                    // correct modifier
                }

                function helper() internal {
                    // no modifier
                }
            }
        "#;
        let detector = Arc::new(InitializerOnInternalDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
