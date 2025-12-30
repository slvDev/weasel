use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{FunctionAttribute, FunctionDefinition, FunctionTy};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct InitializerFrontrunDetector;

impl Detector for InitializerFrontrunDetector {
    fn id(&self) -> &'static str {
        "initializer-frontrun"
    }

    fn name(&self) -> &str {
        "Initializers could be front-run"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Initializers could be front-run, allowing an attacker to either set their own values, \
         take ownership of the contract, and in the best case forcing a re-deployment. Ensure \
         that initializer functions are properly protected with access control or the `initializer` \
         modifier from OpenZeppelin's Initializable contract."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no protection, can be front-run
function initialize(address owner) public {
    _owner = owner;
}

// Good - protected with initializer modifier
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

function initialize(address owner) public initializer {
    _owner = owner;
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            if matches!(func_def.ty, FunctionTy::Constructor) {
                return Vec::new();
            }

            let Some(name) = &func_def.name else {
                return Vec::new();
            };

            if !name.name.to_lowercase().starts_with("init") {
                return Vec::new();
            }

            if !Self::has_initializer_modifier(func_def) {
                return FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&name.loc, file),
                }
                .into();
            }

            Vec::new()
        });
    }
}

impl InitializerFrontrunDetector {
    fn has_initializer_modifier(func_def: &FunctionDefinition) -> bool {
        func_def.attributes.iter().any(|attr| {
            if let FunctionAttribute::BaseOrModifier(_, base) = attr {
                base.name
                    .identifiers
                    .iter()
                    .any(|id| id.name == "initializer")
            } else {
                false
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_initialize_functions() {
        let code = r#"
            contract Test {
                function initialize(address owner) public {
                    // Could be front-run
                }

                function init() external {
                    // Could be front-run
                }

                function initConfig() public {
                    // Also matches
                }
            }
        "#;
        let detector = Arc::new(InitializerFrontrunDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 3, "initialize function");
        assert_eq!(locations[1].line, 7, "init function");
        assert_eq!(locations[2].line, 11, "initConfig function");
    }

    #[test]
    fn test_skips_protected_initializers() {
        let code = r#"
            contract Test {
                constructor(address owner) {
                    // Constructors are fine
                }

                function initialize(address owner) public initializer {
                    // Protected with initializer modifier
                }

                function setup() public {
                    // Different name, doesn't start with init
                }
            }
        "#;
        let detector = Arc::new(InitializerFrontrunDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
