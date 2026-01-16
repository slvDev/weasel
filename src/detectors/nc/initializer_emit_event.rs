use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_statement_types;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{FunctionAttribute, FunctionTy, Loc, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct InitializerEmitEventDetector;

impl Detector for InitializerEmitEventDetector {
    fn id(&self) -> &'static str {
        "initializer-emit-event"
    }

    fn name(&self) -> &str {
        "Consider emitting an event in initializer functions"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Emitting an initialization event offers clear, on-chain evidence of the contract's \
         initialization state, enhancing transparency and auditability. This practice aids users \
         and developers in accurately tracking the contract's lifecycle, pinpointing the precise \
         moment of its initialization. Moreover, it aligns with best practices for event logging \
         in smart contracts, ensuring that significant state changes are both observable and \
         verifiable through emitted events."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no event emitted in initializer
function initialize(address owner) external initializer {
    _owner = owner;
}

// Good - event emitted for transparency
function initialize(address owner) external initializer {
    _owner = owner;
    emit Initialized(owner);
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            if func_def.ty == FunctionTy::Constructor {
                return Vec::new();
            }

            let is_init_name = func_def
                .name
                .as_ref()
                .map(|name| name.name.starts_with("init"))
                .unwrap_or(false);

            let has_initializer_modifier = func_def.attributes.iter().any(|attr| {
                if let FunctionAttribute::BaseOrModifier(_, base) = attr {
                    base.name
                        .identifiers
                        .iter()
                        .any(|id| id.name == "initializer")
                } else {
                    false
                }
            });

            if !is_init_name && !has_initializer_modifier {
                return Vec::new();
            }

            // Check if function has a body with emit statements
            if let Some(body) = &func_def.body {
                let emits = find_statement_types(body, file, self.id(), |stmt| {
                    matches!(stmt, Statement::Emit(_, _))
                });

                if emits.is_empty() {
                    if let Statement::Block { loc: body_loc, .. } = body {
                        let issue_loc = Loc::default()
                            .with_start(func_def.loc.start())
                            .with_end(body_loc.start());

                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(&issue_loc, file),
                        }
                        .into();
                    }
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
    fn test_detects_issue() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                address owner;

                function initialize(address _owner) external {  // Line 7 - init name, no emit
                    owner = _owner;
                }

                function initContract() external {              // Line 11 - init name, no emit
                    owner = msg.sender;
                }

                function initSomething() public {               // Line 15 - init name, no emit
                    // do something
                }

                function setup(address _owner) external initializer {  // Line 19 - initializer modifier, no emit
                    owner = _owner;
                }
            }
        "#;
        let detector = Arc::new(InitializerEmitEventDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4, "Should detect 4 issues");
        assert_eq!(locations[0].line, 7, "initialize function");
        assert_eq!(locations[1].line, 11, "initContract function");
        assert_eq!(locations[2].line, 15, "initSomething function");
        assert_eq!(locations[3].line, 19, "setup with initializer modifier");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                event Initialized(address owner);
                address owner;

                // Has emit - OK
                function initialize(address _owner) external {
                    owner = _owner;
                    emit Initialized(_owner);
                }

                // Has emit with initializer modifier - OK
                function setup(address _owner) external initializer {
                    owner = _owner;
                    emit Initialized(_owner);
                }

                // Not init name, no modifier - OK
                function configure() public {}

                // Constructor - handled by other detector - OK
                constructor(address _owner) {
                    owner = _owner;
                }
            }
        "#;
        let detector = Arc::new(InitializerEmitEventDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
