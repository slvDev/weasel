use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_statement_types;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{FunctionTy, Loc, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ConstructorEmitEventDetector;

impl Detector for ConstructorEmitEventDetector {
    fn id(&self) -> &'static str {
        "constructor-emit-event"
    }

    fn name(&self) -> &str {
        "Consider emitting an event at the end of the constructor"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Emitting an event in the constructor allows users to easily pinpoint when and by \
         whom a contract was constructed. This improves transparency and auditability."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no event emitted
constructor(address owner) {
    _owner = owner;
}

// Good - event emitted for transparency
constructor(address owner) {
    _owner = owner;
    emit ContractInitialized(owner);
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            // Only check constructors
            if func_def.ty != FunctionTy::Constructor {
                return Vec::new();
            }

            // Check if constructor has a body with emit statements
            if let Some(body) = &func_def.body {
                let emits = find_statement_types(body, file, self.id(), |stmt| {
                    matches!(stmt, Statement::Emit(_, _))
                });

                if emits.is_empty() {
                    if let Statement::Block { loc: body_loc, .. } = body {
                        // Only report the constructor signature, not the entire body
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

            contract NoEmit {
                address owner;

                constructor(address _owner) {       // Line 7 - no emit
                    owner = _owner;
                }
            }

            contract AlsoNoEmit {
                constructor() {}                    // Line 13 - empty, no emit
            }
        "#;
        let detector = Arc::new(ConstructorEmitEventDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(
            locations.len(),
            2,
            "Should detect 2 constructors without emit"
        );
        assert_eq!(locations[0].line, 7, "NoEmit constructor");
        assert_eq!(locations[1].line, 13, "AlsoNoEmit constructor");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract WithEmit {
                event Initialized(address owner);
                address owner;

                constructor(address _owner) {
                    owner = _owner;
                    emit Initialized(_owner);       // Has emit - OK
                }
            }

            contract NoConstructor {
                function setup() public {}          // Not a constructor - OK
            }
        "#;
        let detector = Arc::new(ConstructorEmitEventDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(
            locations.len(),
            0,
            "Should not detect constructors with emit"
        );
    }
}
