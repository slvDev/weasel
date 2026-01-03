use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_statement_types;
use solang_parser::pt::{Expression, FunctionAttribute, FunctionTy, Statement, Visibility};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct SetterEventOldValueDetector;

impl Detector for SetterEventOldValueDetector {
    fn id(&self) -> &'static str {
        "setter-event-old-value"
    }

    fn name(&self) -> &str {
        "Setter event should contain both old and new value"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Events that mark critical parameter changes should contain both the old and the new \
         value. This is especially important when the new value is not required to be different \
         from the old value."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
event OwnerSet(address indexed newOwner);

function setOwner(address newOwner) external {
    owner = newOwner;
    emit OwnerSet(newOwner);
}

// Good
event OwnerSet(address indexed oldOwner, address indexed newOwner);

function setOwner(address newOwner) external {
    address oldOwner = owner;
    owner = newOwner;
    emit OwnerSet(oldOwner, newOwner);
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            if matches!(
                func_def.ty,
                FunctionTy::Constructor | FunctionTy::Fallback | FunctionTy::Receive
            ) {
                return Vec::new();
            }

            let name = match &func_def.name {
                Some(id) => id.name.to_lowercase(),
                None => return Vec::new(),
            };

            // Only check functions starting with set or update
            if !name.starts_with("set") && !name.starts_with("update") {
                return Vec::new();
            }

            let mut is_internal_or_private = false;
            let mut is_view_or_pure = false;
            let mut is_virtual = false;

            for attr in &func_def.attributes {
                match attr {
                    FunctionAttribute::Visibility(Visibility::Internal(_))
                    | FunctionAttribute::Visibility(Visibility::Private(_)) => {
                        is_internal_or_private = true;
                    }
                    FunctionAttribute::Mutability(m) => {
                        if matches!(
                            m,
                            solang_parser::pt::Mutability::View(_)
                                | solang_parser::pt::Mutability::Pure(_)
                        ) {
                            is_view_or_pure = true;
                        }
                    }
                    FunctionAttribute::Virtual(_) => {
                        is_virtual = true;
                    }
                    _ => {}
                }
            }

            if is_internal_or_private || is_view_or_pure || is_virtual {
                return Vec::new();
            }

            let Some(body) = &func_def.body else {
                return Vec::new();
            };

            // Find emit statements with only 1 argument (missing old value)
            find_statement_types(body, file, self.id(), |stmt| {
                if let Statement::Emit(_, expr) = stmt {
                    if let Expression::FunctionCall(_, _, args) = expr {
                        return args.len() == 1;
                    }
                }
                false
            })
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_single_arg_emit() {
        let code = r#"
            contract Test {
                address owner;
                uint256 value;
                event OwnerSet(address newOwner);
                event ValueUpdated(uint256 newValue);

                function setOwner(address newOwner) external {
                    owner = newOwner;
                    emit OwnerSet(newOwner);
                }

                function updateValue(uint256 newValue) public {
                    value = newValue;
                    emit ValueUpdated(newValue);
                }
            }
        "#;
        let detector = Arc::new(SetterEventOldValueDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 10, "emit OwnerSet(newOwner)");
        assert_eq!(locations[1].line, 15, "emit ValueUpdated(newValue)");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                address owner;

                event OwnerSet(address oldOwner, address newOwner);
                event OwnerSetSingle(address newOwner);

                function setOwner(address newOwner) external {
                    address oldOwner = owner;
                    owner = newOwner;
                    emit OwnerSet(oldOwner, newOwner);
                }

                function setOwnerNoEvent(address newOwner) external {
                    owner = newOwner;
                }

                function _setInternal(address a) internal {
                    emit OwnerSetSingle(a);
                }

                function transferOwner(address newOwner) external {
                    owner = newOwner;
                    emit OwnerSetSingle(newOwner);
                }

                function setVirtual(address a) external virtual {
                    emit OwnerSetSingle(a);
                }
            }
        "#;
        let detector = Arc::new(SetterEventOldValueDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
