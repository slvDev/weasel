use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::ast_utils::find_statement_types;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{FunctionAttribute, FunctionTy, Statement, Visibility};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct MissingEventSetterDetector;

impl Detector for MissingEventSetterDetector {
    fn id(&self) -> &'static str {
        "missing-event-setter"
    }

    fn name(&self) -> &str {
        "Missing event for critical parameter change"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Setter functions that modify critical parameters should emit events. Events help \
         off-chain tools track changes and prevent users from being surprised by changes."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
function setOwner(address newOwner) external {
    owner = newOwner;
}

// Good
event OwnerUpdated(address indexed oldOwner, address indexed newOwner);

function setOwner(address newOwner) external {
    address oldOwner = owner;
    owner = newOwner;
    emit OwnerUpdated(oldOwner, newOwner);
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

            let is_setter = name.starts_with("set")
                || name.starts_with("update")
                || name.starts_with("change")
                || name.starts_with("reset")
                || name.starts_with("modify")
                || name.starts_with("configure");

            if !is_setter {
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

            let emits = find_statement_types(body, file, self.id(), |stmt| {
                matches!(stmt, Statement::Emit(_, _))
            });

            if !emits.is_empty() {
                return Vec::new();
            }

            FindingData {
                detector_id: self.id(),
                location: loc_to_location(&func_def.loc, file),
            }
            .into()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_missing_events() {
        let code = r#"
            contract Test {
                address owner;
                uint256 value;

                function setOwner(address newOwner) external {
                    owner = newOwner;
                }

                function updateValue(uint256 newValue) public {
                    value = newValue;
                }

                function changeOwner(address newOwner) external {
                    owner = newOwner;
                }

                function resetValue() public {
                    value = 0;
                }

                function modifySettings(uint256 v) external {
                    value = v;
                }

                function configureParams(uint256 v) external {
                    value = v;
                }
            }
        "#;
        let detector = Arc::new(MissingEventSetterDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 6);
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                address owner;

                event OwnerSet(address indexed newOwner);

                function setOwner(address newOwner) external {
                    owner = newOwner;
                    emit OwnerSet(newOwner);
                }

                function _setInternal(address a) internal {
                    owner = a;
                }

                function _setPrivate(address a) private {
                    owner = a;
                }

                function getValue() public view returns (uint256) {
                    return 0;
                }

                function getOwner() public pure returns (address) {
                    return address(0);
                }

                function setVirtual(address a) external virtual {
                    owner = a;
                }

                constructor() {
                    owner = msg.sender;
                }

                // Not setters - "set" in middle of word
                function processAsset(uint256 v) external {
                    owner = address(0);
                }

                function calculateOffset(uint256 v) external {
                    owner = address(0);
                }
            }
        "#;
        let detector = Arc::new(MissingEventSetterDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
