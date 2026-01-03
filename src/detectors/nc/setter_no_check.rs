use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::ast_utils::{find_in_statement, find_statement_types};
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, FunctionAttribute, FunctionTy, Statement, Visibility};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct SetterNoCheckDetector;

impl Detector for SetterNoCheckDetector {
    fn id(&self) -> &'static str {
        "setter-no-check"
    }

    fn name(&self) -> &str {
        "Setter function lacks validation checks"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Setter functions should include validation checks such as sanity checks (e.g., checks \
         against zero values) or authorization checks. Using require, revert, or if statements \
         helps prevent invalid state changes."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
function setOwner(address newOwner) external {
    owner = newOwner;
}

// Good
function setOwner(address newOwner) external {
    require(newOwner != address(0), "Zero address");
    owner = newOwner;
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

            let has_control_flow = find_statement_types(body, file, self.id(), |stmt| {
                matches!(stmt, Statement::If(_, _, _, _) | Statement::Revert(_, _, _))
            })
            .is_empty();

            if !has_control_flow {
                return Vec::new();
            }

            let has_require_assert = find_in_statement(body, file, self.id(), |expr| {
                if let Expression::FunctionCall(_, func, _) = expr {
                    if let Expression::Variable(id) = func.as_ref() {
                        return id.name == "require" || id.name == "assert";
                    }
                }
                false
            })
            .is_empty();

            if !has_require_assert {
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
    fn test_detects_setters_without_checks() {
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

                function changeAdmin(address newAdmin) external {
                    owner = newAdmin;
                }

                function resetCounter() external {
                    value = 0;
                }
            }
        "#;
        let detector = Arc::new(SetterNoCheckDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].line, 6, "setOwner");
        assert_eq!(locations[1].line, 10, "updateValue");
        assert_eq!(locations[2].line, 14, "changeAdmin");
        assert_eq!(locations[3].line, 18, "resetCounter");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                address owner;
                uint256 value;

                function setOwnerWithRequire(address newOwner) external {
                    require(newOwner != address(0), "Zero address");
                    owner = newOwner;
                }

                function setOwnerWithAssert(address newOwner) external {
                    assert(newOwner != address(0));
                    owner = newOwner;
                }

                function setOwnerWithIf(address newOwner) external {
                    if (newOwner == address(0)) revert();
                    owner = newOwner;
                }

                function setOwnerWithRevert(address newOwner) external {
                    if (newOwner == address(0)) {
                        revert("Zero address");
                    }
                    owner = newOwner;
                }

                function _setInternal(address a) internal {
                    owner = a;
                }

                function _setPrivate(address a) private {
                    owner = a;
                }

                function getValue() public view returns (uint256) {
                    return value;
                }

                function setVirtual(address a) external virtual {
                    owner = a;
                }

                constructor() {
                    owner = msg.sender;
                }

                // Not setters
                function processAsset(uint256 v) external {
                    value = v;
                }
            }
        "#;
        let detector = Arc::new(SetterNoCheckDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
