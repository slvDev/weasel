use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{FunctionAttribute, FunctionTy, VariableAttribute, Visibility};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnderscorePrefixDetector;

impl Detector for UnderscorePrefixDetector {
    fn id(&self) -> &'static str {
        "underscore-prefix"
    }

    fn name(&self) -> &str {
        "Internal/private names should begin with underscore"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "According to the Solidity Style Guide, non-external variable and function names should \
         begin with an underscore to clearly indicate their visibility scope."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
uint256 private balance;
function helper() internal {}

// Good
uint256 private _balance;
function _helper() internal {}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let self_clone = Arc::clone(&self);

        visitor.on_variable(move |var_def, file, _context| {
            let name = match &var_def.name {
                Some(id) => &id.name,
                None => return Vec::new(),
            };

            if name.starts_with('_') {
                return Vec::new();
            }

            let mut is_internal_or_private = false;
            let mut is_constant = false;
            let mut is_immutable = false;

            for attr in &var_def.attrs {
                match attr {
                    VariableAttribute::Visibility(Visibility::Internal(_))
                    | VariableAttribute::Visibility(Visibility::Private(_)) => {
                        is_internal_or_private = true;
                    }
                    VariableAttribute::Constant(_) => {
                        is_constant = true;
                    }
                    VariableAttribute::Immutable(_) => {
                        is_immutable = true;
                    }
                    _ => {}
                }
            }

            let has_explicit_visibility = var_def
                .attrs
                .iter()
                .any(|attr| matches!(attr, VariableAttribute::Visibility(_)));

            if !has_explicit_visibility {
                is_internal_or_private = true;
            }

            if is_internal_or_private && !is_constant && !is_immutable {
                return FindingData {
                    detector_id: self_clone.id(),
                    location: loc_to_location(&var_def.loc, file),
                }
                .into();
            }

            Vec::new()
        });

        visitor.on_function(move |func_def, file, _context| {
            if matches!(
                func_def.ty,
                FunctionTy::Constructor | FunctionTy::Fallback | FunctionTy::Receive
            ) {
                return Vec::new();
            }

            let name = match &func_def.name {
                Some(id) => &id.name,
                None => return Vec::new(),
            };

            if name.starts_with('_') {
                return Vec::new();
            }

            let is_internal_or_private = func_def.attributes.iter().any(|attr| {
                matches!(
                    attr,
                    FunctionAttribute::Visibility(Visibility::Internal(_))
                        | FunctionAttribute::Visibility(Visibility::Private(_))
                )
            });

            if is_internal_or_private {
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
    fn test_detects_missing_underscore() {
        let code = r#"
            contract Test {
                uint256 private balance;
                uint256 internal count;
                uint256 stateVar;

                function helper() internal {}
                function compute() private returns (uint256) {}
            }
        "#;
        let detector = Arc::new(UnderscorePrefixDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 5);
        assert_eq!(locations[0].line, 3, "private balance");
        assert_eq!(locations[1].line, 4, "internal count");
        assert_eq!(locations[2].line, 5, "default internal stateVar");
        assert_eq!(locations[3].line, 7, "internal helper");
        assert_eq!(locations[4].line, 8, "private compute");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                uint256 private _balance;
                uint256 internal _count;
                uint256 public publicVar;
                uint256 constant CONST = 1;
                uint256 immutable IMMUT;

                constructor() {
                    IMMUT = 1;
                }

                function _helper() internal {}
                function _compute() private returns (uint256) {}
                function externalFn() external {}
                function publicFn() public {}
            }
        "#;
        let detector = Arc::new(UnderscorePrefixDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
