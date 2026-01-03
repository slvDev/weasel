use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::ast_utils::find_variable_uses;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{FunctionAttribute, FunctionTy};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnusedOverrideParamsDetector;

impl Detector for UnusedOverrideParamsDetector {
    fn id(&self) -> &'static str {
        "unused-override-params"
    }

    fn name(&self) -> &str {
        "Unused override function parameters should be named with underscore"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Override function arguments that are unused should have the variable name removed or \
         commented out to avoid compiler warnings. Use underscore prefix for unused parameters."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
function foo(uint256 unusedParam) external override {
    // unusedParam is never used
}

// Good
function foo(uint256 /* unusedParam */) external override {}
// or
function foo(uint256 _unusedParam) external override {}
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

            let is_override_or_virtual = func_def.attributes.iter().any(|attr| {
                matches!(
                    attr,
                    FunctionAttribute::Override(_, _) | FunctionAttribute::Virtual(_)
                )
            });

            if !is_override_or_virtual {
                return Vec::new();
            }

            let Some(body) = &func_def.body else {
                return Vec::new();
            };

            // Check each parameter
            let mut findings = Vec::new();
            for (loc, param_opt) in &func_def.params {
                let Some(param) = param_opt else {
                    continue;
                };

                let Some(name) = &param.name else {
                    continue;
                };

                if name.name.starts_with('_') {
                    continue;
                }

                // Check if parameter is used in the body
                let uses = find_variable_uses(&name.name, body, file);
                if uses.is_empty() {
                    findings.push(FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(loc, file),
                    });
                }
            }

            findings
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_unused_params() {
        let code = r#"
            contract Test {
                function foo(uint256 unused, uint256 alsoUnused) external override {}

                function bar(address sender, uint256 amount) public override {
                    uint256 x = 1;
                }

                function baz(uint256 a, uint256 b, uint256 c) external virtual {
                    uint256 sum = a + c;
                }

                function multi(bytes calldata data, address to) external override returns (bool) {
                    return true;
                }
            }
        "#;
        let detector = Arc::new(UnusedOverrideParamsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 7);
        assert_eq!(locations[0].line, 3, "unused");
        assert_eq!(locations[1].line, 3, "alsoUnused");
        assert_eq!(locations[2].line, 5, "sender");
        assert_eq!(locations[3].line, 5, "amount");
        assert_eq!(locations[4].line, 9, "b");
        assert_eq!(locations[5].line, 13, "data");
        assert_eq!(locations[6].line, 13, "to");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                function usesParam(uint256 x) external override {
                    uint256 y = x + 1;
                }

                function underscoreParam(uint256 _unused) external override {}

                function notOverride(uint256 unused) external {}

                function usesAllParams(uint256 a, uint256 b) public override returns (uint256) {
                    return a + b;
                }

                function usesInCall(address to) external override {
                    to.call("");
                }

                function noParams() external override {}

                constructor(uint256 unused) {}

                fallback() external {}

                receive() external payable {}
            }
        "#;
        let detector = Arc::new(UnusedOverrideParamsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
