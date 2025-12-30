use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use crate::core::visitor::ASTVisitor;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DeprecatedSetupRoleDetector;

impl Detector for DeprecatedSetupRoleDetector {
    fn id(&self) -> &'static str {
        "deprecated-setup-role"
    }

    fn name(&self) -> &str {
        "Do not use deprecated `_setupRole` function"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "The `_setupRole` function in OpenZeppelin's AccessControl has been deprecated in favor of \
         `_grantRole`. Since both functions are internal and `_setupRole` just calls `_grantRole`, \
         having both with the same visibility makes `_setupRole` redundant. Using deprecated functions \
         may lead to potential future incompatibilities with OpenZeppelin's contracts library. \
         Use `_grantRole` instead."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - uses deprecated _setupRole
contract MyContract is AccessControl {
    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }
}

// Good - uses _grantRole
contract MyContract is AccessControl {
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            let Some(body) = &func_def.body else {
                return Vec::new();
            };

            find_in_statement(body, file, self.id(), |expr| {
                if let Expression::FunctionCall(_, func_expr, _) = expr {
                    if let Expression::Variable(ident) = func_expr.as_ref() {
                        return ident.name == "_setupRole";
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
    fn test_detects_setup_role() {
        let code = r#"
            import "@openzeppelin/contracts/access/AccessControl.sol";

            contract Test is AccessControl {
                constructor() {
                    _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
                }
            }
        "#;
        let detector = Arc::new(DeprecatedSetupRoleDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 6, "_setupRole call");
    }

    #[test]
    fn test_skips_grant_role() {
        let code = r#"
            import "@openzeppelin/contracts/access/AccessControl.sol";

            contract Test is AccessControl {
                constructor() {
                    _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
                }
            }
        "#;
        let detector = Arc::new(DeprecatedSetupRoleDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
