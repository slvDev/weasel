use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use crate::core::visitor::ASTVisitor;
use solang_parser::pt::{Expression, FunctionTy, Identifier};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ExternalCallInModifierDetector;

impl Detector for ExternalCallInModifierDetector {
    fn id(&self) -> &'static str {
        "external-call-in-modifier"
    }

    fn name(&self) -> &str {
        "Avoid external calls in modifiers"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "It is unusual to have external calls in modifiers, and doing so will make reviewers \
         more likely to miss important external interactions. Consider moving the external call \
         to an internal function, and calling that function from the modifier."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - external call in modifier
modifier onlyOwner() {
    require(ERC721(nft).ownerOf(tokenId) == msg.sender);
    _;
}

// Good - move external call to internal function
function _checkOwner() internal view {
    require(ERC721(nft).ownerOf(tokenId) == msg.sender);
}

modifier onlyOwner() {
    _checkOwner();
    _;
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            // Only check modifiers
            if !matches!(func_def.ty, FunctionTy::Modifier) {
                return Vec::new();
            }

            let Some(body) = &func_def.body else {
                return Vec::new();
            };

            find_in_statement(body, file, self.id(), |expr| {
                Self::is_external_call(expr)
            })
        });
    }
}

impl ExternalCallInModifierDetector {
    fn is_external_call(expr: &Expression) -> bool {
        if let Expression::FunctionCall(_, func_expr, _) = expr {
            if let Expression::MemberAccess(_, base_expr, _) = func_expr.as_ref() {
                // Skip this.something() calls - those are internal
                if matches!(base_expr.as_ref(), Expression::Variable(Identifier { name, .. }) if name == "this")
                {
                    return false;
                }
                return true;
            }
        }
        false
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
                modifier onlyOwner() {
                    require(ERC721(nft).ownerOf(tokenId) == msg.sender);  // Line 6 - external call
                    require(token.balanceOf(msg.sender) > 0);             // Line 7 - external call
                    _;
                }

                modifier checkBalance() {
                    require(vault.getBalance() > minAmount);              // Line 12 - external call
                    _;
                }
            }
        "#;
        let detector = Arc::new(ExternalCallInModifierDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3, "Should detect 3 issues");
        assert_eq!(locations[0].line, 6, "ERC721 ownerOf call");
        assert_eq!(locations[1].line, 7, "token balanceOf call");
        assert_eq!(locations[2].line, 12, "vault getBalance call");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                // this.something() calls are internal - OK
                modifier onlyOwner() {
                    require(msg.sender == this.getOwner());
                    _;
                }

                // Regular function with external call - OK (not a modifier)
                function checkOwner() internal view {
                    require(ERC721(nft).ownerOf(tokenId) == msg.sender);
                }

                // Modifier with only internal calls - OK
                modifier nonReentrant() {
                    require(!locked);
                    locked = true;
                    _;
                    locked = false;
                }

                // Modifier calling internal function - OK
                modifier onlyAdmin() {
                    _checkAdmin();
                    _;
                }
            }
        "#;
        let detector = Arc::new(ExternalCallInModifierDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
