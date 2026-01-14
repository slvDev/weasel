use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use solang_parser::pt::{Expression, FunctionTy, Identifier, Type};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct AddressThisPrecalculationDetector;

impl Detector for AddressThisPrecalculationDetector {
    fn id(&self) -> &'static str {
        "address-this-precalculation"
    }

    fn name(&self) -> &str {
        "Consider pre-calculating the address of `address(this)`"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Using `address(this)` requires computing the contract address at runtime which costs gas. \
        Consider pre-calculating the address using Foundry's script.sol or Solady's LibRlp.sol \
        and storing it in a constant to avoid the gas overhead of computing it each time."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - computes address(this) at runtime
function getBalance() external view returns (uint256) {
    return token.balanceOf(address(this));
}

// Good - use pre-calculated constant
address private constant SELF = 0x1234...;

function getBalance() external view returns (uint256) {
    return token.balanceOf(SELF);
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func, file, _context| {
            // Skip constructors - address(this) is sometimes needed there
            if matches!(func.ty, FunctionTy::Constructor) {
                return Vec::new();
            }

            let Some(body) = &func.body else {
                return Vec::new();
            };

            find_in_statement(body, file, self.id(), |expr| {
                if let Expression::FunctionCall(_, func, args) = expr {
                    if matches!(func.as_ref(), Expression::Type(_, Type::Address)) {
                        return matches!(args.first(), Some(Expression::Variable(Identifier { name, .. })) if name == "this");
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
    fn test_detects_address_this() {
        let code = r#"
            pragma solidity ^0.8.0;

            interface IERC20 {
                function balanceOf(address) external view returns (uint256);
            }

            contract Test {
                IERC20 token;

                function getBalance() external view returns (uint256) {
                    return token.balanceOf(address(this));
                }

                function multipleUses() external view returns (bool) {
                    require(isValid(address(this)));
                    return address(this) != address(0);
                }
            }
        "#;

        let detector = Arc::new(AddressThisPrecalculationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 12, "token.balanceOf(address(this))");
        assert_eq!(locations[1].line, 16, "isValid(address(this))");
        assert_eq!(locations[2].line, 17, "address(this) != address(0)");
    }

    #[test]
    fn test_skips_constructor() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                address immutable self;

                constructor() {
                    self = address(this);
                }

                function getSelf() external view returns (address) {
                    return self;
                }
            }
        "#;

        let detector = Arc::new(AddressThisPrecalculationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
