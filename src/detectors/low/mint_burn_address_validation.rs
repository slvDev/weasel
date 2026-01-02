use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use crate::core::visitor::ASTVisitor;
use solang_parser::pt::{Expression, Statement, Type};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct MintBurnAddressValidationDetector;

impl Detector for MintBurnAddressValidationDetector {
    fn id(&self) -> &'static str {
        "mint-burn-address-validation"
    }

    fn name(&self) -> &str {
        "Prevent accidentally burning tokens"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Calls to mint/burn functions should validate that the address parameter is not address(0) \
         to prevent accidentally minting to or burning from the zero address. While most ERC20/ERC721 \
         implementations include internal checks, external wrappers and custom implementations may not. \
         Always validate address parameters with `require(addr != address(0))` before calling mint/burn."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no zero address check before mint
function mintTokens(address to, uint256 amount) public {
    _mint(to, amount);
}

// Good - validates address before mint
function mintTokens(address to, uint256 amount) public {
    require(to != address(0), "Cannot mint to zero address");
    _mint(to, amount);
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
                if let Expression::FunctionCall(_, func, args) = expr {
                    if let Some(name) = Self::get_function_name(func.as_ref()) {
                        let name_lower = name.to_lowercase();
                        if name_lower.contains("mint") || name_lower.contains("burn") {
                            if let Some(first_arg) = args.first() {
                                if let Some(var_name) = Self::get_variable_name(first_arg) {
                                    return !Self::find_address_validation(body, var_name);
                                }
                            }
                        }
                    }
                }
                false
            })
        });
    }
}

impl MintBurnAddressValidationDetector {
    fn get_function_name(expr: &Expression) -> Option<&str> {
        match expr {
            Expression::Variable(id) => Some(&id.name),
            Expression::MemberAccess(_, _, member) => Some(&member.name),
            _ => None,
        }
    }

    fn get_variable_name(expr: &Expression) -> Option<&str> {
        match expr {
            Expression::Variable(id) => Some(&id.name),
            _ => None,
        }
    }

    fn find_address_validation(stmt: &Statement, var_name: &str) -> bool {
        match stmt {
            Statement::Block { statements, .. } => {
                statements.iter().any(|s| Self::find_address_validation(s, var_name))
            }
            Statement::Expression(_, expr) => Self::expr_has_address_validation(expr, var_name),
            Statement::If(_, cond, then_stmt, else_stmt) => {
                Self::expr_has_address_validation(cond, var_name)
                    || Self::find_address_validation(then_stmt, var_name)
                    || else_stmt.as_ref().map_or(false, |s| Self::find_address_validation(s, var_name))
            }
            Statement::While(_, cond, body) => {
                Self::expr_has_address_validation(cond, var_name) || Self::find_address_validation(body, var_name)
            }
            Statement::DoWhile(_, body, cond) => {
                Self::find_address_validation(body, var_name) || Self::expr_has_address_validation(cond, var_name)
            }
            Statement::For(_, _, cond, _, body) => {
                cond.as_ref().map_or(false, |c| Self::expr_has_address_validation(c, var_name))
                    || body.as_ref().map_or(false, |b| Self::find_address_validation(b, var_name))
            }
            Statement::Return(_, Some(expr)) => Self::expr_has_address_validation(expr, var_name),
            _ => false,
        }
    }

    fn expr_has_address_validation(expr: &Expression, var_name: &str) -> bool {
        match expr {
            // != address(0) or == address(0)
            Expression::NotEqual(_, left, right) | Expression::Equal(_, left, right) => {
                (Self::is_variable_named(left, var_name) && Self::is_address_zero(right))
                    || (Self::is_address_zero(left) && Self::is_variable_named(right, var_name))
            }
            // require/assert/revert with the check
            Expression::FunctionCall(_, _, args) => {
                args.iter().any(|arg| Self::expr_has_address_validation(arg, var_name))
            }
            // logical operators
            Expression::And(_, left, right) | Expression::Or(_, left, right) => {
                Self::expr_has_address_validation(left, var_name) || Self::expr_has_address_validation(right, var_name)
            }
            Expression::Not(_, inner) => Self::expr_has_address_validation(inner, var_name),
            _ => false,
        }
    }

    fn is_variable_named(expr: &Expression, name: &str) -> bool {
        matches!(expr, Expression::Variable(id) if id.name == name)
    }

    fn is_address_zero(expr: &Expression) -> bool {
        // Match address(0) pattern
        if let Expression::FunctionCall(_, func, args) = expr {
            if let Expression::Type(_, Type::Address | Type::AddressPayable) = func.as_ref() {
                if let Some(arg) = args.first() {
                    if let Expression::NumberLiteral(_, val, _, _) = arg {
                        return val == "0";
                    }
                }
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
    fn test_detects_unvalidated_mint_burn() {
        let code = r#"
            contract Test {
                function mintWithoutCheck(address to, uint256 amount) public {
                    _mint(to, amount);
                }

                function burnWithoutCheck(address from, uint256 amount) public {
                    _burn(from, amount);
                }

                function safeMintNoCheck(address to, uint256 tokenId) public {
                    _safeMint(to, tokenId);
                }

                function externalMint(address to, uint256 amount) public {
                    token.mint(to, amount);
                }

                function multipleMints(address to, address from, uint256 amount) public {
                    _mint(to, amount);
                    _burn(from, amount);
                }

                function _mint(address to, uint256 amount) internal {}
                function _burn(address from, uint256 amount) internal {}
                function _safeMint(address to, uint256 tokenId) internal {}
            }
        "#;
        let detector = Arc::new(MintBurnAddressValidationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 6);
        assert_eq!(locations[0].line, 4, "_mint(to, amount)");
        assert_eq!(locations[1].line, 8, "_burn(from, amount)");
        assert_eq!(locations[2].line, 12, "_safeMint(to, tokenId)");
        assert_eq!(locations[3].line, 16, "token.mint(to, amount)");
        assert_eq!(locations[4].line, 20, "_mint(to, amount)");
        assert_eq!(locations[5].line, 21, "_burn(from, amount)");
    }

    #[test]
    fn test_skips_validated_mint_burn() {
        let code = r#"
            contract Test {
                function mintWithRequire(address to, uint256 amount) public {
                    require(to != address(0), "Zero address");
                    _mint(to, amount);
                }

                function burnWithIf(address from, uint256 amount) public {
                    if (from == address(0)) revert();
                    _burn(from, amount);
                }

                function mintWithAssert(address to, uint256 amount) public {
                    assert(to != address(0));
                    _mint(to, amount);
                }

                function mintWithLogic(address to, uint256 amount, bool flag) public {
                    require(flag && to != address(0), "Invalid");
                    _mint(to, amount);
                }

                function mintWithReversedCheck(address to, uint256 amount) public {
                    require(address(0) != to, "Zero");
                    _mint(to, amount);
                }

                function mintToSender(uint256 amount) public {
                    _mint(msg.sender, amount);
                }

                function mintToThis(uint256 amount) public {
                    _mint(address(this), amount);
                }

                function _mint(address to, uint256 amount) internal {}
                function _burn(address from, uint256 amount) internal {}
            }
        "#;
        let detector = Arc::new(MintBurnAddressValidationDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
