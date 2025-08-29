use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::{ast_utils, location::loc_to_location};
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, FunctionTy, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnboundedFeeDetector;

impl Detector for UnboundedFeeDetector {
    fn id(&self) -> &'static str {
        "unbounded-fee"
    }

    fn name(&self) -> &str {
        "Fees can be set to be greater than 100%"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &str {
        "There should be an upper limit to reasonable fees. A malicious owner can keep the fee rate at zero, \
        but if a large value transfer enters the mempool, the owner can jack the rate up to the maximum \
        and sandwich attack a user. Fee-setting functions should validate that fees don't exceed reasonable limits."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no validation:
function setFee(uint256 _fee) external onlyOwner {
    fee = _fee;
}

// Good - has validation:
function setFee(uint256 _fee) external onlyOwner {
    require(_fee <= 1000, "Fee too high"); // Max 10%
    fee = _fee;
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            // Skip constructors and virtual functions
            if matches!(func_def.ty, FunctionTy::Constructor) {
                return Vec::new();
            }
            
            // Check if virtual
            if ast_utils::is_function_virtual(func_def) {
                return Vec::new();
            }
            
            // Check if it's view or pure (can't modify state)
            if ast_utils::is_function_readonly(func_def) {
                return Vec::new();
            }
            
            // Check if function name contains "fee" (case-insensitive)
            let func_name = func_def.name.as_ref().map(|n| n.name.to_lowercase()).unwrap_or_default();
            if !func_name.contains("fee") {
                return Vec::new();
            }
            
            // Check if function has validation
            if let Some(body) = &func_def.body {
                if self.has_validation(body) {
                    return Vec::new();
                }
            } else {
                // No body, can't set fees
                return Vec::new();
            }
            
            // Report finding at function name location
            let loc = if let Some(name) = &func_def.name {
                name.loc
            } else {
                func_def.loc_prototype
            };
            
            FindingData {
                detector_id: self.id(),
                location: loc_to_location(&loc, file),
            }
            .into()
        });
    }
}

impl UnboundedFeeDetector {
    fn has_validation(&self, stmt: &Statement) -> bool {
        match stmt {
            // If statement indicates validation logic
            Statement::If(_, _, _, _) => true,
            
            // Check for require/assert/revert in expressions
            Statement::Expression(_, expr) => self.has_validation_expr(expr),
            
            // Check block statements recursively
            Statement::Block { statements, .. } => {
                statements.iter().any(|s| self.has_validation(s))
            }
            
            // Check other control flow statements
            Statement::While(_, _, body) | Statement::DoWhile(_, body, _) => {
                self.has_validation(body)
            }
            
            Statement::For(_, _, _, _, body_opt) => {
                if let Some(body) = body_opt {
                    self.has_validation(body)
                } else {
                    false
                }
            }
            
            Statement::Return(_, Some(expr)) => self.has_validation_expr(expr),
            
            _ => false,
        }
    }
    
    fn has_validation_expr(&self, expr: &Expression) -> bool {
        match expr {
            // Look for require, assert, revert calls
            Expression::FunctionCall(_, func, _) => {
                if let Expression::Variable(ident) = func.as_ref() {
                    let name = &ident.name;
                    if name == "require" || name == "assert" || name == "revert" {
                        return true;
                    }
                }
                false
            }
            
            // Check nested expressions
            Expression::Assign(_, left, right) => {
                self.has_validation_expr(left) || self.has_validation_expr(right)
            }
            
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_unbounded_fee() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            contract FeeContract {
                uint256 public fee;
                uint256 public taxFee;
                
                // Should detect - no validation
                function setFee(uint256 _fee) external {
                    fee = _fee;
                }
                
                // Should detect - no validation
                function updateTaxFee(uint256 _taxFee) public {
                    taxFee = _taxFee;
                }
                
                // Should NOT detect - has require validation
                function setFeeWithValidation(uint256 _fee) external {
                    require(_fee <= 1000, "Fee too high");
                    fee = _fee;
                }
                
                // Should NOT detect - has if statement validation
                function setFeeWithIf(uint256 _fee) external {
                    if (_fee > 1000) {
                        revert("Fee too high");
                    }
                    fee = _fee;
                }
                
                // Should NOT detect - has assert validation
                function setFeeWithAssert(uint256 _fee) external {
                    assert(_fee <= 1000);
                    fee = _fee;
                }
                
                // Should NOT detect - view function
                function getFee() external view returns (uint256) {
                    return fee;
                }
                
                // Should NOT detect - no "fee" in name
                function setValue(uint256 value) external {
                    someValue = value;
                }
            }
        "#;

        let detector = Arc::new(UnboundedFeeDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 unbounded fee setters");
        assert_eq!(locations[0].line, 9, "setFee function");
        assert_eq!(locations[1].line, 14, "updateTaxFee function");
    }

    #[test]
    fn test_interface_skip() {
        let code = r#"
            pragma solidity ^0.8.0;
            
            interface IFeeContract {
                function setFee(uint256 _fee) external;
            }
            
            contract Test {
                // Should NOT detect - pure function
                function calculateFee(uint256 amount) external pure returns (uint256) {
                    return amount * 10 / 100;
                }
            }
        "#;

        let detector = Arc::new(UnboundedFeeDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0, "Should not detect in interfaces or pure functions");
    }
}