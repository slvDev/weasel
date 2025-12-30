use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnlimitedGasCallDetector;

impl Detector for UnlimitedGasCallDetector {
    fn id(&self) -> &'static str {
        "unlimited-gas-call"
    }

    fn name(&self) -> &str {
        "External call recipient may consume all transaction gas"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "There is no limit specified on the amount of gas used, so the recipient can use up all \
         of the transaction's gas, causing it to revert. Use `addr.call{gas: <amount>}(\"\")` or \
         this library instead: https://github.com/nomad-xyz/ExcessivelySafeCall"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - no gas limit
function forward(address recipient, bytes memory data) external {
    recipient.call(data);
}

// Good - with gas limit
function forward(address recipient, bytes memory data) external {
    recipient.call{gas: 10000}(data);
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            match expr {
                // .call{...}(...)
                Expression::FunctionCallBlock(_, func_expr, block) => {
                    if let Expression::MemberAccess(_, obj, member) = func_expr.as_ref() {
                        if member.name == "call" && !Self::is_this_call(obj) {
                            // Check if gas is specified in the options
                            if !Self::has_gas_option(block) {
                                return FindingData {
                                    detector_id: self.id(),
                                    location: loc_to_location(&member.loc, file),
                                }
                                .into();
                            }
                        }
                    }
                }
                // .call(...)
                Expression::FunctionCall(_, func_expr, _) => {
                    if let Expression::MemberAccess(_, obj, member) = func_expr.as_ref() {
                        if member.name == "call" && !Self::is_this_call(obj) {
                            return FindingData {
                                detector_id: self.id(),
                                location: loc_to_location(&member.loc, file),
                            }
                            .into();
                        }
                    }
                }
                _ => {}
            }
            Vec::new()
        });
    }
}

impl UnlimitedGasCallDetector {
    fn has_gas_option(block: &Statement) -> bool {
        match block {
            Statement::Args(_, args) => args.iter().any(|arg| arg.name.name == "gas"),
            _ => false,
        }
    }

    fn is_this_call(expr: &Expression) -> bool {
        match expr {
            // Direct this
            Expression::Variable(ident) if ident.name == "this" => true,
            // address(this)
            Expression::FunctionCall(_, func, args) => {
                if let Expression::Type(_, _) = func.as_ref() {
                    if let Some(arg) = args.first() {
                        if let Expression::Variable(ident) = arg {
                            return ident.name == "this";
                        }
                    }
                }
                false
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
    fn test_detects_unlimited_gas_call() {
        let code = r#"
            contract Test {
                function forward(address recipient, bytes memory data) external {
                    recipient.call(data);
                    recipient.call{value: 1 ether}(data);
                }
            }
        "#;
        let detector = Arc::new(UnlimitedGasCallDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 4, "call without any options");
        assert_eq!(locations[1].line, 5, "call with value but no gas");
    }

    #[test]
    fn test_skips_this_call() {
        let code = r#"
            contract Test {
                function executeInternal(bytes memory data) internal {
                    this.call(data);
                }

                function executeInternalCast(bytes memory data) internal {
                    address(this).call(data);
                }
                
                function forwardWithGas(address recipient, bytes memory data) external {
                    recipient.call{gas: 10000}(data);
                    recipient.call{gas: 10000, value: 1 ether}(data);
                }
            }
        "#;
        let detector = Arc::new(UnlimitedGasCallDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
