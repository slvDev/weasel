use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::is_function_virtual;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{ContractPart, ContractTy, FunctionTy, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct EmptyFunctionBodyDetector;

impl Detector for EmptyFunctionBodyDetector {
    fn id(&self) -> &'static str {
        "empty-function-body"
    }

    fn name(&self) -> &str {
        "Empty Function Body - Consider commenting why"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Functions with empty bodies should have comments explaining why they are empty. \
         Empty functions without documentation can indicate incomplete code or unclear intent. \
         Consider adding NatSpec comments to explain the purpose of empty functions."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - empty function without explanation
function beforeTokenTransfer(address from, address to, uint256 amount) internal {
}

// Good - empty function with clear documentation
/// @notice Hook that is called before token transfers
/// @dev Intentionally left empty - no special transfer logic needed
function beforeTokenTransfer(address from, address to, uint256 amount) internal {
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            if matches!(contract_def.ty, ContractTy::Interface(_)) {
                return Vec::new();
            }

            let mut findings = Vec::new();

            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    if matches!(
                        func_def.ty,
                        FunctionTy::Constructor | FunctionTy::Fallback | FunctionTy::Receive
                    ) {
                        continue;
                    }

                    if is_function_virtual(func_def) {
                        continue;
                    }

                    if let Some(name) = &func_def.name {
                        let is_empty = match &func_def.body {
                            None => true,
                            Some(Statement::Block { statements, .. }) => statements.is_empty(),
                            _ => false,
                        };

                        if is_empty {
                            findings.push(FindingData {
                                detector_id: self.id(),
                                location: loc_to_location(&name.loc, file),
                            });
                        }
                    }
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
    fn test_detects_empty_function_body() {
        let code = r#"
            contract Test {
                function emptyFunc() public {
                }

                function notEmpty() public {
                    uint x = 1;
                }
            }
        "#;
        let detector = Arc::new(EmptyFunctionBodyDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 3, "empty function");
    }

    #[test]
    fn test_skips_valid_cases() {
        let code = r#"
            interface ITest {
                function test() external;
            }

            contract Test {
                constructor() {
                }

                fallback() external payable {
                }

                receive() external payable {
                }

                function virtualFunc() public virtual {
                }

                function notEmpty() public {
                    uint x = 1;
                }
            }
        "#;
        let detector = Arc::new(EmptyFunctionBodyDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
