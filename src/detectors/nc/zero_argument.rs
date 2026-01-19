use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use solang_parser::pt::{ContractPart, Expression};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ZeroArgumentDetector;

impl Detector for ZeroArgumentDetector {
    fn id(&self) -> &'static str {
        "zero-argument"
    }

    fn name(&self) -> &str {
        "Consider using descriptive constants when passing zero as argument"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "When passing zero as a function argument, consider using descriptive constants or an \
         enum instead. This aids in articulating the caller's intention and minimizes errors."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - unclear intent
transfer(recipient, 0);

// Good - clear intent
uint256 constant NO_AMOUNT = 0;
transfer(recipient, NO_AMOUNT);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            let mut findings = Vec::new();

            for part in &contract_def.parts {
                if let ContractPart::FunctionDefinition(func_def) = part {
                    if let Some(body) = &func_def.body {
                        let calls = find_in_statement(body, file, self.id(), |expr| {
                            if let Expression::FunctionCall(_, func_expr, args) = expr {
                                // Skip type casts
                                if matches!(func_expr.as_ref(), Expression::Type(_, _)) {
                                    return false;
                                }

                                // Skip abi.encode* functions
                                if let Expression::MemberAccess(_, base, member) = func_expr.as_ref()
                                {
                                    if let Expression::Variable(id) = base.as_ref() {
                                        if id.name == "abi" && member.name.contains("encode") {
                                            return false;
                                        }
                                    }
                                }

                                // Check if any argument is literal 0
                                return args.iter().any(|arg| {
                                    matches!(arg, Expression::NumberLiteral(_, num, _, _) if num == "0")
                                });
                            }
                            false
                        });
                        findings.extend(calls);
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
    fn test_detects_issue() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test() public {
                    anyFunction(zero, 0);       // Line 6 - literal 0 argument
                    transfer(recipient, 0);     // Line 7 - literal 0 argument
                }
            }
        "#;
        let detector = Arc::new(ZeroArgumentDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 calls with zero argument");
        assert_eq!(locations[0].line, 6, "anyFunction");
        assert_eq!(locations[1].line, 7, "transfer");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                uint256 constant NO_AMOUNT = 0;

                function test() public {
                    transfer(recipient, NO_AMOUNT);     // constant - OK
                    abi.encode(0);                      // encode - OK
                    abi.encodePacked(0, data);          // encodePacked - OK
                    uint256(0);                         // type cast - OK
                }
            }
        "#;
        let detector = Arc::new(ZeroArgumentDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not flag constants, encodes, or casts");
    }
}
