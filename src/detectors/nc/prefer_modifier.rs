use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::ast_utils::find_in_statement;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, FunctionTy, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct PreferModifierDetector;

impl Detector for PreferModifierDetector {
    fn id(&self) -> &'static str {
        "prefer-modifier"
    }

    fn name(&self) -> &str {
        "Use a modifier for msg.sender access control"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "If a function is supposed to be access-controlled, a modifier should be used instead \
         of a require/if/assert statement for better readability."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
function withdraw() external {
    require(msg.sender == owner, "Not owner");
    // ...
}

// Good
modifier onlyOwner() {
    require(msg.sender == owner, "Not owner");
    _;
}

function withdraw() external onlyOwner {
    // ...
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func_def, file, _context| {
            if matches!(func_def.ty, FunctionTy::Modifier) {
                return Vec::new();
            }

            let Some(body) = &func_def.body else {
                return Vec::new();
            };

            let mut findings = find_in_statement(body, file, self.id(), |expr| {
                if let Expression::FunctionCall(_, func, args) = expr {
                    if let Expression::Variable(id) = func.as_ref() {
                        if (id.name == "require" || id.name == "assert") && !args.is_empty() {
                            return Self::contains_msg_sender(&args[0]);
                        }
                    }
                }
                false
            });

            if let Statement::Block { statements, .. } = body {
                for stmt in statements {
                    if let Statement::If(loc, cond, _, _) = stmt {
                        if Self::contains_msg_sender(cond) {
                            findings.push(FindingData {
                                detector_id: self.id(),
                                location: loc_to_location(loc, file),
                            });
                        }
                    }
                }
            }

            findings
        });
    }
}

impl PreferModifierDetector {
    fn contains_msg_sender(expr: &Expression) -> bool {
        match expr {
            Expression::MemberAccess(_, obj, member) => {
                if let Expression::Variable(id) = obj.as_ref() {
                    if id.name == "msg" && member.name == "sender" {
                        return true;
                    }
                }
                Self::contains_msg_sender(obj)
            }
            Expression::Equal(_, left, right)
            | Expression::NotEqual(_, left, right)
            | Expression::Or(_, left, right)
            | Expression::And(_, left, right) => {
                Self::contains_msg_sender(left) || Self::contains_msg_sender(right)
            }
            Expression::Not(_, inner) | Expression::Parenthesis(_, inner) => {
                Self::contains_msg_sender(inner)
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
    fn test_detects_msg_sender_checks() {
        let code = r#"
            contract Test {
                address owner;

                function bad1() external {
                    require(msg.sender == owner, "Not owner");
                }

                function bad2() external {
                    if (msg.sender != owner) revert();
                }

                function bad3() external {
                    assert(msg.sender == owner);
                }
            }
        "#;
        let detector = Arc::new(PreferModifierDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 6, "require msg.sender");
        assert_eq!(locations[1].line, 10, "if msg.sender");
        assert_eq!(locations[2].line, 14, "assert msg.sender");
    }

    #[test]
    fn test_skips_modifiers_and_valid_code() {
        let code = r#"
            contract Test {
                address owner;

                modifier onlyOwner() {
                    require(msg.sender == owner, "Not owner");
                    _;
                }

                function good() external onlyOwner {
                    // Uses modifier - no inline check
                }

                function otherCheck() external {
                    require(amount > 0, "Invalid");
                }
            }
        "#;
        let detector = Arc::new(PreferModifierDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
