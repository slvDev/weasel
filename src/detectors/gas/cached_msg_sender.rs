use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_statement_types;
use solang_parser::pt::{Expression, Identifier, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct CachedMsgSenderDetector;

impl Detector for CachedMsgSenderDetector {
    fn id(&self) -> &'static str {
        "cached-msg-sender"
    }

    fn name(&self) -> &str {
        "Call `msg.sender` directly instead of caching it"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Caching `msg.sender` in a local variable adds unnecessary stack manipulation. \
        Calling `msg.sender` directly is cheaper."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - 3061 gas
function bad() external {
    address callerLocal = msg.sender;
    internalFunc(callerLocal);
    internalFunc(callerLocal);
}

// Good - 3047 gas
function good() external {
    internalFunc(msg.sender);
    internalFunc(msg.sender);
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_function(move |func, file, _context| {
            let Some(body) = &func.body else {
                return Vec::new();
            };

            find_statement_types(body, file, self.id(), |stmt| {
                if let Statement::VariableDefinition(_, _, Some(init)) = stmt {
                    if let Expression::MemberAccess(_, left, Identifier { name: member, .. }) = init
                    {
                        if let Expression::Variable(Identifier { name: obj, .. }) = left.as_ref() {
                            return obj == "msg" && member == "sender";
                        }
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
    fn test_detects_cached_msg_sender() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test() public {
                    address addr = msg.sender;
                }
            }
        "#;

        let detector = Arc::new(CachedMsgSenderDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 6, "address addr = msg.sender");
    }

    #[test]
    fn test_skips_direct_usage() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test() public {
                    require(msg.sender != address(0));
                }
            }
        "#;

        let detector = Arc::new(CachedMsgSenderDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
