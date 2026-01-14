use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::find_in_statement;
use solang_parser::pt::{Expression, Identifier};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct AssemblyAbiDecodeDetector;

impl Detector for AssemblyAbiDecodeDetector {
    fn id(&self) -> &'static str {
        "assembly-abi-decode"
    }

    fn name(&self) -> &str {
        "Use assembly instead of abi.decode to extract calldata values more efficiently"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Instead of using abi.decode, we can use assembly to decode our desired calldata values \
        directly. This allows avoiding decoding calldata values that we will not use."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - decodes all values even if some are unused
(uint256 foo, ) = abi.decode(data, (uint256, address));

// Good - use assembly to decode only what you need
uint256 foo;
assembly {
    foo := calldataload(4)
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

            find_in_statement(body, file, self.id(), |expr| {
                if let Expression::Assign(_, left, right) = expr {
                    // Check if left side is a tuple with empty slots
                    if let Expression::List(_, list) = left.as_ref() {
                        let has_empty_param = list.iter().any(|(_, param)| param.is_none());
                        if !has_empty_param {
                            return false;
                        }

                        // Check if right side is abi.decode
                        if let Expression::FunctionCall(_, func_expr, _) = right.as_ref() {
                            if let Expression::MemberAccess(_, obj, Identifier { name, .. }) =
                                func_expr.as_ref()
                            {
                                if name == "decode" {
                                    if let Expression::Variable(Identifier { name: obj_name, .. }) =
                                        obj.as_ref()
                                    {
                                        return obj_name == "abi";
                                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_abi_decode_with_empty_slots() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(bytes calldata data) public {
                    (uint256 foo, ) = abi.decode(data, (uint256, address));
                }
            }
        "#;

        let detector = Arc::new(AssemblyAbiDecodeDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].line, 6, "(uint256 foo, ) = abi.decode");
    }

    #[test]
    fn test_skips_full_decode() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(bytes calldata data) public {
                    (uint256 foo, address bar) = abi.decode(data, (uint256, address));
                }
            }
        "#;

        let detector = Arc::new(AssemblyAbiDecodeDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
