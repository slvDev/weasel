use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Identifier};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct UnsafeLowLevelCallDetector;

impl Detector for UnsafeLowLevelCallDetector {
    fn id(&self) -> &'static str {
        "unsafe-low-level-call"
    }

    fn name(&self) -> &str {
        "`.call` bypasses function existence check, type checking and argument packing"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Low-level `.call()` operates on address types and bypasses several Solidity safety mechanisms: \
        (1) No EXTCODESIZE check - calls to non-existent contracts succeed silently instead of reverting, \
        (2) No type checking - function signatures and argument types are not validated at compile time, \
        (3) No automatic revert - failed calls return false instead of reverting, requiring manual checks. \
        High-level interface calls (e.g., `IERC20(token).transfer()`) include these protections. \
        Use `.call()` only when necessary and ensure proper validation of inputs and return values."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Flagged - low-level call bypasses safety checks
token.call(abi.encodeWithSelector(IERC20.transfer.selector, to, value));
token.call{value: msg.value}("functionSignature(uint256)");

// Safe - empty data just sends ETH
to.call{value: value}("");

// Better - high-level interface call has:
// - EXTCODESIZE check (reverts if no contract)
// - Type checking at compile time
// - Automatic revert on failure
IVault(vault).deposit(amount, receiver);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func_expr, args) = expr {
                // Check for .call with optional block (e.g., {value: x})
                // Skip contract type casts like ISomeContract(addr).call() - high-level interface call
                // But flag address casts like payable(addr).call() or address(x).call() - still low-level
                let is_low_level_call = match func_expr.as_ref() {
                    Expression::MemberAccess(_, base, Identifier { name, .. }) => {
                        name == "call" && !is_contract_type_cast(base)
                    }
                    Expression::FunctionCallBlock(_, inner, _) => {
                        if let Expression::MemberAccess(_, base, Identifier { name, .. }) =
                            inner.as_ref()
                        {
                            name == "call" && !is_contract_type_cast(base)
                        } else {
                            false
                        }
                    }
                    _ => false,
                };

                if is_low_level_call && has_non_empty_data(args) {
                    return FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(loc, file),
                    }
                    .into();
                }
            }
            Vec::new()
        });
    }
}

/// Check if expression is a contract type cast like ISomeContract(addr)
/// Returns false for address casts like address(x) or payable(x)
fn is_contract_type_cast(expr: &Expression) -> bool {
    if let Expression::FunctionCall(_, func, _) = expr {
        // Contract type cast: ISomeContract(addr) - func is Variable
        // Address type cast: address(x), payable(x) - func is Type
        matches!(func.as_ref(), Expression::Variable(_))
    } else {
        false
    }
}

/// Check if call has non-empty data (not just sending ETH)
fn has_non_empty_data(args: &[Expression]) -> bool {
    match args.first() {
        // Empty string literal "" - just sending ETH
        Some(Expression::StringLiteral(literals)) => {
            literals
                .first()
                .map(|lit| !lit.string.is_empty())
                .unwrap_or(false)
        }
        // Any other expression (abi.encode*, variables, etc.)
        Some(_) => true,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_unsafe_low_level_calls() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(address token, address to, uint256 value, bytes calldata data) public {
                    token.call(abi.encodeWithSelector(IERC20.transfer.selector, to, value));
                    token.call{value: msg.value}("anyString");
                    // Address casts are still low-level calls
                    payable(to).call(data);
                    address(this).call{value: value}(data);
                }
            }
        "#;

        let detector = Arc::new(UnsafeLowLevelCallDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].line, 6, "abi.encodeWithSelector call");
        assert_eq!(locations[1].line, 7, "non-empty string call");
        assert_eq!(locations[2].line, 9, "payable(to).call");
        assert_eq!(locations[3].line, 10, "address(this).call");
    }

    #[test]
    fn test_skips_safe_patterns() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(address to, uint256 value, bytes calldata data) public {
                    // Empty call data - just sending ETH
                    to.call{value: value}("");
                    to.call("");

                    // High-level interface call (type cast) - .call() on contract type
                    // is a function defined in interface, not low-level call
                    ISomeContract(to).call(data);
                    ISomeContract(to).call{value: value}(data);
                }
            }
        "#;

        let detector = Arc::new(UnsafeLowLevelCallDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
