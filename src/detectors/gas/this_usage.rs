use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ThisUsageDetector;

impl Detector for ThisUsageDetector {
    fn id(&self) -> &'static str {
        "this-usage"
    }

    fn name(&self) -> &str {
        "Use of `this` instead of marking as `public` an `external` function"
    }

    fn severity(&self) -> Severity {
        Severity::Gas
    }

    fn description(&self) -> &str {
        "Using `this.` is like making an expensive external call. Consider marking the called \
        function as `public` instead of `external` so it can be called internally without the \
        external call overhead.\n\n\
        *Saves around 2000 gas per instance*"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - expensive external call via `this`
contract Bad {
    function externalFunc() external pure returns (uint256) {
        return 42;
    }

    function caller() external pure returns (uint256) {
        return this.externalFunc(); // ~2000 gas overhead
    }
}

// Good - direct internal call with `public`
contract Good {
    function publicFunc() public pure returns (uint256) {
        return 42;
    }

    function caller() external pure returns (uint256) {
        return publicFunc(); // Direct call, much cheaper
    }
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            let mut findings = Vec::new();

            if let Expression::FunctionCall(loc, func_expr, _) = expr {
                if let Expression::MemberAccess(_, inner, _) = func_expr.as_ref() {
                    if matches!(inner.as_ref(), Expression::Variable(var) if var.name == "this") {
                        findings.push(FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(loc, file),
                        });
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
    fn test_detects_issues() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function externalFunc() external pure returns (uint256) {
                    return 42;
                }

                function anotherExternal(uint256 x) external pure returns (uint256) {
                    return x * 2;
                }

                function caller() external pure returns (uint256) {
                    // Both should be flagged
                    uint256 a = this.externalFunc();
                    uint256 b = this.anotherExternal(10);
                    return a + b;
                }

                function multipleCalls() external pure returns (uint256) {
                    return this.externalFunc() + this.anotherExternal(5);
                }
            }
        "#;

        let detector = Arc::new(ThisUsageDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].line, 15, "this.externalFunc()");
        assert_eq!(locations[1].line, 16, "this.anotherExternal(10)");
        assert_eq!(locations[2].line, 21, "first this.externalFunc()");
        assert_eq!(locations[3].line, 21, "second this.anotherExternal(5)");
    }

    #[test]
    fn test_skips_valid_cases() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function externalFunc() external pure returns (uint256) {
                    return 42;
                }

                function publicFunc() public pure returns (uint256) {
                    return 100;
                }

                function validCases() external pure returns (bytes4, uint256, address) {
                    // Direct call to public function - no issue
                    uint256 x = publicFunc();

                    // Getting function selector - not a call, no issue
                    bytes4 sig = this.externalFunc.selector;

                    // Getting contract address - no issue
                    address addr = address(this);

                    return (sig, x, addr);
                }
            }
        "#;

        let detector = Arc::new(ThisUsageDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 0);
    }
}
