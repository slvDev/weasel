use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::ast_utils::is_external_call;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::Expression;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct NamedFunctionArgsDetector;

impl Detector for NamedFunctionArgsDetector {
    fn id(&self) -> &'static str {
        "named-function-args"
    }

    fn name(&self) -> &str {
        "Consider using named function arguments"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "When calling functions in external contracts with multiple arguments, consider using \
         named function parameters rather than positional ones. This improves code readability \
         and reduces the risk of argument order mistakes."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - positional arguments
token.safeTransferFrom(from, to, amount, data);

// Good - named arguments
token.safeTransferFrom({
    from: from,
    to: to,
    value: amount,
    data: data
});
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, _, args) = expr {
                // Only check calls with 4+ arguments
                if args.len() < 4 {
                    return Vec::new();
                }

                // Only check external calls (excludes abi.*, super.*, this.*, push, pop, etc.)
                if !is_external_call(expr) {
                    return Vec::new();
                }

                return FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(loc, file),
                }
                .into();
            }
            Vec::new()
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
                function test(address addr, address token) public {
                    token.safeTransferFrom(a, b, c, d);            // Line 6 - 4 args
                    addr.complexCall(one, two, three, four, five); // Line 7 - 5 args
                }
            }
        "#;
        let detector = Arc::new(NamedFunctionArgsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");

        assert_eq!(locations.len(), 2, "Should detect 2 issues");
        assert_eq!(locations[0].line, 6, "safeTransferFrom with 4 args");
        assert_eq!(locations[1].line, 7, "complexCall with 5 args");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                function test(address addr) public {
                    addr.singleArg(one);                           // 1 arg - OK
                    addr.twoArgs(one, two);                        // 2 args - OK
                    addr.threeArgs(one, two, three);               // 3 args - OK
                    abi.encode(a, b, c, d, e);                     // abi.* - OK
                    super.test(a, b, c, d);                        // super.* - OK
                    this.doSomething(a, b, c, d);                  // this.* - OK
                    internalCall(a, b, c, d);                      // Not member access - OK
                    arr.push(elem);                                // Built-in - OK
                }

                function internalCall(uint a, uint b, uint c, uint d) internal {}
            }
        "#;
        let detector = Arc::new(NamedFunctionArgsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0, "Should not detect any issues");
    }
}
