use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Loc, Parameter, Type};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct LowLevelCallGasGriefDetector;

impl Detector for LowLevelCallGasGriefDetector {
    fn id(&self) -> &'static str {
        "low-level-call-gas-grief"
    }

    fn name(&self) -> &str {
        "Low-level call with bytes return can cause gas grief attack"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "Capturing return data as bytes from low-level calls can cause gas grief attacks. A malicious \
         contract can return large data, causing expensive memory allocation via RETURNDATACOPY. Use \
         assembly with explicit zero return size or check returndatasize() before copying."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - return data captured as bytes
(bool success, bytes memory data) = target.call(payload);

// Good - use assembly with zero return size
assembly {
    let success := call(gas(), target, amount, 0, 0, 0, 0)
}
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_expression(move |expr, file, _context| {
            if let Expression::Assign(loc, left, right) = expr {
                if !Self::is_low_level_call(right) {
                    return Vec::new();
                }

                if let Expression::List(_, params) = left.as_ref() {
                    if Self::has_bytes_in_list(params) {
                        return FindingData {
                            detector_id: self.id(),
                            location: loc_to_location(loc, file),
                        }
                        .into();
                    }
                }
            }

            Vec::new()
        });
    }
}

impl LowLevelCallGasGriefDetector {
    const LOW_LEVEL_CALLS: &'static [&'static str] = &["call", "delegatecall", "staticcall"];

    fn is_low_level_call(expr: &Expression) -> bool {
        match expr {
            Expression::FunctionCall(_, func, _) => {
                if let Expression::MemberAccess(_, _, member) = func.as_ref() {
                    return Self::LOW_LEVEL_CALLS.contains(&member.name.as_str());
                }
                if let Expression::FunctionCallBlock(_, inner_func, _) = func.as_ref() {
                    if let Expression::MemberAccess(_, _, member) = inner_func.as_ref() {
                        return Self::LOW_LEVEL_CALLS.contains(&member.name.as_str());
                    }
                }
                false
            }
            _ => false,
        }
    }

    fn has_bytes_in_list(params: &[(Loc, Option<Parameter>)]) -> bool {
        for (_, param_opt) in params {
            if let Some(param) = param_opt {
                if Self::is_bytes_type(param) {
                    return true;
                }
            }
        }
        false
    }

    fn is_bytes_type(param: &Parameter) -> bool {
        matches!(&param.ty, Expression::Type(_, Type::DynamicBytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_gas_grief_patterns() {
        let code = r#"
            contract Test {
                function bad1(address target, bytes memory payload) external {
                    (bool success, bytes memory data) = target.call(payload);
                }

                function bad2(address target) external {
                    (, bytes memory returnData) = target.delegatecall("");
                }

                function bad3(address target) external {
                    (bool ok, bytes memory result) = target.staticcall{gas: 10000}("");
                }

                function bad4(address target) external {
                    (bool success, bytes memory data) = target.call{value: 1 ether}("");
                }
            }
        "#;
        let detector = Arc::new(LowLevelCallGasGriefDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 4);
        assert_eq!(locations[0].line, 4, "bytes memory data from call");
        assert_eq!(
            locations[1].line, 8,
            "bytes memory returnData from delegatecall"
        );
        assert_eq!(
            locations[2].line, 12,
            "bytes memory result from staticcall with gas"
        );
        assert_eq!(
            locations[3].line, 16,
            "bytes memory data from call with value"
        );
    }

    #[test]
    fn test_skips_safe_patterns() {
        let code = r#"
            contract Test {
                function safe1(address target, bytes memory payload) external {
                    (bool success, ) = target.call(payload);
                }

                function safe2(address target) external {
                    (bool success,) = target.delegatecall("");
                }

                function safe3(address target) external returns (bool) {
                    (bool ok, ) = target.staticcall("");
                    return ok;
                }
            }
        "#;
        let detector = Arc::new(LowLevelCallGasGriefDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
