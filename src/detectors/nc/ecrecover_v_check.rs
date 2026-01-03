use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Statement};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct EcrecoverVCheckDetector;

impl Detector for EcrecoverVCheckDetector {
    fn id(&self) -> &'static str {
        "ecrecover-v-check"
    }

    fn name(&self) -> &str {
        "No need to check `v == 27` or `v == 28` with ecrecover"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "The EVM precompile for ecrecover already checks if v is 27 or 28. There is no need to \
         perform this check on the caller side. See: https://twitter.com/alexberegszaszi/status/1534461421454606336"
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - unnecessary check
require(v == 27 || v == 28, "Invalid v value");
address signer = ecrecover(hash, v, r, s);

// Good - ecrecover handles this internally
address signer = ecrecover(hash, v, r, s);
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let self_clone = Arc::clone(&self);

        visitor.on_statement(move |stmt, file, _context| {
            if let Statement::If(loc, cond, _, _) = stmt {
                if Self::is_v_27_28_check(cond) {
                    return FindingData {
                        detector_id: self_clone.id(),
                        location: loc_to_location(loc, file),
                    }
                    .into();
                }
            }
            Vec::new()
        });

        visitor.on_expression(move |expr, file, _context| {
            if let Expression::FunctionCall(loc, func, args) = expr {
                if let Expression::Variable(id) = func.as_ref() {
                    if id.name == "require" {
                        if let Some(cond) = args.first() {
                            if Self::is_v_27_28_check(cond) {
                                return FindingData {
                                    detector_id: self.id(),
                                    location: loc_to_location(loc, file),
                                }
                                .into();
                            }
                        }
                    }
                }
            }
            Vec::new()
        });
    }
}

impl EcrecoverVCheckDetector {
    fn is_v_27_28_check(expr: &Expression) -> bool {
        match expr {
            // v == 27 || v == 28
            Expression::Or(_, left, right) => {
                Self::is_v_equal_to(left, "27") && Self::is_v_equal_to(right, "28")
                    || Self::is_v_equal_to(left, "28") && Self::is_v_equal_to(right, "27")
            }
            // v != 27 && v != 28
            Expression::And(_, left, right) => {
                Self::is_v_not_equal_to(left, "27") && Self::is_v_not_equal_to(right, "28")
                    || Self::is_v_not_equal_to(left, "28") && Self::is_v_not_equal_to(right, "27")
            }
            _ => false,
        }
    }

    fn is_v_equal_to(expr: &Expression, value: &str) -> bool {
        if let Expression::Equal(_, left, right) = expr {
            return Self::is_var_v(left) && Self::is_number(right, value)
                || Self::is_var_v(right) && Self::is_number(left, value);
        }
        false
    }

    fn is_v_not_equal_to(expr: &Expression, value: &str) -> bool {
        if let Expression::NotEqual(_, left, right) = expr {
            return Self::is_var_v(left) && Self::is_number(right, value)
                || Self::is_var_v(right) && Self::is_number(left, value);
        }
        false
    }

    fn is_var_v(expr: &Expression) -> bool {
        matches!(expr, Expression::Variable(id) if id.name == "v")
    }

    fn is_number(expr: &Expression, value: &str) -> bool {
        matches!(expr, Expression::NumberLiteral(_, v, _, _) if v == value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_v_checks() {
        let code = r#"
            contract Test {
                function bad1(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public {
                    require(v == 27 || v == 28, "Invalid v");
                    ecrecover(hash, v, r, s);
                }

                function bad2(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public {
                    if (v != 27 && v != 28) revert();
                    ecrecover(hash, v, r, s);
                }
            }
        "#;
        let detector = Arc::new(EcrecoverVCheckDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 4, "require v == 27 || v == 28");
        assert_eq!(locations[1].line, 9, "if v != 27 && v != 28");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                function good(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
                    return ecrecover(hash, v, r, s);
                }

                function otherCheck(uint256 x) public pure returns (bool) {
                    return x == 27 || x == 28;
                }
            }
        "#;
        let detector = Arc::new(EcrecoverVCheckDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
