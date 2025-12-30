use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Type};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DecimalsTypeDetector;

impl Detector for DecimalsTypeDetector {
    fn id(&self) -> &'static str {
        "decimals-wrong-type"
    }

    fn name(&self) -> &str {
        "`decimals()` should be of type `uint8`"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn description(&self) -> &str {
        "The `decimals` function or variable should return or be of type `uint8` according to the \
         ERC-20 standard, not `uint256` or other unsigned integer types."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad - wrong return type
function decimals() public view returns (uint256) {
    return 18;
}

// Bad - wrong variable type
uint256 public decimals = 18;

// Good - correct return type
function decimals() public view returns (uint8) {
    return 18;
}

// Good - correct variable type
uint8 public decimals = 18;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        let self_clone = Arc::clone(&self);

        visitor.on_function(move |func_def, file, _context| {
            let Some(name) = &func_def.name else {
                return Vec::new();
            };

            if name.name != "decimals" {
                return Vec::new();
            }

            for (_, param_opt) in &func_def.returns {
                if let Some(param) = param_opt {
                    if let Expression::Type(_, ty) = &param.ty {
                        if !matches!(ty, Type::Uint(8)) {
                            return FindingData {
                                detector_id: self_clone.id(),
                                location: loc_to_location(&param.loc, file),
                            }
                            .into();
                        }
                    }
                }
            }
            Vec::new()
        });

        visitor.on_variable(move |var_def, file, _context| {
            let Some(var_name) = var_def.name.as_ref() else {
                return Vec::new();
            };

            if var_name.name != "decimals" {
                return Vec::new();
            }

            if let Expression::Type(_, ty) = &var_def.ty {
                if !matches!(ty, Type::Uint(8)) {
                    return FindingData {
                        detector_id: self.id(),
                        location: loc_to_location(&var_def.loc, file),
                    }
                    .into();
                }
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
    fn test_detects_wrong_decimals_type() {
        let code = r#"
            contract Token {
                uint256 public decimals = 18;

                function decimals() public view returns (uint256) {
                    return 18;
                }
            }
        "#;
        let detector = Arc::new(DecimalsTypeDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 3, "variable declaration");
        assert_eq!(locations[1].line, 5, "function return type");
    }

    #[test]
    fn test_skips_correct_uint8_type() {
        let code = r#"
            contract Token {
                uint8 public decimals = 18;

                function decimals() public view returns (uint8) {
                    return 18;
                }

                function otherFunction() public view returns (uint256) {
                    return 100;
                }
            }
        "#;
        let detector = Arc::new(DecimalsTypeDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
