use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::ast_utils::get_contract_info;
use crate::utils::version::solidity_version_req_matches;
use solang_parser::pt::ContractTy;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct DeprecatedSafeMathDetector;

impl Detector for DeprecatedSafeMathDetector {
    fn id(&self) -> &'static str {
        "deprecated-safemath"
    }

    fn name(&self) -> &str {
        "Deprecated library used for Solidity >= 0.8: SafeMath"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "SafeMath is no longer needed for Solidity >= 0.8 as the compiler has built-in \
         overflow/underflow checks. Using SafeMath adds unnecessary gas overhead."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad (Solidity >= 0.8)
using SafeMath for uint256;
uint256 result = a.add(b);

// Good (Solidity >= 0.8)
uint256 result = a + b;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_contract(move |contract_def, file, _context| {
            if matches!(
                contract_def.ty,
                ContractTy::Interface(_) | ContractTy::Library(_)
            ) {
                return Vec::new();
            }

            let version_has_builtin_checks = match &file.solidity_version {
                Some(version_str) => solidity_version_req_matches(version_str, ">=0.8.0"),
                None => false,
            };

            if !version_has_builtin_checks {
                return Vec::new();
            }

            let Some(contract_info) = get_contract_info(contract_def, file) else {
                return Vec::new();
            };

            contract_info
                .using_directives
                .iter()
                .filter(|using| {
                    using
                        .library_name
                        .as_ref()
                        .is_some_and(|name| name.contains("SafeMath"))
                })
                .map(|using| FindingData {
                    detector_id: self.id(),
                    location: using.loc.clone(),
                })
                .collect()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_safemath_in_0_8() {
        let code = r#"
            pragma solidity ^0.8.0;

            contract Test {
                using SafeMath for uint256;
                using SafeMath for uint128;

                function add(uint256 a, uint256 b) public pure returns (uint256) {
                    return a.add(b);
                }
            }
        "#;
        let detector = Arc::new(DeprecatedSafeMathDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 5, "using SafeMath for uint256");
        assert_eq!(locations[1].line, 6, "using SafeMath for uint128");
    }

    #[test]
    fn test_skips_valid_code() {
        // Older version - SafeMath is needed
        let code1 = r#"
            pragma solidity ^0.7.0;
            contract Test {
                using SafeMath for uint256;
            }
        "#;
        let detector1 = Arc::new(DeprecatedSafeMathDetector::default());
        let locations1 = run_detector_on_code(detector1, code1, "test.sol");
        assert_eq!(locations1.len(), 0);

        // No SafeMath usage
        let code2 = r#"
            pragma solidity ^0.8.0;
            contract Test {
                function add(uint256 a, uint256 b) public pure returns (uint256) {
                    return a + b;
                }
            }
        "#;
        let detector2 = Arc::new(DeprecatedSafeMathDetector::default());
        let locations2 = run_detector_on_code(detector2, code2, "test.sol");
        assert_eq!(locations2.len(), 0);
    }
}
