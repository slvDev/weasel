use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::FunctionTy;
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct SensitiveTermsDetector;

impl Detector for SensitiveTermsDetector {
    fn id(&self) -> &'static str {
        "sensitive-terms"
    }

    fn name(&self) -> &str {
        "Avoid the use of sensitive terms"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Use alternative variants: allowlist/denylist instead of whitelist/blacklist, \
         primary/replica instead of master/slave."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
mapping(address => bool) whitelist;
address master;

// Good
mapping(address => bool) allowlist;
address primary;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        // Check function names
        let self_clone = Arc::clone(&self);
        visitor.on_function(move |func_def, file, _context| {
            if matches!(func_def.ty, FunctionTy::Constructor | FunctionTy::Fallback | FunctionTy::Receive) {
                return Vec::new();
            }

            let Some(name) = &func_def.name else {
                return Vec::new();
            };

            if Self::has_sensitive_term(&name.name) {
                return FindingData {
                    detector_id: self_clone.id(),
                    location: loc_to_location(&func_def.loc, file),
                }
                .into();
            }

            Vec::new()
        });

        // Check state variable names
        visitor.on_variable(move |var_def, file, _context| {
            let Some(name) = &var_def.name else {
                return Vec::new();
            };

            if Self::has_sensitive_term(&name.name) {
                return FindingData {
                    detector_id: self.id(),
                    location: loc_to_location(&var_def.loc, file),
                }
                .into();
            }

            Vec::new()
        });
    }
}

impl SensitiveTermsDetector {
    fn has_sensitive_term(name: &str) -> bool {
        let lower = name.to_lowercase();
        lower.contains("whitelist")
            || lower.contains("blacklist")
            || lower.contains("master")
            || lower.contains("slave")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_sensitive_terms() {
        let code = r#"
            contract Test {
                mapping(address => bool) whitelist;
                mapping(address => bool) blacklist;
                address masterAddress;
                address slaveNode;

                function addToWhitelist(address user) external {}
                function setMaster(address addr) external {}
            }
        "#;
        let detector = Arc::new(SensitiveTermsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 6);
        assert_eq!(locations[0].line, 3, "whitelist");
        assert_eq!(locations[1].line, 4, "blacklist");
        assert_eq!(locations[2].line, 5, "masterAddress");
        assert_eq!(locations[3].line, 6, "slaveNode");
        assert_eq!(locations[4].line, 8, "addToWhitelist");
        assert_eq!(locations[5].line, 9, "setMaster");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                mapping(address => bool) allowlist;
                mapping(address => bool) denylist;
                address primaryAddress;
                address replicaNode;

                function addToAllowlist(address user) external {}
                function setPrimary(address addr) external {}
            }
        "#;
        let detector = Arc::new(SensitiveTermsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
