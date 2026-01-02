use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::utils::location::loc_to_location;
use crate::utils::version::solidity_version_req_matches;
use crate::{core::visitor::ASTVisitor, models::FindingData};
use solang_parser::pt::{Expression, Type};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct NamedMappingsDetector;

impl Detector for NamedMappingsDetector {
    fn id(&self) -> &'static str {
        "named-mappings"
    }

    fn name(&self) -> &str {
        "Consider using named mappings"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Named mappings (introduced in Solidity 0.8.18) improve code readability by allowing \
         parameter names in mapping declarations, e.g., `mapping(address user => uint256 balance)`."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad (pre-0.8.18 style)
mapping(address => uint256) balances;

// Good (0.8.18+ style)
mapping(address user => uint256 balance) balances;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_variable(move |var_def, file, _context| {
            let version_supports_named = match &file.solidity_version {
                Some(version_str) => solidity_version_req_matches(version_str, ">=0.8.18"),
                None => false,
            };

            if !version_supports_named {
                return Vec::new();
            }

            if Self::has_unnamed_mapping(&var_def.ty) {
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

impl NamedMappingsDetector {
    fn has_unnamed_mapping(expr: &Expression) -> bool {
        if let Expression::Type(
            _,
            Type::Mapping {
                key_name,
                value_name,
                key,
                value,
                ..
            },
        ) = expr
        {
            if key_name.is_none() || value_name.is_none() {
                return true;
            }
            if Self::has_unnamed_mapping(key) || Self::has_unnamed_mapping(value) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_unnamed_mappings() {
        let code = r#"
            pragma solidity ^0.8.18;

            contract Test {
                mapping(address => uint256) balances;
                mapping(address => mapping(uint256 => bool)) nested;
            }
        "#;
        let detector = Arc::new(NamedMappingsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 2);
        assert_eq!(locations[0].line, 5, "balances mapping");
        assert_eq!(locations[1].line, 6, "nested mapping");
    }

    #[test]
    fn test_skips_named_and_old_versions() {
        // Named mappings - should not flag
        let code = r#"
            pragma solidity ^0.8.18;

            contract Test {
                mapping(address user => uint256 balance) balances;
            }
        "#;
        let detector = Arc::new(NamedMappingsDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);

        let code2 = r#"
            pragma solidity ^0.8.0;

            contract Test {
                mapping(address => uint256) balances;
            }
        "#;
        let detector2 = Arc::new(NamedMappingsDetector::default());
        let locations2 = run_detector_on_code(detector2, code2, "test.sol");
        assert_eq!(locations2.len(), 0);
    }
}
