use crate::core::visitor::ASTVisitor;
use crate::detectors::Detector;
use crate::models::severity::Severity;
use crate::models::FindingData;
use crate::utils::location::loc_to_location;
use solang_parser::pt::{Expression, Loc, Type};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct MappingStyleDetector;

impl Detector for MappingStyleDetector {
    fn id(&self) -> &'static str {
        "mapping-style"
    }

    fn name(&self) -> &str {
        "Mapping definitions do not follow the Solidity Style Guide"
    }

    fn severity(&self) -> Severity {
        Severity::NC
    }

    fn description(&self) -> &str {
        "Mapping definitions should not have spaces between 'mapping' and '(' or after '('. \
         See the mappings section of the Solidity Style Guide."
    }

    fn example(&self) -> Option<String> {
        Some(
            r#"```solidity
// Bad
mapping (address => uint256) balances;
mapping( address => uint256) balances;

// Good
mapping(address => uint256) balances;
```"#
                .to_string(),
        )
    }

    fn register_callbacks(self: Arc<Self>, visitor: &mut ASTVisitor) {
        visitor.on_variable(move |var_def, file, _context| {
            if !matches!(var_def.ty, Expression::Type(_, Type::Mapping { .. })) {
                return Vec::new();
            }

            let Loc::File(_, start, end) = var_def.loc else {
                return Vec::new();
            };

            let Some(source) = file.content.get(start..end.min(file.content.len())) else {
                return Vec::new();
            };

            if source.contains("mapping (") || source.contains("mapping( ") {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::run_detector_on_code;

    #[test]
    fn test_detects_bad_mapping_style() {
        let code = r#"
            contract Test {
                mapping (address => uint256) balances;
                mapping( address => uint256) allowances;
                mapping (uint256 => mapping (address => bool)) nested;
            }
        "#;
        let detector = Arc::new(MappingStyleDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 3);
        assert_eq!(locations[0].line, 3, "mapping (address");
        assert_eq!(locations[1].line, 4, "mapping( address");
        assert_eq!(locations[2].line, 5, "nested mapping");
    }

    #[test]
    fn test_skips_valid_code() {
        let code = r#"
            contract Test {
                mapping(address => uint256) balances;
                mapping(uint256 => mapping(address => bool)) nested;
                uint256 notAMapping;
            }
        "#;
        let detector = Arc::new(MappingStyleDetector::default());
        let locations = run_detector_on_code(detector, code, "test.sol");
        assert_eq!(locations.len(), 0);
    }
}
